import { createHash, randomUUID } from 'node:crypto';
import { fetch, EnvHttpProxyAgent, Agent, Dispatcher } from 'undici';
import { Exchange } from './types';
import type { RequestSigner } from './credentials';

// Uses HTTPS_PROXY / HTTP_PROXY from the environment when set, direct connection otherwise.
const dispatcher: Dispatcher =
  process.env.HTTPS_PROXY || process.env.HTTP_PROXY ? new EnvHttpProxyAgent() : new Agent();

export interface HttpRequest {
  operation: string;
  method: string;
  url: string;
  headers?: Record<string, string>;
  json?: unknown;
  form?: Record<string, string>;
  redirect?: 'manual' | 'follow';
  /** Do not record in the exchange log (e.g. noisy helper calls) */
  silent?: boolean;
  /** Skip the configured signer for this call (signature enforcement test). */
  unsigned?: boolean;
  /** Per-call dispatcher (e.g. the bank's test CA without a client certificate). */
  dispatcher?: Dispatcher;
}

export interface HttpResponse {
  status: number;
  ok: boolean;
  headers: Record<string, string>;
  text: string;
  json: any;
  durationMs: number;
  serverTimingMs?: number;
  error?: string;
  requestHeaders: Record<string, string>;
  /** Base64 SHA-256 of the exact response bytes, for Digest verification (GE-JWS §9.4, §10.6). */
  bodySha256?: string;
  /** Base64 SHA-512 of the same bytes (GE-JWS §5.1: SHA-512 Digest must be supported too). */
  bodySha512?: string;
  /** Set-Cookie values, kept apart because they cannot be joined into one header (bank login pages). */
  setCookies?: string[];
}

export function newRequestId(): string {
  return randomUUID();
}

function parseServerTiming(value?: string): number | undefined {
  if (!value) return undefined;
  const m = /dur=([\d.]+)/.exec(value);
  return m ? Number(m[1]) : undefined;
}

export class HttpRecorder {
  readonly exchanges: Exchange[] = [];

  constructor(
    private readonly targetId: string,
    private readonly timeoutMs: number,
    /** Sandbox targets: client-certificate dispatcher, and a signer applied to calls under signBase. */
    private opts: { dispatcher?: Dispatcher; signer?: RequestSigner; signBase?: string } = {},
  ) {}

  /** Switches later calls to the client certificate (after the unauthenticated passive checks). */
  useClient(opts: { dispatcher?: Dispatcher; signer?: RequestSigner; signBase?: string }) {
    this.opts = opts;
  }

  async request(req: HttpRequest): Promise<HttpResponse> {
    const headers: Record<string, string> = { Accept: 'application/json', ...(req.headers ?? {}) };
    let body: string | undefined;
    if (req.json !== undefined) {
      headers['Content-Type'] = 'application/json';
      body = JSON.stringify(req.json);
    } else if (req.form) {
      headers['Content-Type'] = 'application/x-www-form-urlencoded';
      body = new URLSearchParams(req.form).toString();
    }

    if (this.opts.signer && !req.unsigned && this.opts.signBase && req.url.startsWith(this.opts.signBase))
      Object.assign(headers, this.opts.signer({ method: req.method, url: req.url, headers, body }));

    const started = performance.now();
    let res: HttpResponse;
    try {
      const r = await fetch(req.url, {
        method: req.method,
        headers,
        body,
        redirect: req.redirect ?? 'manual',
        dispatcher: req.dispatcher ?? this.opts.dispatcher ?? dispatcher,
        signal: AbortSignal.timeout(this.timeoutMs),
      });
      const bytes = Buffer.from(await r.arrayBuffer());
      const text = bytes.toString('utf8');
      const durationMs = performance.now() - started;
      const respHeaders: Record<string, string> = {};
      r.headers.forEach((v, k) => (respHeaders[k.toLowerCase()] = v));
      let json: any = undefined;
      try {
        json = text ? JSON.parse(text) : undefined;
      } catch {
        json = undefined;
      }
      res = {
        status: r.status,
        ok: r.status < 500,
        headers: respHeaders,
        text,
        json,
        durationMs,
        serverTimingMs: parseServerTiming(respHeaders['server-timing']),
        requestHeaders: headers,
        bodySha256: createHash('sha256').update(bytes).digest('base64'),
        bodySha512: createHash('sha512').update(bytes).digest('base64'),
        setCookies: r.headers.getSetCookie?.() ?? [],
      };
    } catch (e: any) {
      const durationMs = performance.now() - started;
      const cause = e?.cause?.code || e?.cause?.message || e?.name;
      res = {
        status: 0,
        ok: false,
        headers: {},
        text: '',
        json: undefined,
        durationMs,
        error: `${e?.message ?? 'request failed'}${cause ? ` (${cause})` : ''}`,
        requestHeaders: headers,
      };
    }

    if (!req.silent) {
      this.exchanges.push({
        targetId: this.targetId,
        operation: req.operation,
        method: req.method,
        url: redactUrl(req.url),
        status: res.status,
        ok: res.ok,
        durationMs: Math.round(res.durationMs * 10) / 10,
        serverTimingMs: res.serverTimingMs,
        error: res.error,
        requestHeaders: redact(headers),
        responseHeaders: redactLocation(res.headers),
        bodySnippet: redactBody(res.text).slice(0, 2000),
        bodySha256: res.bodySha256,
        bodySha512: res.bodySha512,
        ts: new Date().toISOString(),
      });
    }
    return res;
  }
}

const SECRET_FIELDS = 'access_token|refresh_token|id_token|client_secret|code_verifier|password|passwd|otp';

/** Token responses: keep the shape, drop the secrets (access/refresh/id tokens, client secrets, PKCE verifiers, passwords), as JSON or form-encoded. */
export function redactBody(text: string): string {
  return text
    .replace(new RegExp(`("(?:${SECRET_FIELDS})"\\s*:\\s*")[^"]*(")`, 'gi'), '$1***$2')
    .replace(new RegExp(`((?:^|[?&\\s"'])(?:${SECRET_FIELDS})=)[^&\\s"']*`, 'gi'), '$1***');
}

/** Same secrets in a URL query string (e.g. a login form sent with GET). */
export function redactUrl(url: string): string {
  return url.replace(new RegExp(`([?&](?:${SECRET_FIELDS})=)[^&#]*`, 'gi'), '$1***');
}

/** Authorization codes travel in redirect Location headers; session cookies in Set-Cookie. */
function redactLocation(h: Record<string, string>): Record<string, string> {
  // Bank login pages set session cookies: keep the names, drop the values.
  if (h['set-cookie']) h = { ...h, 'set-cookie': h['set-cookie'].replace(/(^|,\s*)([^=,;\s]+)=[^;]*/g, '$1$2=***') };
  if (!h['location']) return h;
  return { ...h, location: h['location'].replace(/([?&]code=)[^&]+/, '$1***') };
}

/** Never store bearer tokens or secrets in the exchange log: any Authorization scheme (Bearer, Basic, ...), API keys, secrets, passwords, cookies. */
export function redact(h: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(h)) {
    out[k] = /authorization/i.test(k)
      ? maskAuthorization(v)
      : /^cookie$/i.test(k)
        ? v.replace(/=[^;]*/g, '=***')
        : /api-?key|secret|password|passwd/i.test(k)
          ? '***'
          : v;
  }
  return out;
}

/** "Basic dXNlcjpzZWNyZXQ=" -> "Basic ***": the scheme stays visible, the credentials never are. */
function maskAuthorization(v: string): string {
  const scheme = /^\s*(\S+)\s+\S/.exec(v)?.[1];
  return scheme ? `${scheme} ***` : '***';
}
