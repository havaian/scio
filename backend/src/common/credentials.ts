import { createHash, createPrivateKey, createSign, KeyObject, X509Certificate } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { rootCertificates } from 'node:tls';
import { resolve } from 'node:path';
import { Agent, Dispatcher, EnvHttpProxyAgent } from 'undici';
import { TargetConfig } from './types';

/** Certificates live outside the repo history: ./certs locally, /app/certs in Docker (git-ignored). */
export const CERT_DIR = process.env.CERT_DIR ?? resolve(process.cwd(), '..', 'certs');

export interface LoadedCredentials {
  /** Undici dispatcher presenting the client certificate (mTLS, QWAC). */
  dispatcher: Dispatcher;
  /** Builds Digest + x-jws-signature for a request (QSealC), when signing is on. */
  signer?: RequestSigner;
  /** Mutable signer options (e.g. typ, added when a bank insists on it). */
  signerOptions?: JwsOptions;
  certSubject: string;
  certExpires: string;
  /** TPP identifier from the certificate (organizationIdentifier, e.g. PSDGE-NBG-...), used as OAuth client_id when none is configured. */
  tppId?: string;
}

export interface JwsOptions {
  /** "typ" header: GE-JWS §6 does not recommend it (value JOSE if used); some banks require it. */
  typ?: string;
  /** Leave (request-target) out of sigD.pars: only for banks whose verifier fails on it (GE-JWS requires it). */
  omitRequestTarget?: boolean;
  /** Put the issuing chain after the signing certificate in x5c. GE-JWS §6 allows only the signing certificate; used only as a fallback for banks that refuse it. */
  x5cChain?: boolean;
  /** Shift sigT by this many seconds (clock-window test only; GE-JWS §5 window is -60 s..+2 s). */
  sigTOffsetSec?: number;
  /** Set by loadCredentials: whether the seal certificate file carries a chain to fall back to. */
  chainAvailable?: boolean;
}

export type RequestSigner = (req: { method: string; url: string; headers: Record<string, string>; body?: string }) => Record<string, string>;

/** Loads the target's test certificate. Returns a reason string when it is not configured or not readable. */
export function loadCredentials(target: TargetConfig): LoadedCredentials | string {
  const c = target.credentials;
  if (!c) return 'no credentials configured for this target';
  const file = (name?: string) => (name ? resolve(CERT_DIR, name) : undefined);
  const certPath = file(c.cert);
  const keyPath = file(c.key);
  if (!certPath || !keyPath) return 'credentials.cert and credentials.key are required';
  const signCertPath = file(c.signCert);
  const signKeyPath = file(c.signKey);
  const caPath = file(c.ca);
  for (const p of [certPath, keyPath, signCertPath, signKeyPath]) if (p && !existsSync(p)) return `certificate file not found: ${p}`;
  // The root CA is optional: without it only publicly trusted server certificates are accepted.
  const passphrase = c.passphraseEnv ? process.env[c.passphraseEnv] : undefined;
  try {
    // Certificates may come as PEM or DER (portal .crt files), alone or with their chain (exported from .p12): normalised to PEM.
    const key = readFileSync(keyPath);
    // Fail early on a wrong passphrase instead of inside the TLS handshake.
    const keyObj = createPrivateKey({ key, passphrase });
    const chain = certChain(readFileSync(certPath), keyObj);
    const x509 = chain[0];
    const cert = chain.map((x) => x.toString()).join('');
    // The bank's sandbox root CA (e.g. AltasoftPsd2RootCa) is trusted for this target only, next to the public roots.
    const ca = caPath && existsSync(caPath) ? [...rootCertificates, ...certChain(readFileSync(caPath)).map((x) => x.toString())] : undefined;
    const tls = { cert, key, passphrase, ...(ca ? { ca } : {}) };
    // Same proxy behaviour as the shared client: HTTPS_PROXY when set, direct otherwise.
    const dispatcher: Dispatcher =
      process.env.HTTPS_PROXY || process.env.HTTP_PROXY ? new EnvHttpProxyAgent({ connect: tls, requestTls: tls } as any) : new Agent({ connect: tls });
    let signer: RequestSigner | undefined;
    const signerOptions: JwsOptions = {};
    if (c.sign !== false) {
      const sKey = signKeyPath ? createPrivateKey({ key: readFileSync(signKeyPath), passphrase }) : keyObj;
      const sChain = signCertPath ? certChain(readFileSync(signCertPath), sKey) : chain;
      signerOptions.chainAvailable = sChain.length > 1;
      signer = jwsSigner(sKey, sChain[0], sChain.slice(1), signerOptions);
    }
    const tppId = /(?:organizationIdentifier|2\.5\.4\.97)=([^\n,]+)/.exec(x509.subject)?.[1];
    return { dispatcher, signer, signerOptions, certSubject: x509.subject.replace(/\n/g, ', '), certExpires: x509.validTo, tppId };
  } catch (e: any) {
    return `certificate could not be loaded: ${e?.message ?? e}`;
  }
}

/**
 * The bank's published test CA (credentials.ca), next to the public roots, for this target only. No client certificate:
 * used to reach the front door when the sandbox's server certificate chains to a private test root.
 */
export function targetCaDispatcher(target: TargetConfig): { dispatcher: Dispatcher; ca: string[] } | undefined {
  const caFile = target.credentials?.ca ? resolve(CERT_DIR, target.credentials.ca) : undefined;
  if (!caFile || !existsSync(caFile)) return undefined;
  try {
    const ca = [...rootCertificates, ...certChain(readFileSync(caFile)).map((x) => x.toString())];
    const dispatcher: Dispatcher = process.env.HTTPS_PROXY || process.env.HTTP_PROXY ? new EnvHttpProxyAgent({ connect: { ca }, requestTls: { ca } } as any) : new Agent({ connect: { ca } });
    return { dispatcher, ca };
  } catch {
    return undefined;
  }
}

/**
 * All certificates in a PEM bundle (or one DER certificate), the one matching the private key first.
 * openssl pkcs12 -nokeys exports the chain in no fixed order.
 */
export function certChain(buf: Buffer, key?: KeyObject): X509Certificate[] {
  const text = buf.toString('latin1');
  const certs = text.includes('-----BEGIN CERTIFICATE-----')
    ? (text.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) ?? []).map((p) => new X509Certificate(p))
    : [new X509Certificate(buf)];
  if (!certs.length) throw new Error('no certificate in file');
  if (key) {
    const i = certs.findIndex((c) => c.checkPrivateKey(key));
    if (i < 0) throw new Error('no certificate in the file matches the private key');
    certs.unshift(...certs.splice(i, 1));
  }
  return certs;
}

/** Digest header value: SHA-256 of the exact body bytes (GE-JWS §9.3). */
export function digestOf(body?: string): string {
  return `SHA-256=${createHash('sha256').update(body ?? '', 'utf8').digest('base64')}`;
}

/**
 * Headers covered by the signature, in this order (GE-JWS §5, §7): request line, host, content-type,
 * every PSU-* header, x-request-id, tpp-redirect-uri, digest.
 */
export function signedHeaderNames(headers: Record<string, string>): string[] {
  const lower = Object.keys(headers).map((k) => k.toLowerCase());
  const pick = (n: string) => (lower.includes(n) ? [n] : []);
  return [
    '(request-target)',
    'host',
    ...pick('content-type'),
    ...lower.filter((k) => k.startsWith('psu-')).sort(),
    ...pick('x-request-id'),
    ...pick('tpp-redirect-uri'),
    ...pick('consent-id'),
    'digest',
  ];
}

/** The HttpHeaders signing string: "name: value" lines joined with LF (GE-JWS §9.5). */
export function signingString(method: string, url: string, headers: Record<string, string>, pars: string[]): string {
  const u = new URL(url);
  const get = (n: string) => Object.entries(headers).find(([k]) => k.toLowerCase() === n)?.[1] ?? '';
  return pars
    .map((n) => {
      if (n === '(request-target)') return `${n}: ${method.toLowerCase()} ${u.pathname}${u.search}`;
      if (n === 'host') return `host: ${u.host}`;
      // Content-Type type/subtype and charset are case-insensitive: signed in lower case (GE-JWS §7.1).
      if (n === 'content-type') return `content-type: ${get(n).toLowerCase()}`;
      return `${n}: ${get(n)}`;
    })
    .join('\n');
}

/** Detached JWS with b64=false over the HTTP headers (GE-JWS §6, §9). x5c carries the QSealC. */
export function jwsSigner(key: KeyObject, cert: X509Certificate, chain: X509Certificate[] = [], opts: JwsOptions = {}): RequestSigner {
  const ec = key.asymmetricKeyType === 'ec';
  const alg = ec ? 'ES256' : 'RS256';
  // x5c: the seal certificate first, then its chain (RFC 7515 §4.1.6), so the bank can build the path to its trusted root.
  // (Kept above for reference; GE-JWS overrides it.) GE-JWS §6: x5c holds exactly one entry, the signing certificate. The chain is added only when opts.x5cChain is set
  // (fallback for a bank that refuses the compliant form; reported as that bank's deviation).
  const single = [cert.raw.toString('base64')];
  const withChain = [cert, ...chain].map((c) => c.raw.toString('base64'));
  return (req) => {
    const x5c = opts.x5cChain ? withChain : single;
    const headers: Record<string, string> = { ...req.headers, Digest: digestOf(req.body) };
    const pars = signedHeaderNames(headers).filter((p) => !(opts.omitRequestTarget && p === '(request-target)'));
    const protectedHeader = {
      ...(opts.typ ? { typ: opts.typ } : {}),
      b64: false,
      x5c,
      crit: ['sigT', 'sigD', 'b64'],
      sigT: new Date(Date.now() + (opts.sigTOffsetSec ?? 0) * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z'),
      sigD: { pars, mId: 'http://uri.etsi.org/19182/HttpHeaders' },
      alg,
    };
    const h = Buffer.from(JSON.stringify(protectedHeader)).toString('base64url');
    const input = `${h}.${signingString(req.method, req.url, headers, pars)}`;
    const sig = createSign('SHA256').update(input).sign(ec ? { key, dsaEncoding: 'ieee-p1363' } : key);
    return { Digest: headers.Digest, 'x-jws-signature': `${h}..${sig.toString('base64url')}` };
  };
}
