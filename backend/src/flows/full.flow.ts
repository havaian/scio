import { createHash, randomBytes } from 'node:crypto';
import { HttpResponse, newRequestId } from '../common/http';
import { AuditContext, REF } from '../checks/context';

/** Per-operation schema validation results collected while the flow runs. */
export interface SchemaResult {
  operation: string;
  status: number;
  valid: boolean;
  errors?: string[];
  skipped?: string;
}

const isoDate = (d: Date) => d.toISOString().slice(0, 10);

export function pkcePair() {
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

/**
 * Calls an XS2A endpoint with the standard headers and validates the response against the bank's own spec.
 */
export async function api(
  ctx: AuditContext,
  operation: string,
  method: string,
  path: string,
  opts: {
    auth?: boolean;
    consent?: boolean;
    json?: unknown;
    headers?: Record<string, string>;
    absolute?: boolean;
    validate?: boolean;
    retry?: boolean;
    /** Extra retries with backoff for calls the rest of the flow depends on (resource creation). */
    retries?: number;
    /** Use this access token / Consent-ID instead of the AIS ones (PIS, loans and savings journeys). */
    token?: string;
    consentId?: string;
    /** Send without Digest / x-jws-signature even when a signer is configured (signature enforcement test). */
    unsigned?: boolean;
  } = {},
): Promise<HttpResponse> {
  const headers: Record<string, string> = { 'X-Request-ID': newRequestId(), 'PSU-IP-Address': '192.0.2.10' };
  const token = opts.token ?? ctx.state.token?.access_token;
  const consentId = opts.consentId ?? ctx.state.consentId;
  if (opts.auth !== false && token) headers['Authorization'] = `Bearer ${token}`;
  if (opts.consent !== false && consentId) headers['Consent-ID'] = consentId;
  // Explicit headers win (negative tests override or blank out the defaults).
  Object.assign(headers, opts.headers ?? {});
  for (const [k, v] of Object.entries(headers)) if (v === '') delete headers[k];

  const url = opts.absolute ? path : ctx.url(path);
  let r = await ctx.http.request({ operation, method, url, headers, json: opts.json, unsigned: opts.unsigned });
  // Flow calls retry once on 5xx/timeouts so a transient outage does not hide later checks.
  // Both attempts stay in the log, so reliability statistics still see the failure.
  // A new X-Request-ID makes a new request (GE-XS2A §7.7): POST/PUT/DELETE retries keep the original one, so a
  // timed-out consent or payment is not created twice. retries: 0 disables retrying.
  const attempts = opts.retry === false || operation.startsWith('probe.') ? 0 : Math.max(0, opts.retries ?? 1);
  for (let i = 0; i < attempts && (r.status === 0 || r.status >= 500); i++) {
    await new Promise((res) => setTimeout(res, 800 * 2 ** i));
    const requestId = method.toUpperCase() === 'GET' ? newRequestId() : headers['X-Request-ID'];
    r = await ctx.http.request({ operation, method, url, headers: requestId ? { ...headers, 'X-Request-ID': requestId } : headers, json: opts.json, unsigned: opts.unsigned });
  }
  // 5xx and timeouts are availability problems (reliability layer), not schema deviations.
  if (opts.validate !== false && ctx.spec && r.status > 0 && r.status < 500) {
    const v = ctx.spec.validate(method, url, r.status, r.json);
    (ctx.state.schemaResults ??= [] as SchemaResult[]).push({
      operation: v.operation ? `${v.operation.method} ${v.operation.path}` : `${method} ${new URL(url).pathname}`,
      status: r.status,
      valid: v.valid,
      errors: v.errors,
      skipped: v.skipped,
    });
  }
  return r;
}

/** Runs authorize -> mock consent page approval -> redirect with code. Returns the code. */
export async function obtainCode(ctx: AuditContext, scope: string, challenge: string, redirectUri: string): Promise<string | undefined> {
  const disc = ctx.state.discovery;
  const authEndpoint = disc?.authorization_endpoint ?? ctx.oauthUrl('/psd2/openbanking/oauth/authorize');
  const q = new URLSearchParams({
    client_id: ctx.target.clientId ?? 'scio',
    scope,
    response_type: 'code',
    redirect_uri: redirectUri,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    state: randomBytes(8).toString('hex'),
    nonce: randomBytes(8).toString('hex'),
  });
  let r = await ctx.http.request({ operation: 'oauth.authorize', method: 'GET', url: `${authEndpoint}?${q}` });
  let location = r.headers['location'];
  // Simulated SCA: the mock shows an approval page instead of a bank login.
  for (let hop = 0; hop < 3 && location && !location.startsWith(redirectUri); hop++) {
    const pageUrl = new URL(location, authEndpoint).toString();
    r = await ctx.http.request({ operation: 'sca.approve', method: 'POST', url: pageUrl, form: { decision: 'approve' } });
    location = r.headers['location'];
  }
  if (!location?.startsWith(redirectUri)) return undefined;
  return new URL(location).searchParams.get('code') ?? undefined;
}

/** True when the call could not be judged: no response, or a server error after retries. */
export const unavailable = (r: HttpResponse) => r.status === 0 || r.status >= 500;

/**
 * Authorize (PKCE) + token for a resource, trying scope spellings in order (e.g. PIS:<id>, PIS).
 * Returns the access token and the scope that worked, or undefined.
 */
export async function authorizeScopes(ctx: AuditContext, scopes: string[], operation: string): Promise<{ token: string; scope: string } | undefined> {
  const redirectUri = ctx.target.redirectUri ?? 'https://example.org/cb';
  for (const scope of scopes) {
    const { verifier, challenge } = pkcePair();
    let code: string | undefined;
    for (let i = 0; i < 3 && !code; i++) {
      code = await obtainCode(ctx, scope, challenge, redirectUri);
      if (!code) await new Promise((res) => setTimeout(res, 800));
    }
    if (!code) continue;
    let t = await exchangeCode(ctx, code, verifier, redirectUri, `${operation}.token`);
    for (let i = 0; i < 2 && unavailable(t); i++) {
      await new Promise((res) => setTimeout(res, 1000));
      t = await exchangeCode(ctx, code, verifier, redirectUri, `${operation}.token`);
    }
    if (t.status === 200 && t.json?.access_token) return { token: t.json.access_token, scope };
  }
  return undefined;
}

export async function exchangeCode(ctx: AuditContext, code: string, verifier: string, redirectUri: string, operation = 'oauth.token') {
  const tokenEndpoint = ctx.state.discovery?.token_endpoint ?? ctx.oauthUrl('/openbanking/oauth/token');
  return ctx.http.request({
    operation,
    method: 'POST',
    url: tokenEndpoint,
    form: {
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri,
      code_verifier: verifier,
      client_id: ctx.target.clientId ?? 'scio',
    },
  });
}

/** oneOff: a throwaway consent (GE-XS2A §9.1.1.3: recurringIndicator false, frequencyPerDay 1), which never replaces earlier recurring ones (§9.1.1.4). */
export async function createConsent(ctx: AuditContext, operation = 'consent.create', oneOff = false) {
  const validUntil = new Date(Date.now() + 89 * 86400_000);
  return api(ctx, operation, 'POST', '/v1/consents', {
    auth: false,
    consent: false,
    retries: 3,
    headers: { 'TPP-Redirect-URI': ctx.target.redirectUri ?? 'https://example.org/cb' },
    json: {
      access: { accounts: [], balances: [], transactions: [] },
      recurringIndicator: !oneOff,
      validUntil: isoDate(validUntil),
      frequencyPerDay: oneOff ? 1 : 4,
      combinedServiceIndicator: false,
    },
  });
}

/**
 * Happy path for a Berlin Group style bank with OAuth2 SCA:
 * discovery -> consent -> authorize (PKCE) -> token -> AIS reads.
 */
export async function runFullFlow(ctx: AuditContext) {
  const redirectUri = ctx.target.redirectUri ?? 'https://example.org/cb';

  const disc = await api(ctx, 'oauth.discovery', 'GET', ctx.oauthUrl('/.well-known/oauth-authorization-server'), { absolute: true, auth: false, consent: false });
  ctx.state.discovery = disc.json;
  ctx.state.discoveryResponse = disc;

  const consent = await createConsent(ctx);
  ctx.state.consentResponse = consent;
  if (unavailable(consent)) {
    // An outage is a reliability result; conformance could not be judged.
    ctx.add({ checkId: 'flow.consent', layer: 'conformance', status: 'skip', severity: 'none', title: 'Create AIS consent', endpoint: 'POST /v1/consents', message: `Could not be tested: service unavailable after retries (${ctx.short(consent)}). Later AIS checks are skipped. Rerun the audit.` });
    ctx.add({ checkId: 'rel.flow-outage', layer: 'reliability', status: 'fail', severity: 'high', title: 'Service available for the consent flow', endpoint: 'POST /v1/consents', message: `Consent creation failed with ${ctx.short(consent)} on every attempt (with backoff), so no AIS journey could start.`, expected: '201 Created', actual: ctx.short(consent), fix: 'Investigate the outage; return Retry-After with 503 so TPPs can back off, and publish incidents on a status page.' });
    return;
  }
  if (consent.status !== 201 || !consent.json?.consentId) {
    ctx.add({
      checkId: 'flow.consent',
      layer: 'conformance',
      status: 'fail',
      severity: 'high',
      title: 'Create AIS consent',
      endpoint: 'POST /v1/consents',
      message: `Consent could not be created (${ctx.short(consent)}). Later AIS checks are skipped.`,
      reference: REF.BG,
    });
    return;
  }
  ctx.state.consentId = consent.json.consentId;

  const { verifier, challenge } = pkcePair();
  const code = await obtainCode(ctx, `AIS:${ctx.state.consentId}`, challenge, redirectUri);
  if (!code) {
    ctx.add({ checkId: 'flow.authorize', layer: 'conformance', status: 'fail', severity: 'high', title: 'OAuth authorization (redirect SCA)', message: 'No authorization code was returned to the redirect URI.', reference: REF.OAUTH });
    return;
  }
  const token = await exchangeCode(ctx, code, verifier, redirectUri);
  if (token.status !== 200 || !token.json?.access_token) {
    ctx.add({ checkId: 'flow.token', layer: 'conformance', status: 'fail', severity: 'high', title: 'Token exchange', message: `Token request failed (${ctx.short(token)}).`, reference: REF.OAUTH });
    return;
  }
  ctx.state.token = token.json;
  ctx.state.usedCode = { code, verifier };
  ctx.pass({ checkId: 'flow.authorize', layer: 'conformance', title: 'Consent + OAuth flow completes', message: 'Consent created, authorised with PKCE (S256), and exchanged for an access token.' });

  ctx.state.consentStatus = await api(ctx, 'consent.status', 'GET', `/v1/consents/${ctx.state.consentId}/status`);
  ctx.state.consentDetails = await api(ctx, 'consent.get', 'GET', `/v1/consents/${ctx.state.consentId}`);

  const from = isoDate(new Date(Date.now() - 90 * 86400_000));
  const to = isoDate(new Date());
  ctx.state.txWindow = { from, to };

  const accounts = await api(ctx, 'ais.accounts', 'GET', '/v1/accounts?withBalance=true');
  ctx.state.accounts = accounts;
  const accList: any[] = accounts.json?.accounts ?? [];
  ctx.state.accountReads = [];
  for (const a of accList.slice(0, 3)) {
    const id = a.resourceId;
    const details = await api(ctx, 'ais.account', 'GET', `/v1/accounts/${encodeURIComponent(id)}`);
    const balances = await api(ctx, 'ais.balances', 'GET', `/v1/accounts/${encodeURIComponent(id)}/balances`);
    const tx = await api(ctx, 'ais.transactions', 'GET', `/v1/accounts/${encodeURIComponent(id)}/transactions?bookingStatus=booked&dateFrom=${from}&dateTo=${to}`);
    ctx.state.accountReads.push({ id, details, balances, tx });
  }

  const cards = await api(ctx, 'ais.cardAccounts', 'GET', '/v1/card-accounts');
  ctx.state.cards = cards;
  ctx.state.cardReads = [];
  for (const c of (cards.json?.cardAccounts ?? []).slice(0, 2)) {
    const id = c.resourceId;
    const details = await api(ctx, 'ais.cardAccount', 'GET', `/v1/card-accounts/${encodeURIComponent(id)}`);
    const balances = await api(ctx, 'ais.cardBalances', 'GET', `/v1/card-accounts/${encodeURIComponent(id)}/balances`);
    const tx = await api(ctx, 'ais.cardTransactions', 'GET', `/v1/card-accounts/${encodeURIComponent(id)}/transactions?bookingStatus=booked&dateFrom=${from}&dateTo=${to}`);
    ctx.state.cardReads.push({ id, details, balances, tx });
  }
}
