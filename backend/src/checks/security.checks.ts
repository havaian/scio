import * as tls from 'node:tls';
import { HttpResponse, newRequestId } from '../common/http';
import { api, exchangeCode, obtainCode, pkcePair } from '../flows/full.flow';
import { AuditContext, REF } from './context';

/** Layer 4: discovery metadata, transport and OAuth hardening. */
export function checkDiscovery(ctx: AuditContext, disc: any, source: string) {
  if (!disc) {
    ctx.add({ checkId: 'sec.discovery', layer: 'security', status: 'fail', severity: 'medium', title: 'OAuth discovery document', message: `No discovery document at ${source}.`, fix: 'Publish OAuth/OpenID discovery metadata so TPPs can configure clients automatically.', reference: REF.OAUTH });
    return;
  }
  const methods: string[] = disc.token_endpoint_auth_methods_supported ?? [];
  const strong = methods.filter((m) => ['tls_client_auth', 'self_signed_tls_client_auth', 'private_key_jwt'].includes(m));
  const weak = methods.filter((m) => ['none', 'client_secret_basic', 'client_secret_post'].includes(m));
  if (!methods.length)
    ctx.add({ checkId: 'sec.client-auth', layer: 'security', status: 'warn', severity: 'low', title: 'Client authentication methods', message: 'token_endpoint_auth_methods_supported is not published.', reference: REF.FAPI });
  else if (weak.length)
    ctx.add({ checkId: 'sec.client-auth', layer: 'security', status: 'fail', severity: 'high', title: 'Client authentication methods', message: `Token endpoint accepts weak client authentication: ${weak.join(', ')}.`, expected: 'tls_client_auth or private_key_jwt only', actual: methods.join(', '), fix: 'Accept only certificate-based (tls_client_auth) or private_key_jwt client authentication at the token endpoint.', reference: `${REF.FAPI}; ${REF.MTLS}` });
  else ctx.pass({ checkId: 'sec.client-auth', layer: 'security', title: 'Client authentication methods', message: `Only strong methods advertised: ${strong.join(', ')}.` });

  if (disc.tls_client_certificate_bound_access_tokens === false)
    ctx.add({ checkId: 'sec.bound-tokens', layer: 'security', status: 'fail', severity: 'medium', title: 'Certificate-bound access tokens', message: 'tls_client_certificate_bound_access_tokens is false: a stolen token works from any client.', expected: 'true', actual: 'false', fix: 'Bind access tokens to the TPP certificate (RFC 8705 cnf claim) and advertise it.', reference: REF.MTLS });
  else if (disc.tls_client_certificate_bound_access_tokens === true)
    ctx.pass({ checkId: 'sec.bound-tokens', layer: 'security', title: 'Certificate-bound access tokens', message: 'Advertised as supported.' });

  const pkce: string[] = disc.code_challenge_methods_supported ?? [];
  if (pkce.includes('plain'))
    ctx.add({ checkId: 'sec.pkce-methods', layer: 'security', status: 'fail', severity: 'medium', title: 'PKCE methods', message: 'PKCE "plain" is allowed.', fix: 'Allow only S256.', reference: REF.PKCE });
  else if (pkce.includes('S256')) ctx.pass({ checkId: 'sec.pkce-methods', layer: 'security', title: 'PKCE methods', message: 'Only S256 advertised.' });
  // FAPI 1.0 Part 1 §5.2.2-7 (required by GE-IAA §6.1): PKCE with S256 is mandatory, so the metadata should say so.
  else ctx.add({ checkId: 'sec.pkce-methods', layer: 'security', status: 'warn', severity: 'low', title: 'PKCE methods', message: pkce.length ? `code_challenge_methods_supported lists ${pkce.join(', ')} but not S256.` : 'code_challenge_methods_supported is not published, so a TPP cannot tell whether PKCE (S256) is enforced.', expected: 'code_challenge_methods_supported: ["S256"]', fix: 'Require PKCE with S256 and advertise it in the discovery metadata (RFC 8414).', reference: REF.PKCE });

  for (const k of ['authorization_endpoint', 'token_endpoint']) {
    if (disc[k] && !String(disc[k]).startsWith('https://'))
      ctx.add({ checkId: 'sec.https-endpoints', layer: 'security', status: 'fail', severity: 'high', title: 'HTTPS endpoints', message: `${k} is not HTTPS.`, reference: REF.OAUTH });
  }
}

export function checkTransportHeaders(ctx: AuditContext, r: HttpResponse | undefined, where: string) {
  if (!r || r.status === 0) return;
  const hsts = r.headers['strict-transport-security'];
  if (!hsts) ctx.add({ checkId: 'sec.hsts', layer: 'security', status: 'warn', severity: 'low', title: 'HSTS header', endpoint: where, message: 'No Strict-Transport-Security header.', fix: 'Send Strict-Transport-Security: max-age=31536000; includeSubDomains.', reference: REF.HSTS });
  else ctx.pass({ checkId: 'sec.hsts', layer: 'security', title: 'HSTS header', endpoint: where, message: hsts });

  const acao = r.headers['access-control-allow-origin'];
  if (acao === '*')
    ctx.add({ checkId: 'sec.cors', layer: 'security', status: 'warn', severity: 'medium', title: 'CORS policy', endpoint: where, message: 'Access-Control-Allow-Origin: * lets any website call the API from a browser. XS2A traffic is server-to-server from licensed TPPs.', fix: 'Remove CORS headers from XS2A endpoints, or restrict them to known origins.', reference: REF.GE });
}

/** TLS alerts a server sends when it requires a client certificate (bad_certificate 42, handshake_failure 40, certificate_required 116). */
const CLIENT_CERT_REQUIRED = /certificate.required|CERTIFICATE_REQUIRED|ALERT_HANDSHAKE_FAILURE|ALERT_BAD_CERTIFICATE|alert number (40|42|116)|handshake failure/i;
/** Errors raised when the client cannot verify the server's certificate. */
const SERVER_CERT_ERROR = /UNABLE_TO_GET_ISSUER_CERT|UNABLE_TO_VERIFY_LEAF_SIGNATURE|CERT_HAS_EXPIRED|CERT_NOT_YET_VALID|SELF_SIGNED_CERT|DEPTH_ZERO_SELF_SIGNED|ERR_TLS_CERT_ALTNAME|CERT_UNTRUSTED/i;

/** Without a client certificate the bank must refuse at TLS or HTTP level. */
export function checkMtlsEnforced(ctx: AuditContext, r: HttpResponse, where: string) {
  const err = r.error ?? '';
  if (r.status === 0 && /proxy/i.test(err)) {
    ctx.add({ checkId: 'sec.mtls-enforced', layer: 'security', status: 'skip', severity: 'none', title: 'Client certificate enforced', endpoint: where, message: `Could not determine through the local proxy: ${err}` });
  } else if (r.status === 0 && SERVER_CERT_ERROR.test(err)) {
    // Our side rejected the bank's certificate: says nothing about client-certificate enforcement.
    const viaProxy = !!(process.env.HTTPS_PROXY || process.env.HTTP_PROXY);
    ctx.add({ checkId: 'sec.mtls-enforced', layer: 'security', status: 'skip', severity: 'none', title: 'Client certificate enforced', endpoint: where, message: `Not determinable: the server certificate failed verification first (${err}).` });
    ctx.add({ checkId: 'sec.server-cert-chain', layer: 'security', status: viaProxy ? 'info' : 'fail', severity: viaProxy ? 'none' : 'medium', title: 'Server certificate chain verifiable', endpoint: where, message: viaProxy ? `Certificate verification failed (${err}), but a proxy is configured and may be the cause. Rerun with a direct connection.` : `The server certificate could not be verified with the public trust store (${err}): a missing intermediate certificate, an expired or self-signed certificate, or a private test CA. Strict TPP clients will refuse to connect unless the bank publishes that CA.`, expected: 'complete chain to a trusted root', actual: err, fix: viaProxy ? undefined : 'Serve the full certificate chain (leaf + intermediates) from a publicly trusted CA, or publish the test CA for TPPs; renew certificates before expiry.', reference: REF.FAPI });
  } else if (r.status === 0 && CLIENT_CERT_REQUIRED.test(err)) {
    ctx.pass({ checkId: 'sec.mtls-enforced', layer: 'security', title: 'Client certificate enforced', endpoint: where, message: `Connection refused at TLS level without a client certificate (${err}).` });
  } else if (r.status === 0 && /ECONNRESET|socket|EPROTO/i.test(err)) {
    // A reset can be mTLS enforcement or a network fault: not proof either way.
    ctx.add({ checkId: 'sec.mtls-enforced', layer: 'security', status: 'info', severity: 'none', title: 'Client certificate enforced', endpoint: where, message: `Connection closed during the handshake without a client certificate (${err}). Consistent with mTLS enforcement, but a network fault looks the same.` });
  } else if ([401, 403].includes(r.status)) {
    // Only a certificate error code proves the refusal was for the missing certificate; TOKEN_MISSING etc. say nothing about it.
    const codes = errorCodes(r.json);
    const certCode = codes.find((c) => /^CERTIFICATE_/i.test(c));
    if (certCode) ctx.pass({ checkId: 'sec.mtls-enforced', layer: 'security', title: 'Client certificate enforced', endpoint: where, message: `Refused at HTTP level without a client certificate (${ctx.short(r)}, ${certCode}).` });
    else ctx.add({ checkId: 'sec.mtls-enforced', layer: 'security', status: 'info', severity: 'none', title: 'Client certificate enforced', endpoint: where, message: `Refused without a client certificate (${ctx.short(r)}), but for the token${codes.length ? ` (${codes.join(', ')})` : ''}; certificate enforcement is not observable.`, actual: ctx.short(r) });
  } else if (r.status >= 200 && r.status < 300) {
    ctx.add({ checkId: 'sec.mtls-enforced', layer: 'security', status: 'fail', severity: 'high', title: 'Client certificate enforced', endpoint: where, message: `Request without any client certificate was served (${ctx.short(r)}).`, expected: 'TLS handshake failure or 401 CERTIFICATE_MISSING', actual: ctx.short(r), fix: 'Require a valid QWAC client certificate from a Georgian-recognised issuer on every XS2A and token endpoint.', reference: `${REF.GE}; ${REF.MTLS}` });
  } else if (r.status > 0) {
    ctx.add({ checkId: 'sec.mtls-enforced', layer: 'security', status: 'info', severity: 'none', title: 'Client certificate enforced', endpoint: where, message: `Request reached the application without a client certificate and was answered ${ctx.short(r)}. Certificate checking may happen after request validation.` });
  } else {
    ctx.add({ checkId: 'sec.mtls-enforced', layer: 'security', status: 'skip', severity: 'none', title: 'Client certificate enforced', endpoint: where, message: `No response: ${err}` });
  }
}

/** Error codes in a tppMessages array or an RFC 7807 body (member names matched case-insensitively). */
function errorCodes(json: any): string[] {
  if (!json || typeof json !== 'object') return [];
  const get = (o: any, k: string) => (o && typeof o === 'object' ? o[Object.keys(o).find((x) => x.toLowerCase() === k.toLowerCase()) ?? ''] : undefined);
  const msgs = get(json, 'tppMessages');
  const list = [...(Array.isArray(msgs) ? msgs : []).map((m: any) => get(m, 'code')), get(json, 'code'), ...(Array.isArray(get(json, 'additionalErrors')) ? get(json, 'additionalErrors').map((m: any) => get(m, 'code')) : [])];
  return list.filter((c): c is string => typeof c === 'string');
}

/** TLS handshake inspection. Needs a direct connection: through an intercepting proxy the certificate seen is the proxy's. */
export async function checkTls(ctx: AuditContext, urlStr: string, ca?: string[]) {
  if (process.env.HTTPS_PROXY || process.env.HTTP_PROXY) {
    ctx.add({ checkId: 'sec.tls', layer: 'security', status: 'skip', severity: 'none', title: 'TLS version and certificate', endpoint: urlStr, message: 'Skipped: TLS inspection needs a direct connection and a proxy is configured.' });
    return;
  }
  const u = new URL(urlStr);
  const info = await new Promise<{ protocol?: string; cipher?: string; validTo?: string; issuer?: string; error?: string }>((resolve) => {
    // ca: the bank's published test root next to the public roots (sandboxes), so the handshake can be inspected.
    const s = tls.connect({ host: u.hostname, port: Number(u.port || 443), servername: u.hostname, timeout: 10000, ...(ca ? { ca } : {}) }, () => {
      const cert = s.getPeerCertificate();
      const iss = cert?.issuer?.O ?? cert?.issuer?.CN;
      resolve({ protocol: s.getProtocol() ?? undefined, cipher: s.getCipher()?.name, validTo: cert?.valid_to, issuer: Array.isArray(iss) ? iss.join(', ') : iss });
      s.end();
    });
    s.on('error', (e) => resolve({ error: e.message }));
    s.on('timeout', () => {
      resolve({ error: 'timeout' });
      s.destroy();
    });
  });
  if (info.error) {
    // A handshake that fails only because no client certificate was offered still tells us TLS is enforced.
    // A server certificate we cannot verify is a different matter: say so instead of blaming the missing client certificate.
    const message = SERVER_CERT_ERROR.test(info.error) ? `Handshake did not complete: the server certificate failed verification (${info.error}).` : `Handshake did not complete without a client certificate: ${info.error}`;
    ctx.add({ checkId: 'sec.tls', layer: 'security', status: 'info', severity: 'none', title: 'TLS version and certificate', endpoint: u.host, message });
    return;
  }
  const versionOk = info.protocol === 'TLSv1.3' || info.protocol === 'TLSv1.2';
  const daysLeft = info.validTo ? Math.floor((Date.parse(info.validTo) - Date.now()) / 86400_000) : undefined;
  const status = !versionOk ? 'fail' : daysLeft !== undefined && daysLeft < ctx.thresholds.certExpiryWarnDays ? 'warn' : 'pass';
  ctx.add({
    checkId: 'sec.tls',
    layer: 'security',
    status,
    severity: status === 'fail' ? 'high' : status === 'warn' ? 'medium' : 'none',
    title: 'TLS version and certificate',
    endpoint: u.host,
    message: `${info.protocol}, ${info.cipher}; certificate by ${info.issuer ?? '?'} valid until ${info.validTo}${daysLeft !== undefined ? ` (${daysLeft} days)` : ''}.`,
    fix: status === 'pass' ? undefined : 'Use TLS 1.2+ (prefer 1.3) and renew certificates well before expiry.',
    reference: REF.FAPI,
    evidence: info,
  });
}

/** Active OAuth hardening tests. Only run on targets provided for testing (mode "full"). */
export async function runActiveSecurity(ctx: AuditContext) {
  checkDiscovery(ctx, ctx.state.discovery, ctx.oauthUrl('/.well-known/oauth-authorization-server'));
  checkTransportHeaders(ctx, ctx.state.accounts ?? ctx.state.discoveryResponse, 'XS2A API');
  checkMtlsEnforced(ctx, ctx.state.accounts ?? ctx.state.discoveryResponse, 'GET /v1/accounts');
  await checkTls(ctx, ctx.target.baseUrl);

  if (ctx.target.simulated) {
    ctx.add({ checkId: 'sec.mock-note', layer: 'security', status: 'info', severity: 'none', title: 'Simulated target', message: 'This target is the organizers\' mock. Its spec marks signature, digest and request-ID headers as relaxed and it uses mock bearer tokens, so security results describe the mock, not the real bank. Cross-check with the public test environment.' });
  }
  if (!ctx.state.consentId) return;
  const redirectUri = ctx.target.redirectUri ?? 'https://example.org/cb';
  const scope = `AIS:${ctx.state.consentId}`;

  // Transient outages (5xx/timeouts) must never be read as "accepted": retry, then report as untestable.
  const exchangeRetry = async (code: string, verifier: string, uri: string, op: string) => {
    let r = await exchangeCode(ctx, code, verifier, uri, op);
    for (let i = 0; i < 2 && (r.status === 0 || r.status >= 500); i++) {
      await new Promise((res) => setTimeout(res, 1000));
      r = await exchangeCode(ctx, code, verifier, uri, op);
    }
    return r;
  };
  const codeRetry = async (challenge: string) => {
    for (let i = 0; i < 3; i++) {
      const c = await obtainCode(ctx, scope, challenge, redirectUri);
      if (c) return c;
      await new Promise((res) => setTimeout(res, 1000));
    }
    return undefined;
  };
  const untestable = (id: string, title: string, why: string) =>
    ctx.add({ checkId: id, layer: 'security', status: 'skip', severity: 'none', title, message: `Could not be tested: ${why}. Rerun the audit.` });

  // Authorization code replay.
  if (ctx.state.usedCode) {
    const r = await exchangeRetry(ctx.state.usedCode.code, ctx.state.usedCode.verifier, redirectUri, 'neg.code-replay');
    oauthNeg(ctx, 'sec.code-replay', 'Authorization code cannot be reused', r, 'high', 'Invalidate authorization codes after first use and revoke tokens issued from a replayed code.');
  }

  // Wrong PKCE verifier.
  const p1 = pkcePair();
  const code1 = await codeRetry(p1.challenge);
  if (code1) {
    const r = await exchangeRetry(code1, pkcePair().verifier, redirectUri, 'neg.pkce-wrong-verifier');
    oauthNeg(ctx, 'sec.pkce-enforced', 'PKCE verifier is checked', r, 'high', 'Reject token requests whose code_verifier does not hash to the stored code_challenge.');
  } else untestable('sec.pkce-enforced', 'PKCE verifier is checked', 'no authorization code could be obtained');

  // redirect_uri mismatch.
  const p2 = pkcePair();
  const code2 = await codeRetry(p2.challenge);
  if (code2) {
    const r = await exchangeRetry(code2, p2.verifier, 'https://attacker.example/cb', 'neg.redirect-mismatch');
    oauthNeg(ctx, 'sec.redirect-binding', 'redirect_uri must match the authorization request', r, 'medium', 'Compare redirect_uri at the token endpoint with the one used in the authorization request.');
  } else untestable('sec.redirect-binding', 'redirect_uri must match the authorization request', 'no authorization code could be obtained');

  // Signature header enforcement (the standard lets ASPSPs mandate X-JWS-Signature; the Georgian profile uses it).
  const unsigned = await api(ctx, 'neg.unsigned', 'GET', '/v1/accounts', { validate: false });
  // GE-XS2A §5.4 makes the TPP seal mandatory and its verification by the bank mandatory. A simulated target whose own
  // spec relaxes the signature headers gets a warning (the mock is not the bank); any other target a failure.
  if (unsigned.status === 200)
    ctx.add({ checkId: 'sec.message-signing', layer: 'security', status: ctx.target.simulated ? 'warn' : 'fail', severity: ctx.target.simulated ? 'medium' : 'high', title: 'Unsigned requests are refused', endpoint: 'GET /v1/accounts', message: `Requests without x-jws-signature / Digest are accepted.${ctx.target.simulated ? ' The mock\'s spec relaxes the signature headers, so this describes the mock, not the bank.' : ''}`, expected: '401 SIGNATURE_MISSING (GE-XS2A §5.4, §7.4)', actual: ctx.short(unsigned), fix: 'Require and verify the TPP seal (Digest + x-jws-signature, GE-JWS) on every request.', reference: 'GE-XS2A §5.4, §7.4; GE-JWS §5' });

  const token = ctx.state.token;
  if (token?.expires_in && Number(token.expires_in) > 3600)
    ctx.add({ checkId: 'sec.token-lifetime', layer: 'security', status: 'warn', severity: 'low', title: 'Access token lifetime', message: `Access tokens live ${token.expires_in}s.`, fix: 'Keep access tokens short-lived (<= 1 hour) and rely on refresh tokens.', reference: REF.FAPI });
  else if (token?.expires_in) ctx.pass({ checkId: 'sec.token-lifetime', layer: 'security', title: 'Access token lifetime', message: `${token.expires_in}s.` });
}

function oauthNeg(ctx: AuditContext, id: string, title: string, r: HttpResponse, severity: 'high' | 'medium', fix: string) {
  if (r.status === 0 || r.status >= 500) {
    ctx.add({ checkId: id, layer: 'security', status: 'skip', severity: 'none', title, endpoint: 'POST token endpoint', message: `Could not be tested: the token endpoint was unavailable (${ctx.short(r)}) after retries. Rerun the audit.` });
    return;
  }
  // Only a 2xx that issues a token counts as "accepted"; other 4xx are rejections.
  const ok = !(r.status >= 200 && r.status < 300);
  ctx.add({
    checkId: id,
    layer: 'security',
    status: ok ? 'pass' : 'fail',
    severity: ok ? 'none' : severity,
    title,
    endpoint: 'POST token endpoint',
    message: ok ? `Rejected (${ctx.short(r)}).` : `Accepted: ${ctx.short(r)}${r.json?.access_token ? ', an access token was issued' : ''}.`,
    expected: '400 invalid_grant',
    actual: ctx.short(r),
    fix: ok ? undefined : fix,
    reference: `${REF.OAUTH}; ${REF.PKCE}`,
  });
}

export { newRequestId };
