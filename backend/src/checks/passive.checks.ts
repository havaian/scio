import type { Dispatcher } from 'undici';
import { newRequestId } from '../common/http';
import { AuditContext, REF, sleep } from './context';
import { checkDiscovery, checkMtlsEnforced, checkTls, checkTransportHeaders } from './security.checks';
import { latencyFinding, stats } from './performance.checks';
import { checkErrorBodies } from './live-conformance.checks';
import { targetCaDispatcher } from '../common/credentials';

/** Server certificate errors that a bank's published test CA can resolve (not expiry or name mismatch). */
const CA_PATH_ERROR = /UNABLE_TO_GET_ISSUER_CERT|UNABLE_TO_VERIFY_LEAF_SIGNATURE|SELF_SIGNED_CERT|DEPTH_ZERO_SELF_SIGNED|CERT_UNTRUSTED/i;

/**
 * Public bank endpoints without credentials: read-only, unauthenticated, a handful of requests.
 * Nothing here tries to bypass authentication; it only observes how the front door behaves.
 */
export async function runPassive(ctx: AuditContext) {
  const t = ctx.target;

  if (t.discoveryUrl) {
    const d = await ctx.http.request({ operation: 'oauth.discovery', method: 'GET', url: t.discoveryUrl });
    checkDiscovery(ctx, d.status === 200 ? d.json : undefined, t.discoveryUrl);
    checkTransportHeaders(ctx, d, 'discovery');
    ctx.state.discoveryResponse = d;
  }
  const bankCa = targetCaDispatcher(t);
  await checkTls(ctx, t.baseUrl, bankCa?.ca);
  if (t.skipEndpointProbes) return;

  const url = `${t.baseUrl.replace(/\/$/, '')}${t.accountsPath ?? '/v1/accounts'}`;
  let valid = await ctx.http.request({ operation: 'passive.accounts', method: 'GET', url, headers: { 'X-Request-ID': newRequestId(), 'PSU-IP-Address': '192.0.2.10' } });
  // A sandbox whose server certificate chains to the test root the bank publishes on its portal: trust that root for
  // this bank only and look again, so client-certificate enforcement and the front door can still be judged.
  let viaCa: Dispatcher | undefined;
  if (valid.status === 0 && bankCa && CA_PATH_ERROR.test(valid.error ?? '')) {
    const firstError = valid.error;
    const again = await ctx.http.request({ operation: 'passive.accounts', method: 'GET', url, headers: { 'X-Request-ID': newRequestId(), 'PSU-IP-Address': '192.0.2.10' }, dispatcher: bankCa.dispatcher });
    const resolved = !(again.status === 0 && CA_PATH_ERROR.test(again.error ?? ''));
    // Unresolved: checkMtlsEnforced below reports the chain failure on the original error.
    if (resolved) ctx.add({ checkId: 'sec.server-cert-chain', layer: 'security', status: resolved ? 'info' : 'fail', severity: resolved ? 'none' : 'medium', title: 'Server certificate chain verifiable', endpoint: 'GET /v1/accounts', message: resolved ? `Not publicly trusted (${firstError}), but it verifies with the test root CA the bank publishes on its portal (${t.credentials?.ca}). Normal for a sandbox; TPPs must install that CA.` : `The server certificate verifies neither with the public trust store nor with the bank's published test CA (${again.error}).`, expected: 'chain to a public root, or to the test CA the bank publishes', actual: firstError, fix: resolved ? undefined : 'Serve the full certificate chain (leaf + intermediates) that leads to the published test root.', reference: 'GE-XS2A §5.2, §5.5' });
    if (resolved) {
      valid = again;
      viaCa = bankCa.dispatcher;
    }
  }
  checkMtlsEnforced(ctx, valid, 'GET /v1/accounts');
  checkTransportHeaders(ctx, valid, 'GET /v1/accounts');

  // Header validation happens before authentication at some banks: observable without credentials.
  const bad = await ctx.http.request({ operation: 'passive.invalid-request-id', method: 'GET', url, headers: { 'X-Request-ID': 'not-a-uuid' }, dispatcher: viaCa });
  if (bad.status > 0) {
    const ok = bad.status === 400 && /FORMAT_ERROR/.test(JSON.stringify(bad.json ?? ''));
    ctx.add({ checkId: 'neg.invalid-request-id', layer: 'conformance', status: ok ? 'pass' : bad.status === 401 || bad.status === 403 ? 'info' : 'warn', severity: ok ? 'none' : 'low', title: 'Non-UUID X-Request-ID is rejected', message: ok ? `Rejected with ${ctx.short(bad)} before authentication.` : `Answered ${ctx.short(bad)}; header validation could not be observed without credentials.`, expected: '400 FORMAT_ERROR', actual: ctx.short(bad), reference: REF.BG });
  }
  // Same rule as the live journey: tppMessages or RFC 7807 with a code, and the code's HTTP status.
  const errBodies = ctx.http.exchanges.filter((x) => (x.operation === 'passive.accounts' || x.operation === 'passive.invalid-request-id') && x.status >= 400 && x.status < 500);
  checkErrorBodies(ctx, errBodies, 'unauthenticated error responses');

  // Light latency sample of the front door (5 calls, 1 s apart).
  for (let i = 0; i < 5; i++) {
    await ctx.http.request({ operation: 'probe.front-door', method: 'GET', url, headers: { 'X-Request-ID': newRequestId() }, dispatcher: viaCa });
    await sleep(1000);
  }
  const xs = ctx.http.exchanges.filter((x) => x.operation === 'probe.front-door');
  const s = stats('front door (unauthenticated)', xs);
  // No HTTP answer at all = refused at TLS level (mTLS) or unreachable: not an availability sample.
  if (xs.some((x) => x.status > 0)) ctx.state.endpointStats = [s];
  if (xs.every((x) => x.status === 0)) {
    ctx.add({ checkId: 'lat.p95', layer: 'latency', status: 'skip', severity: 'none', title: 'Response time', endpoint: s.operation, message: /CERT_|SELF_SIGNED|ALTNAME/i.test(xs[0]?.error ?? '') ? `No HTTP responses: the server certificate could not be verified (${xs[0]?.error}).` : /TIMEOUT|ETIMEDOUT|ECONNREFUSED|ENOTFOUND/i.test(xs[0]?.error ?? '') ? `No HTTP responses (${xs[0]?.error}): the host did not answer, so it may be down or allow only listed IP addresses.` : `No HTTP responses (${xs[0]?.error ?? 'unknown'}). With mTLS enforced at TLS level, latency needs a client certificate.` });
  } else {
    // Front door only: unauthenticated, a handful of calls, so slow answers are a low-severity signal.
    latencyFinding(ctx, s, ' (front door, unauthenticated)', 'low');
    ctx.add({ checkId: 'rel.availability', layer: 'reliability', status: s.availabilityPct >= ctx.thresholds.availabilityPct ? 'pass' : 'warn', severity: 'none', title: 'Availability and error rate', endpoint: s.operation, message: `${s.availabilityPct}% of ${s.samples} front-door calls answered without a server error (${Object.entries(s.statuses).map(([k, v]) => `${k}×${v}`).join(', ')}).${s.availabilityPct === 0 && Object.keys(s.statuses).some((k) => Number(k) >= 500) ? ' The host is up but answers an unauthenticated request with a server error instead of 401/403.' : ''}`, evidence: s });
  }
}
