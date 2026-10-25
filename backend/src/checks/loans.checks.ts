import { HttpResponse } from '../common/http';
import { api, authorizeScopes, unavailable } from '../flows/full.flow';
import { AuditContext, REF } from './context';
import { errCode, is } from './live-conformance.checks';
import { runNegatives } from './pis.checks';

/**
 * Deposit (savings) and loan information sharing, through the v2 account-access consent.
 * NBG lists both as "available, not yet in practical use". Only runs when the spec documents them.
 */

const isoDate = (d: Date) => d.toISOString().slice(0, 10);

function has(ctx: AuditContext, method: string, path: string) {
  return !!ctx.spec?.operations.some((o) => o.method === method && o.path === path);
}

/** IBANs to request in the consent: the bank's own documented example first (sandboxes usually seed those). */
function exampleAccess(ctx: AuditContext) {
  const op = ctx.spec?.operations.find((o) => o.method === 'POST' && o.path === '/v2/consents/account-access');
  const ex: any = Object.values<any>(op?.op?.requestBody?.content?.['application/json']?.examples ?? {})[0];
  const value = ex?.$ref ? ctx.spec!.resolve(ex.$ref)?.value : ex?.value;
  if (value?.access?.loans || value?.access?.savings) return value.access;
  return { loans: [], savings: [] };
}

/** Refusal because the consent does not cover the resource: 403, or a CONSENT_* message code (BG IG §14.11). */
export function consentScopeRefusal(r: HttpResponse): boolean {
  return r.status === 403 || ([400, 401].includes(r.status) && /^CONSENT_/.test(errCode(r) ?? ''));
}

export async function runLoans(ctx: AuditContext) {
  if (!has(ctx, 'POST', '/v2/consents/account-access')) return;
  // One-off (GE-XS2A §9.1.1.3: frequencyPerDay 1), so it cannot replace the main recurring AIS consent (§9.1.1.4) that later checks use.
  const consentBody = { access: exampleAccess(ctx), consentType: 'detailed', recurringIndicator: false, validTo: isoDate(new Date(Date.now() + 89 * 86400_000)), frequencyPerDay: 1 };
  const consent = await api(ctx, 'v2.consent.create', 'POST', '/v2/consents/account-access', {
    auth: false,
    consent: false,
    headers: { 'TPP-Redirect-URI': ctx.target.redirectUri ?? 'https://example.org/cb' },
    json: consentBody,
    retries: 3,
  });
  const endpoint = 'POST /v2/consents/account-access';
  if (unavailable(consent)) {
    ctx.add({ checkId: 'v2.consent', layer: 'conformance', status: 'skip', severity: 'none', title: 'Create deposit/loan consent', endpoint, message: `Could not be tested: service unavailable after retries (${ctx.short(consent)}). Deposit and loan checks skipped.` });
    return;
  }
  if (consent.status !== 201 || !consent.json?.consentId) {
    ctx.add({ checkId: 'v2.consent', layer: 'conformance', status: 'fail', severity: 'high', title: 'Create deposit/loan consent', endpoint, message: `The consent for loans and savings was not created (${ctx.short(consent)}).`, expected: '201 with consentId', actual: ctx.short(consent), fix: 'Accept the documented account-access consent (loans, savings with rights) and return 201 with consentId and SCA links.', reference: REF.GE, evidence: { request: consentBody } });
    return;
  }
  const consentId: string = consent.json.consentId;
  const problems: string[] = [];
  if (consent.json.consentStatus !== 'received') problems.push(`consentStatus "${consent.json.consentStatus}", expected "received"`);
  if (!consent.json._links?.scaOAuth && !consent.json._links?.scaRedirect && !consent.json._links?.startAuthorisation) problems.push('no SCA link in _links');
  if (!consent.headers['location']) problems.push('missing Location header');
  ctx.add({ checkId: 'v2.consent', layer: 'conformance', status: problems.length ? 'warn' : 'pass', severity: problems.length ? 'low' : 'none', title: 'Create deposit/loan consent', endpoint, message: problems.length ? problems.join('; ') : `Consent ${consentId} created with SCA link.`, fix: problems.length ? 'Return consentStatus "received", Location and the SCA link.' : undefined, reference: REF.BG });

  const auth = await authorizeScopes(ctx, [`AIS:${consentId}`, `LOANS:${consentId}`, `SAVINGS:${consentId}`], 'v2.oauth');
  if (!auth) {
    ctx.add({ checkId: 'v2.authorize', layer: 'conformance', status: 'fail', severity: 'high', title: 'Deposit/loan consent authorisation', endpoint: 'authorize + token', message: 'No access token could be obtained for the v2 consent (tried scopes AIS:, LOANS:, SAVINGS: + consentId).', fix: 'Support OAuth2 SCA for account-access consents with the same scope convention as AIS.', reference: REF.OAUTH });
    return;
  }
  ctx.pass({ checkId: 'v2.authorize', layer: 'conformance', title: 'Deposit/loan consent authorisation', endpoint: 'authorize + token', message: `Authorised with PKCE, scope "${auth.scope}".` });
  const opts = { token: auth.token, consentId };
  ctx.state.v2 = { consentId, token: auth.token };
  ctx.state.extraBodies ??= [];

  const status = await api(ctx, 'v2.consent.status', 'GET', `/v2/consents/account-access/${consentId}/status`, opts);
  if (!unavailable(status)) {
    const ok = status.status === 200 && status.json?.consentStatus === 'valid';
    ctx.add({ checkId: 'v2.consent-status', layer: 'conformance', status: ok ? 'pass' : 'warn', severity: ok ? 'none' : 'low', title: 'Consent valid after authorisation', endpoint: 'GET /v2/consents/account-access/{consentId}/status', message: ok ? 'consentStatus "valid".' : `consentStatus "${status.json?.consentStatus ?? ctx.short(status)}" after successful SCA.`, expected: '"valid"', fix: ok ? undefined : 'Set the consent to "valid" once the PSU authorises it.', reference: REF.BG });
  }

  // Lists, details, balances for each family.
  for (const fam of ['savings', 'loans'] as const) {
    if (!has(ctx, 'GET', `/v2/${fam}`)) continue;
    const list = await api(ctx, `v2.${fam}.list`, 'GET', `/v2/${fam}?withBalance=true`, opts);
    ctx.state[`${fam}List`] = list;
    if (unavailable(list)) continue;
    const items: any[] = list.json?.accounts ?? list.json?.[fam] ?? [];
    const ok = list.status === 200;
    ctx.add({ checkId: `v2.${fam}.list`, layer: 'conformance', status: ok ? 'pass' : 'fail', severity: ok ? 'none' : 'high', title: `${fam === 'savings' ? 'Deposit' : 'Loan'} list`, endpoint: `GET /v2/${fam}`, message: ok ? `${items.length} ${fam === 'savings' ? 'deposits' : 'loans'} returned.` : `Could not be read (${ctx.short(list)}).`, expected: '200', actual: ctx.short(list), fix: ok ? undefined : `Serve GET /v2/${fam} for a valid consent.`, reference: REF.GE });
    if (ok) ctx.state.extraBodies.push(list.json);
    const id = items[0]?.resourceId;
    if (!id) continue;

    const det = await api(ctx, `v2.${fam}.details`, 'GET', `/v2/${fam}/${encodeURIComponent(id)}`, opts);
    if (det.status === 200) ctx.state.extraBodies.push(det.json);

    // The published spec has "/v2/loans{resourceId}/balances" (missing "/"). Test what the implementation actually serves.
    const malformedDocumented = ctx.spec!.operations.some((o) => o.path === `/v2/${fam}{resourceId}/balances`);
    // When the spec only has the malformed path, the corrected one matches an unrelated operation: skip schema validation.
    const proper = await api(ctx, `v2.${fam}.balances`, 'GET', `/v2/${fam}/${encodeURIComponent(id)}/balances`, { ...opts, validate: !malformedDocumented });
    if (proper.status === 200) ctx.state.extraBodies.push(proper.json);
    if (malformedDocumented) {
      const asDocumented = await api(ctx, `v2.${fam}.balances.as-documented`, 'GET', `/v2/${fam}${encodeURIComponent(id)}/balances`, { ...opts, validate: false });
      const served = proper.status === 200 ? 'the corrected path' : asDocumented.status === 200 ? 'only the documented (malformed) path' : 'neither path';
      ctx.add({
        checkId: 'v2.path-as-documented',
        layer: 'conformance',
        status: proper.status === 200 && asDocumented.status !== 200 ? 'fail' : proper.status === 200 ? 'warn' : 'fail',
        severity: 'medium',
        title: 'Documented path matches the implementation',
        endpoint: `GET /v2/${fam}{resourceId}/balances`,
        message: `The spec documents /v2/${fam}{resourceId}/balances. Calling it as documented answered ${ctx.short(asDocumented)}; the corrected /v2/${fam}/{resourceId}/balances answered ${ctx.short(proper)}. The implementation serves ${served}, so a client generated from the spec ${asDocumented.status === 200 ? 'works only by accident' : 'cannot read balances'}.`,
        expected: `/v2/${fam}/{resourceId}/balances documented and served`,
        actual: `documented: ${ctx.short(asDocumented)}; corrected: ${ctx.short(proper)}`,
        fix: `Fix the path in the published OpenAPI document to /v2/${fam}/{resourceId}/balances.`,
        reference: REF.OAS,
      });
    } else if (!unavailable(proper)) {
      const ok = proper.status === 200;
      ctx.add({ checkId: `v2.${fam}.balances`, layer: 'conformance', status: ok ? 'pass' : 'fail', severity: ok ? 'none' : 'medium', title: `${fam === 'savings' ? 'Deposit' : 'Loan'} balances`, endpoint: `GET /v2/${fam}/{resourceId}/balances`, message: ok ? 'Served.' : `Not served (${ctx.short(proper)}).`, reference: REF.GE });
    }
  }

  // Negative tests.
  const firstSaving = (ctx.state.savingsList?.json?.accounts ?? ctx.state.savingsList?.json?.savings ?? [])[0]?.resourceId;
  const aisToken: string | undefined = ctx.state.token?.access_token;
  await runNegatives(ctx, [
    { id: 'v2.neg.no-consent', title: 'Deposit list without Consent-ID is rejected', endpoint: 'GET /v2/savings', run: () => api(ctx, 'v2.neg.no-consent', 'GET', '/v2/savings', { token: auth.token, consent: false, validate: false }), expect: is(400, 'FORMAT_ERROR'), expected: '400 FORMAT_ERROR', severity: 'low', fix: 'A missing mandatory header is a format error: 400 FORMAT_ERROR naming Consent-ID.' },
    { id: 'v2.neg.no-token', title: 'Deposit list without access token is rejected', endpoint: 'GET /v2/savings', run: () => api(ctx, 'v2.neg.no-token', 'GET', '/v2/savings', { auth: false, consentId, validate: false }), expect: (r: HttpResponse) => r.status === 401, expected: '401 TOKEN_UNKNOWN / TOKEN_INVALID', severity: 'high', layer: 'security', fix: 'Require a valid access token on every deposit and loan call.' },
    { id: 'v2.neg.unknown-resource', title: 'Unknown deposit id is rejected', endpoint: 'GET /v2/savings/{resourceId}', run: () => api(ctx, 'v2.neg.unknown-resource', 'GET', '/v2/savings/does-not-exist', { ...opts, validate: false }), expect: (r: HttpResponse) => [403, 404].includes(r.status) && errCode(r) === 'RESOURCE_UNKNOWN', expected: '404 RESOURCE_UNKNOWN', severity: 'low', fix: 'Return 404 RESOURCE_UNKNOWN for deposit ids unknown or outside the consent.' },
    // Needs the AIS token too: without it the 401 would only show that a token is required.
    // Only a consent-scope refusal passes; other 4xx are reported as a different rejection.
    ...(ctx.state.consentId && aisToken && firstSaving
      ? [{ id: 'v2.neg.ais-consent', title: 'AIS consent cannot read deposits', endpoint: 'GET /v2/savings/{resourceId}', run: () => api(ctx, 'v2.neg.ais-consent', 'GET', `/v2/savings/${encodeURIComponent(firstSaving)}`, { token: aisToken, consentId: ctx.state.consentId, validate: false }), expect: consentScopeRefusal, expected: '401 CONSENT_INVALID or 403 (consent does not cover deposits)', severity: 'high' as const, layer: 'security' as const, fix: 'Check that the consent behind the token covers deposits before serving them.' }]
      : []),
  ]);

  // Deleting the v2 consent revokes it.
  if (has(ctx, 'DELETE', '/v2/consents/account-access/{consentId}')) {
    const del = await api(ctx, 'v2.consent.delete', 'DELETE', `/v2/consents/account-access/${consentId}`, opts);
    const after = await api(ctx, 'v2.consent.after-delete', 'GET', '/v2/savings', { ...opts, validate: false });
    if (!unavailable(del) && !unavailable(after)) {
      const ok = (del.status === 204 || del.status === 200) && after.status >= 400;
      ctx.add({ checkId: 'v2.consent-delete', layer: 'security', status: ok ? 'pass' : 'fail', severity: ok ? 'none' : 'high', title: 'Deleted consent stops data access', endpoint: 'DELETE /v2/consents/account-access/{consentId}', message: ok ? `Deleted (${ctx.short(del)}); later read refused (${ctx.short(after)}).` : `Delete answered ${ctx.short(del)}, then the deposit list answered ${ctx.short(after)}.`, expected: '204, then 401 CONSENT_INVALID / 403', actual: `${ctx.short(del)} -> ${ctx.short(after)}`, fix: ok ? undefined : 'Revoke all access through a consent as soon as the TPP deletes it.', reference: REF.BG });
    }
  }
}
