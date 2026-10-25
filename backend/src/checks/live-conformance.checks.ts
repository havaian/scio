import { constants, createHash, verify as cryptoVerify, X509Certificate } from 'node:crypto';
import { HttpResponse } from '../common/http';
import { signingString } from '../common/credentials';
import { api, createConsent, SchemaResult } from '../flows/full.flow';
import { AuditContext, REF } from './context';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function errCode(r: HttpResponse): string | undefined {
  return r.json?.tppMessages?.[0]?.code ?? r.json?.code;
}

/** Expected HTTP status and one of the allowed message codes (Berlin Group IG §14.11). */
export function is(status: number, ...codes: string[]) {
  return (r: HttpResponse) => r.status === status && (!codes.length || codes.includes(errCode(r) ?? ''));
}

/** HTTP status per message code, Berlin Group IG 1.3.x §14.11 (header/query context). */
export const CODE_STATUS: Record<string, number[]> = {
  CERTIFICATE_INVALID: [401], CERTIFICATE_EXPIRED: [401], CERTIFICATE_BLOCKED: [401], CERTIFICATE_REVOKED: [401], CERTIFICATE_MISSING: [401],
  SIGNATURE_INVALID: [401], SIGNATURE_MISSING: [401], ROLE_INVALID: [401], FORMAT_ERROR: [400], PARAMETER_NOT_CONSISTENT: [400],
  PARAMETER_NOT_SUPPORTED: [400], PSU_CREDENTIALS_INVALID: [401], SERVICE_INVALID: [400, 405], SERVICE_BLOCKED: [403],
  CORPORATE_ID_INVALID: [401], CONSENT_UNKNOWN: [400, 403], CONSENT_INVALID: [401], CONSENT_EXPIRED: [401],
  TOKEN_UNKNOWN: [401], TOKEN_INVALID: [401], TOKEN_EXPIRED: [401], RESOURCE_UNKNOWN: [400, 403, 404], RESOURCE_EXPIRED: [400, 403],
  RESOURCE_BLOCKED: [400], TIMESTAMP_INVALID: [400], PERIOD_INVALID: [400], SCA_METHOD_UNKNOWN: [400], SCA_INVALID: [400],
  STATUS_INVALID: [409], SESSIONS_NOT_SUPPORTED: [400], ACCESS_EXCEEDED: [429], REQUESTED_FORMATS_INVALID: [406],
  // PIS codes (BG IG §14.11).
  PRODUCT_INVALID: [403], PRODUCT_UNKNOWN: [404], PAYMENT_FAILED: [400], EXECUTION_DATE_INVALID: [400], CANCELLATION_INVALID: [405],
};

export type ErrorShape = 'tpp' | 'rfc7807' | 'case' | 'none';

/**
 * Error body variant. Two are allowed (BG IG §4.13.3): tppMessages with category ERROR/WARNING + code (§14.2),
 * or RFC 7807 with a message code (§14.12). "case" = the right members with the wrong letter case
 * (e.g. TppMessages/Code): JSON member names are case-sensitive, so standard clients do not find them.
 */
export function errorShape(j: any): { shape: ErrorShape; code?: string } {
  if (!j || typeof j !== 'object') return { shape: 'none' };
  if (Array.isArray(j.tppMessages) && j.tppMessages.length > 0 && j.tppMessages.every((m: any) => ['ERROR', 'WARNING'].includes(m?.category) && m?.code))
    return { shape: 'tpp', code: j.tppMessages[0].code };
  if (typeof j.code === 'string' && (j.title !== undefined || j.type !== undefined)) return { shape: 'rfc7807', code: j.code };
  // Case-insensitive lookup to name the deviation precisely.
  const ci = (o: any, k: string) => (o && typeof o === 'object' ? o[Object.keys(o).find((x) => x.toLowerCase() === k.toLowerCase()) ?? ''] : undefined);
  const msgs = ci(j, 'tppMessages');
  const looseCode = Array.isArray(msgs) ? ci(msgs[0], 'code') : ci(j, 'code');
  if (typeof looseCode === 'string') return { shape: 'case', code: looseCode };
  return { shape: 'none' };
}

/** Shared by the live journey and the passive probes, so both judge error bodies by the same rule. */
export function checkErrorBodies(ctx: AuditContext, errors: { status: number; bodySnippet: string; responseHeaders: Record<string, string> }[], what: string) {
  if (!errors.length) return;
  // Two variants are allowed (BG IG §4.13.3): tppMessages with category ERROR/WARNING + code (§14.2),
  // or RFC 7807 with a message code (§14.12). Either way the message code is mandatory.
  const parsed = errors.map((x) => {
    let j: any;
    try {
      j = JSON.parse(x.bodySnippet);
    } catch {
      j = undefined;
    }
    return { x, ...errorShape(j) };
  });
  const none = parsed.filter((p) => p.shape === 'none');
  const cased = parsed.filter((p) => p.shape === 'case');
  if (none.length || cased.length) {
    const parts: string[] = [];
    if (none.length) parts.push(`${none.length} carry neither a tppMessages array (category ERROR/WARNING + code) nor an RFC 7807 body with a message code`);
    if (cased.length) parts.push(`${cased.length} use the right members with the wrong letter case (e.g. "TppMessages"/"Code" instead of "tppMessages"/"code"); JSON member names are case-sensitive, so standard clients find no message code`);
    ctx.add({ checkId: 'live.error-format', layer: 'conformance', status: 'fail', severity: 'medium', title: 'Error body structure', message: `Of ${errors.length} ${what}: ${parts.join('; ')}.`, actual: (cased[0] ?? none[0]).x.bodySnippet.slice(0, 200), fix: 'Return errors as { "tppMessages": [ { "category": "ERROR", "code": "...", "text": "..." } ] } (exact camelCase member names) or as RFC 7807 with "code".', reference: REF.BG });
  } else ctx.pass({ checkId: 'live.error-format', layer: 'conformance', title: 'Error body structure', message: `All ${errors.length} ${what} carry a standard message code.` });

  const problemJson = errors.filter((x) => (x.responseHeaders['content-type'] ?? '').includes('problem+json') || parsed.find((p) => p.x === x)?.shape === 'rfc7807');
  if (problemJson.length)
    ctx.add({ checkId: 'live.error-content-type', layer: 'conformance', status: 'info', severity: 'none', title: 'Error format variant', message: `${problemJson.length} ${what} use the RFC 7807 variant, which the Berlin Group guidelines allow. TPPs must support both variants for this bank.`, reference: REF.BG });

  // Message code must match the HTTP status (BG IG §14.11).
  // Codes in wrong-case members are still judged.
  const mismatched = parsed.filter(({ x, code }) => code && CODE_STATUS[code] && !CODE_STATUS[code].includes(x.status));
  if (mismatched.length)
    ctx.add({ checkId: 'live.error-code-status', layer: 'conformance', status: 'fail', severity: 'low', title: 'Message code matches HTTP status', message: `${mismatched.length} of ${errors.length} ${what} use a status the standard does not allow for their message code.`, actual: [...new Set(mismatched.map(({ x, code }) => `${code} with ${x.status} (allowed: ${CODE_STATUS[code!].join('/')})`))].join('; '), fix: 'Use the HTTP status defined for each message code in the Berlin Group code table.', reference: REF.BG });
  else if (parsed.some((p) => p.code && CODE_STATUS[p.code])) ctx.pass({ checkId: 'live.error-code-status', layer: 'conformance', title: 'Message code matches HTTP status', message: 'Every message code came with its standard HTTP status.' });
}

/** 4xx answers of XS2A calls: on the XS2A base URL, OAuth and SCA (login page) calls left out. */
export function xs2aErrors<T extends { status: number; url: string; operation: string }>(exchanges: T[], baseUrl: string): T[] {
  const base = baseUrl.replace(/\/$/, '');
  return exchanges.filter((x) => x.status >= 400 && x.status < 500 && x.url.startsWith(base) && !/(^|\.)(oauth|sca)(\.|-|$)|(^|\.)token$/.test(x.operation));
}

/**
 * Whether a consent's access covers balances / transactions of one account: listed by IBAN or resourceId in the
 * access array, or account-wide through allPsd2 (and availableAccountsWithBalance for balances).
 * An empty array is a bank-offered consent (BG IG: the PSU picks the accounts at the bank) that still lists none,
 * so it is taken to cover the accounts the consent returns.
 */
export function grantsFor(access: any, k: 'balances' | 'transactions', acc: { iban?: string; resourceId?: string }): boolean {
  if (!access || typeof access !== 'object') return false;
  if (access.allPsd2 !== undefined || (k === 'balances' && access.availableAccountsWithBalance !== undefined)) return true;
  const list = access[k];
  if (!Array.isArray(list)) return list !== undefined;
  if (!list.length) return true;
  return list.some((r: any) => (!!r?.iban && r.iban === acc.iban) || (!!r?.resourceId && r.resourceId === acc.resourceId));
}

/** Layer 1 (standard compatibility), live part: responses vs the bank's own spec and vs the standard's rules. */
export async function runLiveConformance(ctx: AuditContext) {
  checkSchemaResults(ctx);

  checkRequestIdEcho(ctx);

  // 3. Consent creation response shape.
  const c: HttpResponse | undefined = ctx.state.consentResponse;
  if (c?.status === 201) {
    const problems: string[] = [];
    if (!c.headers['location']) problems.push('missing Location header');
    if (c.json?.consentStatus !== 'received') problems.push(`consentStatus is "${c.json?.consentStatus}", expected "received"`);
    if (!c.headers['aspsp-sca-approach']) problems.push('missing ASPSP-SCA-Approach header');
    // OAuth2 SCA is signalled as REDIRECT plus an scaOAuth link, so either link is acceptable here.
    if (!c.json?._links?.scaOAuth && !c.json?._links?.scaRedirect && !c.json?._links?.startAuthorisation) problems.push('no SCA link in _links');
    if (problems.length)
      ctx.add({ checkId: 'live.consent-created', layer: 'conformance', status: 'warn', severity: 'low', title: 'Consent creation response', endpoint: 'POST /v1/consents -> 201', message: problems.join('; '), fix: 'Return Location, ASPSP-SCA-Approach consistent with the links returned, consentStatus "received" and the SCA link for the chosen approach.', reference: REF.BG });
    else ctx.pass({ checkId: 'live.consent-created', layer: 'conformance', title: 'Consent creation response', endpoint: 'POST /v1/consents -> 201', message: 'Location, ASPSP-SCA-Approach, status and SCA links present.' });
  }

  if (!ctx.state.token) return;
  const firstAcc = ctx.state.accountReads?.[0]?.id;

  // 4. Negative tests. Each states what the standard expects and what the bank did.
  type Neg = { id: string; title: string; run: () => Promise<HttpResponse>; expect: (r: HttpResponse) => boolean; expected: string; severity: 'high' | 'medium' | 'low'; fix: string; layer?: 'conformance' | 'security' };
  const negs: Neg[] = [
    {
      id: 'neg.missing-request-id',
      title: 'Request without X-Request-ID is rejected',
      run: () => api(ctx, 'neg.missing-request-id', 'GET', '/v1/accounts', { headers: { 'X-Request-ID': '' }, validate: false }),
      expect: is(400, 'FORMAT_ERROR'),
      expected: '400 FORMAT_ERROR',
      severity: 'medium',
      fix: 'Treat X-Request-ID as mandatory: reject missing values with 400 FORMAT_ERROR and a tppMessages entry naming the header.',
    },
    {
      id: 'neg.invalid-request-id',
      title: 'Non-UUID X-Request-ID is rejected',
      run: () => api(ctx, 'neg.invalid-request-id', 'GET', '/v1/accounts', { headers: { 'X-Request-ID': 'not-a-uuid' }, validate: false }),
      expect: is(400, 'FORMAT_ERROR'),
      expected: '400 FORMAT_ERROR',
      severity: 'low',
      fix: 'Validate X-Request-ID as a UUID and return 400 FORMAT_ERROR otherwise (other Georgian ASPSPs already do).',
    },
    {
      id: 'neg.no-token',
      title: 'Request without access token is rejected',
      run: () => api(ctx, 'neg.no-token', 'GET', '/v1/accounts', { auth: false, validate: false }),
      expect: is(401, 'TOKEN_UNKNOWN', 'TOKEN_INVALID'),
      expected: '401 TOKEN_UNKNOWN / TOKEN_INVALID',
      severity: 'high',
      layer: 'security',
      fix: 'Require a valid access token on every AIS call and answer 401 when it is missing.',
    },
    {
      id: 'neg.bad-token',
      title: 'Invalid access token is rejected',
      run: () => api(ctx, 'neg.bad-token', 'GET', '/v1/accounts', { headers: { Authorization: 'Bearer invalid-token' }, validate: false }),
      expect: is(401, 'TOKEN_UNKNOWN', 'TOKEN_INVALID'),
      expected: '401 TOKEN_UNKNOWN / TOKEN_INVALID',
      severity: 'high',
      layer: 'security',
      fix: 'Reject unknown or expired tokens with 401 TOKEN_UNKNOWN or TOKEN_INVALID.',
    },
    {
      id: 'neg.missing-consent-id',
      title: 'Missing Consent-ID header is rejected as a format error',
      run: () => api(ctx, 'neg.missing-consent-id', 'GET', '/v1/accounts', { consent: false, validate: false }),
      expect: is(400, 'FORMAT_ERROR'),
      expected: '400 FORMAT_ERROR (mandatory header missing)',
      severity: 'low',
      fix: 'A missing mandatory header is a format error: return 400 FORMAT_ERROR naming Consent-ID, not a "consent unknown" error.',
    },
    {
      id: 'neg.unknown-consent',
      title: 'Unknown Consent-ID is rejected',
      run: () => api(ctx, 'neg.unknown-consent', 'GET', '/v1/accounts', { headers: { 'Consent-ID': '00000000-0000-4000-8000-000000000000' }, validate: false }),
      // BG IG §14.11 allows 400 and 403 for CONSENT_UNKNOWN.
      expect: (r) => [400, 403].includes(r.status) && errCode(r) === 'CONSENT_UNKNOWN',
      expected: '400 or 403 CONSENT_UNKNOWN',
      severity: 'medium',
      layer: 'security',
      fix: 'Bind the token to its consent and reject any other Consent-ID with CONSENT_UNKNOWN (400, or 403).',
    },
    {
      id: 'neg.unknown-account',
      title: 'Unknown account id is rejected',
      run: () => api(ctx, 'neg.unknown-account', 'GET', '/v1/accounts/does-not-exist', { validate: false }),
      expect: is(404, 'RESOURCE_UNKNOWN'),
      expected: '404 RESOURCE_UNKNOWN (account-id in path)',
      severity: 'low',
      fix: 'Return 404 RESOURCE_UNKNOWN for account ids that are unknown or outside the consent.',
    },
    {
      id: 'neg.bad-consent-body',
      title: 'Malformed consent request is rejected',
      run: () => api(ctx, 'neg.bad-consent-body', 'POST', '/v1/consents', { auth: false, consent: false, json: { recurringIndicator: 'yes' }, validate: false }),
      expect: is(400, 'FORMAT_ERROR'),
      expected: '400 FORMAT_ERROR',
      severity: 'low',
      fix: 'Validate consent bodies against the schema and return 400 FORMAT_ERROR.',
    },
  ];
  if (firstAcc) {
    const { from, to } = ctx.state.txWindow ?? {};
    negs.push({
      id: 'neg.reversed-period',
      title: 'dateTo earlier than dateFrom is rejected',
      run: () => api(ctx, 'neg.reversed-period', 'GET', `/v1/accounts/${encodeURIComponent(firstAcc)}/transactions?bookingStatus=booked&dateFrom=${to}&dateTo=${from}`, { validate: false }),
      expect: is(400, 'PERIOD_INVALID', 'FORMAT_ERROR'),
      expected: '400 PERIOD_INVALID or FORMAT_ERROR',
      severity: 'low',
      fix: 'Reject inverted date ranges with 400 PERIOD_INVALID instead of returning an empty or unfiltered list.',
    });
    negs.push({
      id: 'neg.bad-date',
      title: 'Invalid dateFrom is rejected',
      run: () => api(ctx, 'neg.bad-date', 'GET', `/v1/accounts/${encodeURIComponent(firstAcc)}/transactions?bookingStatus=booked&dateFrom=2026-13-45`, { validate: false }),
      expect: (r) => r.status === 400,
      expected: '400 FORMAT_ERROR',
      severity: 'low',
      fix: 'Validate ISO 8601 date query parameters and return 400 FORMAT_ERROR.',
    });
  }

  for (const n of negs) {
    let r = await n.run();
    // api() already retried once; a persisting 5xx/timeout means the test could not run, not that it passed or failed.
    if (r.status === 0 || r.status >= 500) {
      await new Promise((res) => setTimeout(res, 1000));
      r = await n.run();
    }
    if (r.status === 0 || r.status >= 500) {
      ctx.add({ checkId: n.id, layer: n.layer ?? 'conformance', status: 'skip', severity: 'none', title: n.title, message: `Could not be tested: service unavailable (${ctx.short(r)}). Rerun the audit.`, expected: n.expected, actual: ctx.short(r) });
      continue;
    }
    const ok = n.expect(r);
    // Rejected, but with a different status/code than the standard: an interoperability issue, not a hole.
    const rejectedOtherwise = !ok && r.status >= 400 && r.status < 500;
    ctx.add({
      checkId: n.id,
      layer: rejectedOtherwise ? 'conformance' : n.layer ?? 'conformance',
      status: ok ? 'pass' : rejectedOtherwise ? 'warn' : 'fail',
      severity: ok ? 'none' : rejectedOtherwise ? 'low' : n.severity,
      title: n.title,
      message: ok
        ? `Rejected as expected (${ctx.short(r)}).`
        : rejectedOtherwise
          ? `Rejected, but with ${ctx.short(r)} instead of ${n.expected}. TPPs that branch on status codes will mis-handle it.`
          : `Not rejected: the request was served (${ctx.short(r)}).`,
      expected: n.expected,
      actual: ctx.short(r),
      fix: ok ? undefined : n.fix,
      reference: REF.BG,
    });
  }

  // 5. Error body structure across every 4xx we collected (XS2A calls only; OAuth and login pages follow other rules).
  const errors = xs2aErrors(ctx.http.exchanges, ctx.target.baseUrl);
  checkErrorBodies(ctx, errors, 'error responses');

  // 5b. Georgian rules on account data (GE XS2A IG §9.3.3, §9.3.4, §9.3.6).
  const access = ctx.state.consentDetails?.json?.access ?? {};
  const grants = (k: 'balances' | 'transactions', acc: { iban?: string; resourceId?: string }) => grantsFor(access, k, acc);
  const accs: any[] = ctx.state.accounts?.json?.accounts ?? [];
  const covered = accs.filter((a) => grants('balances', a));
  if (covered.length) {
    const missing = covered.filter((a) => !Array.isArray(a.balances) || !a.balances.length);
    ctx.add({
      checkId: 'live.with-balance',
      layer: 'conformance',
      status: missing.length ? 'fail' : 'pass',
      severity: missing.length ? 'medium' : 'none',
      title: 'withBalance=true returns balances',
      endpoint: 'GET /v1/accounts?withBalance=true',
      message: missing.length ? `${missing.length} of ${covered.length} accounts came back without balances although the consent covers their balances.` : `All ${covered.length} accounts with a balances consent include balances.`,
      expected: 'balances present for every account covered by a balances consent',
      actual: missing.length ? `no balances on ${missing.map((a) => a.resourceId).join(', ')}` : undefined,
      fix: missing.length ? 'When withBalance=true and the consent covers balances, include the balances array for each account.' : undefined,
      reference: REF.GE,
    });
    const plain = await api(ctx, 'live.without-balance', 'GET', '/v1/accounts');
    const leaked = (plain.json?.accounts ?? []).filter((a: any) => a.balances !== undefined);
    if (plain.status === 200 && leaked.length)
      ctx.add({ checkId: 'live.without-balance', layer: 'conformance', status: 'fail', severity: 'low', title: 'Balances only when withBalance=true', endpoint: 'GET /v1/accounts', message: `${leaked.length} accounts include balances although withBalance was not requested.`, fix: 'Return balances in the account list only when withBalance=true.', reference: REF.GE });
  }

  for (const read of ctx.state.accountReads ?? []) {
    const links = read.details?.json?.account?._links ?? {};
    if (read.details?.status !== 200) continue;
    const acc = { resourceId: read.id, iban: read.details?.json?.account?.iban ?? accs.find((a) => a.resourceId === read.id)?.iban };
    const need = [grants('balances', acc) && 'balances', grants('transactions', acc) && 'transactions'].filter(Boolean) as string[];
    const missing = need.filter((k) => !links[k]);
    ctx.add({
      checkId: 'live.account-links',
      layer: 'conformance',
      status: missing.length ? 'fail' : 'pass',
      severity: missing.length ? 'low' : 'none',
      title: 'Account details link to consented resources',
      endpoint: `GET /v1/accounts/${read.id}`,
      message: missing.length ? `_links lacks ${missing.join(' and ')} although the consent covers them. TPPs that follow links cannot navigate to the data.` : `_links contains ${need.join(' and ') || 'the account link'}.`,
      expected: `_links.${need.join(', _links.')}`,
      actual: `_links: ${Object.keys(links).join(', ') || 'none'}`,
      fix: missing.length ? 'Return balances and transactions hyperlinks whenever the consent covers them (and never when it does not).' : undefined,
      reference: REF.GE,
    });
  }

  if (firstAcc) {
    const { from } = ctx.state.txWindow ?? {};
    // Judged only when bookingStatus=booked worked on the same account: otherwise a refusal says nothing about the parameter.
    const booked: HttpResponse | undefined = ctx.state.accountReads?.[0]?.tx;
    for (const bs of ['pending', 'both']) {
      if (booked?.status !== 200) {
        ctx.add({ checkId: 'live.booking-status', layer: 'conformance', status: 'skip', severity: 'none', title: `bookingStatus=${bs} supported`, endpoint: `GET /v1/accounts/{id}/transactions?bookingStatus=${bs}`, message: `Could not be tested: bookingStatus=booked on the same account did not return 200 (${booked ? ctx.short(booked) : 'not read'}).`, reference: REF.GE });
        continue;
      }
      const r = await api(ctx, `live.booking-status.${bs}`, 'GET', `/v1/accounts/${encodeURIComponent(firstAcc)}/transactions?bookingStatus=${bs}&dateFrom=${from}`);
      const ok = r.status === 200;
      ctx.add({ checkId: 'live.booking-status', layer: 'conformance', status: ok ? 'pass' : 'fail', severity: ok ? 'none' : 'medium', title: `bookingStatus=${bs} supported`, endpoint: `GET /v1/accounts/{id}/transactions?bookingStatus=${bs}`, message: ok ? 'Supported.' : `Not supported (${ctx.short(r)}).`, expected: '200', actual: ctx.short(r), fix: ok ? undefined : 'Support booked, pending and both; only "information" is optional in Georgia.', reference: REF.GE });
    }
  }

  checkResponseSeals(ctx);

  // 6. Consent deletion revokes access. Uses a separate one-off consent so the main (recurring) one stays usable (GE-XS2A §9.1.1.3, §9.1.1.4).
  const tmp = await createConsent(ctx, 'neg.consent-delete.create', true);
  if (tmp.status === 201 && tmp.json?.consentId) {
    const del = await api(ctx, 'consent.delete', 'DELETE', `/v1/consents/${tmp.json.consentId}`, { auth: false, consent: false });
    const status = await api(ctx, 'consent.status.after-delete', 'GET', `/v1/consents/${tmp.json.consentId}/status`, { auth: false, consent: false, validate: false });
    const ok = del.status === 204 && status.json?.consentStatus === 'terminatedByTpp';
    ctx.add({ checkId: 'live.consent-delete', layer: 'conformance', status: ok ? 'pass' : 'warn', severity: ok ? 'none' : 'low', title: 'Consent deletion', endpoint: 'DELETE /v1/consents/{consentId}', message: ok ? 'Deleted with 204; status became terminatedByTpp.' : `DELETE returned ${ctx.short(del)}; status afterwards "${status.json?.consentStatus ?? ctx.short(status)}".`, expected: '204, then consentStatus terminatedByTpp', fix: ok ? undefined : 'Return 204 on deletion and report consentStatus "terminatedByTpp" afterwards.', reference: REF.BG });
  }
}


/** Structural checks of a detached JWS protected header (GE-JWS §6). The signature itself needs the bank's QSealC chain. */
export function jwsHeaderProblems(value: string, receivedAt?: Date): string[] {
  const parts = value.split('.');
  if (parts.length !== 3) return ['not a JWS compact serialization'];
  if (parts[1] !== '') return ['payload not detached'];
  let h: any;
  try {
    h = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
  } catch {
    return ['protected header is not Base64url JSON'];
  }
  return jwsProtectedHeaderProblems(h, receivedAt);
}

/** GE-JWS 0.5.RC1 §5, §5.1, §6, §8.1 rules on the protected header. receivedAt enables the sigT clock window. */
export function jwsProtectedHeaderProblems(h: any, receivedAt?: Date): string[] {
  const out: string[] = [];
  if (h.b64 !== false) out.push('b64 is not false');
  // sigT: mandatory, UTC, no fractional seconds (e.g. 2019-11-19T17:28:15Z).
  if (!h.sigT) out.push('sigT missing');
  else if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(String(h.sigT))) out.push(`sigT "${h.sigT}" is not UTC without fractional seconds`);
  else if (receivedAt) {
    // §5: reject when sigT is more than 2 s ahead of the receiver's clock, or more than 60 s behind it.
    const skew = (Date.parse(h.sigT) - receivedAt.getTime()) / 1000;
    if (skew > 2) out.push(`sigT is ${Math.round(skew)} s in the future (max 2 s)`);
    else if (skew < -60) out.push(`sigT is ${Math.round(-skew)} s old (max 60 s)`);
  }
  if (!h.sigD) out.push('sigD missing');
  else {
    if (h.sigD.mId !== 'http://uri.etsi.org/19182/HttpHeaders') out.push(`sigD.mId is "${h.sigD.mId ?? 'missing'}", must be http://uri.etsi.org/19182/HttpHeaders`);
    if (!Array.isArray(h.sigD.pars) || !h.sigD.pars.length) out.push('sigD.pars missing or empty');
    else if (!h.sigD.pars.map((p: string) => String(p).toLowerCase()).includes('digest')) out.push('digest not covered by sigD.pars');
  }
  // §6, §8.1: x5c is mandatory and holds exactly the signing certificate; x5t#S256 only by bilateral agreement, then with kid.
  if (h.x5c !== undefined && h['x5t#S256'] !== undefined) out.push('x5c and x5t#S256 used together (forbidden)');
  if (h.x5c === undefined && h['x5t#S256'] === undefined && h.x5u === undefined) out.push('no certificate reference (x5c mandatory)');
  else if (h.x5c === undefined) out.push('x5c missing (allowed only by bilateral agreement)');
  if (Array.isArray(h.x5c) && h.x5c.length > 1) out.push(`x5c holds ${h.x5c.length} certificates (must hold only the signing certificate)`);
  if (h['x5t#S256'] !== undefined && h.kid === undefined) out.push('x5t#S256 without kid');
  for (const k of ['x5t', 'jwk', 'cty']) if (h[k] !== undefined) out.push(`"${k}" must not be used`);
  if (h.typ !== undefined && h.typ !== 'JOSE') out.push(`typ "${h.typ}" (not recommended; if used, must be JOSE)`);
  // GE-JWS §5.1: "none" is never allowed; a QSealC seal needs an asymmetric algorithm (RS/PS/ES).
  // The mandatory set is RS/PS/ES with 256 or 512.
  if (!h.alg || !/^(RS|PS|ES)(256|512)$/.test(h.alg)) out.push(`algorithm "${h.alg ?? 'missing'}" not allowed`);
  const crit: string[] = Array.isArray(h.crit) ? h.crit : [];
  for (const k of ['sigT', 'sigD', 'b64']) if (h[k] !== undefined && !crit.includes(k)) out.push(`${k} not listed in crit`);
  return out;
}

/** Digest value of a body for the algorithm a header names (GE-JWS §5.1: SHA-256 and SHA-512 must be supported). */
export function digestMatches(digestHeader: string, body: Buffer | { sha256?: string; sha512?: string }): { alg?: string; ok: boolean; computed?: string } {
  const m = /(SHA-256|SHA-512)=([A-Za-z0-9+/=]+)/i.exec(digestHeader);
  if (!m) return { ok: false };
  const alg = m[1].toUpperCase();
  const want = Buffer.isBuffer(body) ? createHash(alg === 'SHA-512' ? 'sha512' : 'sha256').update(body).digest('base64') : alg === 'SHA-512' ? body.sha512 : body.sha256;
  return { alg, ok: !!want && m[2] === want, computed: want ? `${alg}=${want}` : undefined };
}

/**
 * Cryptographic check of a detached JWS over HTTP headers with the key in x5c[0].
 * Trust in the certificate chain is a separate question (needs the bank's QSealC CA); the signature itself only needs the key.
 */
export function verifyDetachedJws(value: string, method: string, url: string, headers: Record<string, string>): { verified?: boolean; reason?: string } {
  const [hb64, payload, sigb64] = value.split('.');
  if (payload !== '' || !sigb64) return { reason: 'not a detached JWS' };
  let h: any;
  try {
    h = JSON.parse(Buffer.from(hb64, 'base64url').toString('utf8'));
  } catch {
    return { reason: 'header not JSON' };
  }
  if (!Array.isArray(h.x5c) || !h.x5c[0]) return { reason: 'no x5c certificate to verify with' };
  const pars: string[] = h.sigD?.pars ?? [];
  const lower = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]));
  const pseudo = pars.filter((p) => p.startsWith('(') && p.toLowerCase() !== '(request-target)');
  if (pseudo.length) return { reason: `pseudo-header(s) ${pseudo.join(', ')} not defined by GE-JWS` };
  const missing = pars.filter((p) => !p.startsWith('(') && p.toLowerCase() !== 'host' && lower[p.toLowerCase()] === undefined);
  if (missing.length) return { reason: `signed header(s) not in the message: ${missing.join(', ')}` };
  const m = /^(RS|PS|ES)(256|512)$/.exec(h.alg ?? '');
  if (!m) return { reason: `algorithm ${h.alg} not supported` };
  try {
    const cert = new X509Certificate(Buffer.from(h.x5c[0], 'base64'));
    const input = Buffer.from(`${hb64}.${signingString(method, url, lower, pars.map((p) => p.toLowerCase()))}`);
    const sig = Buffer.from(sigb64, 'base64url');
    const hash = `sha${m[2]}`;
    const key: any = m[1] === 'PS' ? { key: cert.publicKey, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: Number(m[2]) / 8 } : m[1] === 'ES' ? { key: cert.publicKey, dsaEncoding: 'ieee-p1363' } : cert.publicKey;
    return { verified: cryptoVerify(hash, input, key, sig) };
  } catch (e: any) {
    return { reason: `could not verify: ${e?.message ?? e}` };
  }
}

/** 1. Responses match the documented schemas, aggregated per operation. Shared with the sandbox flow. */
export function checkSchemaResults(ctx: AuditContext) {
  const results: SchemaResult[] = ctx.state.schemaResults ?? [];
  const byOp = new Map<string, SchemaResult[]>();
  for (const r of results) byOp.set(`${r.operation} -> ${r.status}`, [...(byOp.get(`${r.operation} -> ${r.status}`) ?? []), r]);
  for (const [key, rs] of byOp) {
    const bad = rs.filter((r) => !r.valid && !r.skipped);
    if (bad.length) {
      ctx.add({
        checkId: 'live.schema',
        layer: 'conformance',
        status: 'fail',
        severity: 'medium',
        title: 'Response does not match the published schema',
        endpoint: key,
        message: `${bad.length} of ${rs.length} responses deviate from the bank's own OpenAPI document.`,
        actual: [...new Set(bad.flatMap((b) => b.errors ?? []))].slice(0, 6).join('; '),
        fix: 'Align the implementation with the published schema, or correct the schema if the implementation is right. Either way, TPP clients generated from the spec will break today.',
        reference: REF.GE,
      });
    } else if (rs.some((r) => r.skipped)) {
      ctx.add({ checkId: 'live.schema', layer: 'conformance', status: 'info', severity: 'none', title: 'Response schema not checkable', endpoint: key, message: rs[0].skipped ?? '' });
    } else {
      ctx.pass({ checkId: 'live.schema', layer: 'conformance', title: 'Response matches published schema', endpoint: key, message: `${rs.length} response(s) validated.` });
    }
  }
}

/** 2. X-Request-ID echoed back. */
export function checkRequestIdEcho(ctx: AuditContext) {
  const xs2aBase = ctx.target.baseUrl.replace(/\/$/, '');
  // Our deliberately malformed X-Request-ID tests (neg.*-request-id) are left out.
  const sent = ctx.http.exchanges.filter((x) => x.requestHeaders['X-Request-ID'] && x.status > 0 && x.status < 500 && x.url.startsWith(xs2aBase) && !/^neg\..*request-id$/.test(x.operation));
  const notEchoed = sent.filter((x) => x.responseHeaders['x-request-id'] !== x.requestHeaders['X-Request-ID']);
  if (notEchoed.length) {
    ctx.add({ checkId: 'live.x-request-id-echo', layer: 'conformance', status: 'fail', severity: 'low', title: 'X-Request-ID not echoed', message: `${notEchoed.length} of ${sent.length} responses did not return the request's X-Request-ID.`, fix: 'Return the X-Request-ID received in every response header.', reference: REF.BG, evidence: notEchoed.slice(0, 5).map((x) => `${x.method} ${x.url}`) });
  } else if (sent.length) {
    ctx.pass({ checkId: 'live.x-request-id-echo', layer: 'conformance', title: 'X-Request-ID echoed', message: `All ${sent.length} responses returned the X-Request-ID that was sent.` });
  }
}

/** 5c. Responses must carry the bank's JWS seal (GE XS2A IG §5.4, §7.4; GE JWS guide §5, §7). */
export function checkResponseSeals(ctx: AuditContext) {
  const base = ctx.target.baseUrl.replace(/\/$/, '');
  // Bank login pages (sca.*) are HTML for the PSU, not XS2A responses.
  const okResponses = ctx.http.exchanges.filter((x) => x.url.startsWith(base) && x.status >= 200 && x.status < 300 && !x.operation.startsWith('sca.'));
  if (okResponses.length) {
    const unsigned = okResponses.filter((x) => !x.responseHeaders['x-jws-signature'] || !x.responseHeaders['digest']);
    ctx.add({
      checkId: 'sec.response-signed',
      layer: 'security',
      status: unsigned.length ? 'fail' : 'pass',
      severity: unsigned.length ? 'medium' : 'none',
      title: 'Responses carry the bank\'s JWS seal',
      message: unsigned.length ? `${unsigned.length} of ${okResponses.length} successful responses have no x-jws-signature and Digest headers, so a TPP cannot prove what the bank returned.` : `All ${okResponses.length} successful responses are sealed.`,
      expected: 'x-jws-signature + Digest on every response',
      actual: unsigned.length ? 'headers missing' : undefined,
      fix: unsigned.length ? 'Seal every response with the bank\'s QSealC per the Georgian JWS guide (x-jws-signature, Digest, sigT).' : undefined,
      reference: REF.GE,
    });

    // Presence is not enough: the Digest must be the body's hash, and the JWS header must carry the mandatory fields.
    const withDigest = okResponses.filter((x) => x.responseHeaders['digest'] && x.bodySha256);
    if (withDigest.length) {
      // SHA-256 and SHA-512 are both allowed (GE-JWS §5.1).
      const checked = withDigest.map((x) => ({ x, ...digestMatches(x.responseHeaders['digest'], { sha256: x.bodySha256, sha512: x.bodySha512 }) }));
      const wrong = checked.filter((c) => !c.ok);
      const algs = [...new Set(checked.map((c) => c.alg).filter(Boolean))].join(', ') || 'unsupported algorithm';
      ctx.add({ checkId: 'sec.digest-valid', layer: 'security', status: wrong.length ? 'fail' : 'pass', severity: wrong.length ? 'high' : 'none', title: 'Digest matches the response body', message: wrong.length ? `${wrong.length} of ${withDigest.length} Digest headers do not equal the hash of the body (or use an algorithm other than SHA-256/SHA-512). The seal then proves nothing about the data.` : `All ${withDigest.length} Digest headers equal the ${algs} hash of the body.`, expected: 'Digest: SHA-256=<base64> or SHA-512=<base64> of the exact body bytes', actual: wrong.length ? `${wrong[0].x.responseHeaders['digest']} vs computed ${wrong[0].computed ?? `SHA-256=${wrong[0].x.bodySha256}`}` : undefined, fix: wrong.length ? 'Compute Digest over the exact bytes sent, after any encoding, and sign it in the JWS (sigD).' : undefined, reference: REF.GE, evidence: wrong.slice(0, 5).map((c) => `${c.x.method} ${c.x.url}`) });
    }
    const withJws = okResponses.filter((x) => x.responseHeaders['x-jws-signature']);
    if (withJws.length) {
      // Signature value: verified with the key in x5c[0]. Trust in the bank's QSealC chain is a separate question.
      const results = withJws.map((x) => ({ x, ...verifyDetachedJws(x.responseHeaders['x-jws-signature'], x.method, x.url, x.responseHeaders) }));
      const bad = results.filter((r) => r.verified === false);
      const good = results.filter((r) => r.verified === true);
      const unverifiable = results.filter((r) => r.verified === undefined);
      // None verifying at all can also mean a different signing-string convention for responses: warn then, fail only when
      // the same bank's signatures verify on some responses and not on others.
      const allBad = bad.length > 0 && good.length === 0;
      if (bad.length || good.length)
        ctx.add({ checkId: 'sec.response-signature-valid', layer: 'security', status: !bad.length ? 'pass' : allBad ? 'warn' : 'fail', severity: !bad.length ? 'none' : allBad ? 'medium' : 'high', title: 'Response signature verifies', message: bad.length ? `${bad.length} of ${bad.length + good.length} response signatures do not verify with the certificate in their own x5c.${allBad ? ' None verified, so the bank may build the response signing string differently from GE-JWS §9.5; the call log has the headers to compare.' : ' Others from the same bank do, so these responses are signed over different data. A TPP cannot rely on them.'}` : `All ${good.length} response signatures verify with the certificate in x5c (chain trust not judged).${unverifiable.length ? ` ${unverifiable.length} could not be checked (${unverifiable[0].reason}).` : ''}`, expected: 'JWS over the sigD.pars headers verifies with x5c[0] (GE-JWS §10)', fix: bad.length ? 'Sign exactly the headers listed in sigD.pars, in that order, with the key of the certificate placed in x5c.' : undefined, reference: REF.GE, evidence: bad.slice(0, 5).map((r) => `${r.x.method} ${r.x.url}`) });
      else
        ctx.add({ checkId: 'sec.response-signature-valid', layer: 'security', status: 'info', severity: 'none', title: 'Response signature verifies', message: `${unverifiable.length} response signatures could not be checked: ${unverifiable[0].reason}.`, reference: REF.GE });
      const problems = new Map<string, number>();
      for (const x of withJws) for (const p of jwsHeaderProblems(x.responseHeaders['x-jws-signature'], new Date(x.ts))) problems.set(p.replace(/\d+ s/, 'N s'), (problems.get(p.replace(/\d+ s/, 'N s')) ?? 0) + 1);
      ctx.add({ checkId: 'sec.jws-header', layer: 'security', status: problems.size ? 'fail' : 'pass', severity: problems.size ? 'medium' : 'none', title: 'JWS protected header complete', message: problems.size ? `Problems across ${withJws.length} signatures: ${[...problems].map(([p, n]) => `${p} (${n})`).join('; ')}.` : `All ${withJws.length} signatures follow the GE-JWS header profile (b64=false, sigT in UTC within the clock window, sigD with the ETSI HttpHeaders mId and digest, x5c with the signing certificate only, allowed algorithm, crit).`, expected: 'detached JWS: b64=false; sigT UTC, no fractions, -60 s..+2 s; sigD.mId http://uri.etsi.org/19182/HttpHeaders with digest in pars; x5c = [signing certificate] (x5t#S256 + kid only by agreement, never both); no x5t/jwk/cty; RS/PS/ES 256/512; crit = sigT, sigD, b64', fix: problems.size ? 'Build the protected header as the Georgian JWS profile requires (§5, §6, §8.1) and send it detached (§9.8). Keep the server clock on UTC (NTP).' : undefined, reference: REF.GE });
    }
  }
}
