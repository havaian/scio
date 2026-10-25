import { test } from 'node:test';
import assert from 'node:assert/strict';
import { api } from '../src/flows/full.flow';
import { failedLanding, journeyStats, nokRedirectUri } from '../src/flows/sandbox.flow';
import { grantsFor, xs2aErrors } from '../src/checks/live-conformance.checks';
import { consentScopeRefusal } from '../src/checks/loans.checks';
import { AuditContext } from '../src/checks/context';
import { HttpRecorder, HttpRequest, HttpResponse } from '../src/common/http';
import { Exchange, Thresholds } from '../src/common/types';

const res = (status: number, json?: any): HttpResponse => ({ status, ok: status > 0 && status < 400, headers: {}, text: json ? JSON.stringify(json) : '', json, durationMs: 1, requestHeaders: {} });

/** Context whose HTTP layer answers from a list and records the requests (no network). */
function stubCtx(answers: number[]) {
  const ctx = new AuditContext({ id: 't', name: 't', bank: 't', mode: 'full', simulated: true, baseUrl: 'https://bank.example/xs2a' }, new HttpRecorder('t', 1000), {} as Thresholds);
  const sent: HttpRequest[] = [];
  (ctx.http as any).request = async (req: HttpRequest) => {
    sent.push(req);
    return res(answers[Math.min(sent.length - 1, answers.length - 1)]);
  };
  return { ctx, sent };
}

test('api: a retried POST keeps its X-Request-ID (same request, GE-XS2A §7.7); a retried GET gets a new one', async () => {
  const post = stubCtx([503, 201]);
  const r = await api(post.ctx, 'consent.create', 'POST', '/v1/consents', { json: {} });
  assert.equal(r.status, 201);
  assert.equal(post.sent.length, 2);
  assert.equal(post.sent[0].headers!['X-Request-ID'], post.sent[1].headers!['X-Request-ID']);

  const get = stubCtx([0, 200]);
  await api(get.ctx, 'ais.accounts', 'GET', '/v1/accounts');
  assert.equal(get.sent.length, 2);
  assert.notEqual(get.sent[0].headers!['X-Request-ID'], get.sent[1].headers!['X-Request-ID']);
});

test('api: retries: 0 sends the request once', async () => {
  const s = stubCtx([503, 201]);
  const r = await api(s.ctx, 'pis.create', 'POST', '/v1/payments/x', { json: {}, retries: 0 });
  assert.equal(r.status, 503);
  assert.equal(s.sent.length, 1);
});

test('grantsFor: balances/transactions arrays are matched per account; allPsd2 and availableAccountsWithBalance are account-wide', () => {
  const access = { accounts: [{ iban: 'GE1' }, { iban: 'GE2' }], balances: [{ iban: 'GE1' }], transactions: [{ resourceId: 'r2' }] };
  assert.equal(grantsFor(access, 'balances', { iban: 'GE1', resourceId: 'r1' }), true);
  assert.equal(grantsFor(access, 'balances', { iban: 'GE2', resourceId: 'r2' }), false);
  assert.equal(grantsFor(access, 'transactions', { iban: 'GE2', resourceId: 'r2' }), true);
  assert.equal(grantsFor(access, 'transactions', { iban: 'GE1', resourceId: 'r1' }), false);
  assert.equal(grantsFor({ balances: [] }, 'balances', { iban: 'GE1' }), true); // bank-offered consent, accounts not listed
  assert.equal(grantsFor({ accounts: [{ iban: 'GE1' }] }, 'balances', { iban: 'GE1' }), false);
  assert.equal(grantsFor({ allPsd2: 'allAccounts' }, 'transactions', { iban: 'GE9' }), true);
  assert.equal(grantsFor({ availableAccountsWithBalance: 'allAccounts' }, 'balances', { iban: 'GE9' }), true);
  assert.equal(grantsFor({ availableAccountsWithBalance: 'allAccounts' }, 'transactions', { iban: 'GE9' }), false);
  assert.equal(grantsFor(undefined, 'balances', { iban: 'GE1' }), false);
});

test('xs2aErrors: only 4xx on the XS2A base URL, OAuth and SCA calls left out', () => {
  const x = (operation: string, url: string, status = 400) => ({ operation, url, status });
  const base = 'https://bank.example/xs2a/';
  const kept = xs2aErrors(
    [
      x('neg.no-token', 'https://bank.example/xs2a/v1/accounts', 401),
      x('ais.accounts', 'https://bank.example/xs2a/v1/accounts', 200),
      x('ais.balances', 'https://bank.example/xs2a/v1/accounts/1/balances', 503),
      x('oauth.token', 'https://bank.example/xs2a/oauth/token'),
      x('pis.oauth.token', 'https://bank.example/xs2a/oauth/token'),
      x('v2.oauth.token', 'https://bank.example/xs2a/oauth/token'),
      x('pis.cancel.oauth.token', 'https://bank.example/xs2a/oauth/token'),
      x('sandbox.token', 'https://bank.example/xs2a/token'),
      x('sca.approve', 'https://bank.example/xs2a/sca/page'),
      x('sandbox.oauth-metadata', 'https://bank.example/xs2a/.well-known'),
      x('neg.bad-date', 'https://other.example/v1/accounts'),
      x('pis.neg.no-token', 'https://bank.example/xs2a/v1/payments/x/1/status', 401),
    ],
    base,
  );
  assert.deepEqual(kept.map((k) => k.operation), ['neg.no-token', 'pis.neg.no-token']);
});

test('consentScopeRefusal: 403 or a CONSENT_* code passes; a bare 401 or 404 does not', () => {
  assert.equal(consentScopeRefusal(res(403)), true);
  assert.equal(consentScopeRefusal(res(401, { tppMessages: [{ category: 'ERROR', code: 'CONSENT_INVALID' }] })), true);
  assert.equal(consentScopeRefusal(res(400, { tppMessages: [{ category: 'ERROR', code: 'CONSENT_UNKNOWN' }] })), true);
  assert.equal(consentScopeRefusal(res(401, { tppMessages: [{ category: 'ERROR', code: 'TOKEN_INVALID' }] })), false);
  assert.equal(consentScopeRefusal(res(404, { tppMessages: [{ category: 'ERROR', code: 'RESOURCE_UNKNOWN' }] })), false);
});

test('Nok redirect: distinct URI with the redirect URI prefix; Nok or error landing is a failed login', () => {
  const ok = 'https://scio.uz/callback';
  const nok = nokRedirectUri(ok);
  assert.notEqual(nok, ok);
  assert.ok(nok.startsWith(ok));
  assert.equal(nokRedirectUri('https://x/cb?a=1'), 'https://x/cb?a=1&result=nok');
  assert.equal(failedLanding(`${nok}&state=1`, nok), true);
  assert.equal(failedLanding(`${ok}?error=access_denied`, nok), true);
  assert.equal(failedLanding(`${ok}?code=abc`, nok), false);
  assert.equal(failedLanding(ok, nok), false);
});

test('journeyStats: only .diag calls are left out; retried 5xx of the standard requests count', () => {
  const ctx = new AuditContext({ id: 't', name: 't', bank: 't', mode: 'full', simulated: false, baseUrl: 'https://x' }, new HttpRecorder('t', 1000), { availabilityPct: 99, errorRatePct: 1, latencyP95Ms: 1000, source: 'assumed' } as Thresholds);
  const x = (operation: string, status: number): Exchange => ({ targetId: 't', operation, method: 'GET', url: 'https://x/v1', status, ok: status > 0 && status < 500, durationMs: 100, requestHeaders: {}, responseHeaders: {}, bodySnippet: '', ts: '' });
  ctx.http.exchanges.push(x('sandbox.consent', 503), x('sandbox.consent', 201), x('sandbox.consent.diag', 400), x('sandbox.authorisation.diag', 400), x('sandbox.consent-status', 200), x('ais.accounts', 200), x('ais.balances', 200));
  journeyStats(ctx);
  const f = ctx.findings.find((y) => y.checkId === 'rel.availability');
  assert.ok(f);
  assert.equal((f!.evidence as any).diagnosticCallsExcluded, 2);
  assert.equal((f!.evidence as any).samples, 5);
  assert.equal(f!.status, 'fail');
});
