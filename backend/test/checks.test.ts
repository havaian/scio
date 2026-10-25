import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runDataChecks } from '../src/checks/data.checks';
import { runStaticSpecChecks } from '../src/checks/static-spec.checks';
import { checkMtlsEnforced } from '../src/checks/security.checks';
import { AuditContext } from '../src/checks/context';
import { HttpRecorder, HttpResponse } from '../src/common/http';
import { commonScores } from '../src/reports/report.service';
import { aggregate, toCsv, windowStart } from '../src/monitor/uptime';
import { Spec } from '../src/spec/spec';
import { Exchange, Finding, Thresholds } from '../src/common/types';

const target = { id: 't', name: 't', bank: 'b', mode: 'passive' as const, simulated: false, baseUrl: 'https://api.bank.ge/0.8' };
const newCtx = (spec?: Spec) => new AuditContext(target, new HttpRecorder('t', 1000), {} as Thresholds, spec);
const pick = (ctx: AuditContext, id: string) => ctx.findings.filter((f) => f.checkId === id);
const ok = (json: unknown) => ({ status: 200, json });

test('currency: XXX (multi-currency account, GE-XS2A §9.3.3) and metal codes are ISO 4217', () => {
  const ctx = newCtx();
  ctx.state.accounts = ok({ accounts: [{ resourceId: 'a', currency: 'XXX' }, { resourceId: 'b', currency: 'XAU' }, { resourceId: 'c', currency: 'GEL' }] });
  runDataChecks(ctx);
  assert.equal(pick(ctx, 'data.currency')[0].status, 'pass');
  const bad = newCtx();
  bad.state.accounts = ok({ accounts: [{ resourceId: 'a', currency: 'LARI' }] });
  runDataChecks(bad);
  assert.equal(pick(bad, 'data.currency')[0].status, 'fail');
});

test('card accounts: cardTransactions read, cardTransactionId unique, balances as for accounts, no transactions = info', () => {
  const ctx = newCtx();
  ctx.state.txWindow = { from: '2026-07-01', to: '2026-10-20' };
  ctx.state.accountReads = [{ id: 'acc', tx: ok({ transactions: { booked: [] } }) }];
  ctx.state.cardReads = [
    {
      id: 'card',
      balances: ok({ balances: [{ balanceType: 'interimAvailable' }] }),
      tx: ok({ cardTransactions: { booked: [{ cardTransactionId: 'x1', bookingDate: '2026-10-21' }, { cardTransactionId: 'x1', bookingDate: '2026-09-01' }] } }),
    },
  ];
  runDataChecks(ctx);
  const byEndpoint = (id: string, ep: string) => pick(ctx, id).find((f) => f.endpoint === ep)!;
  // dateTo + 1 day is tolerated (Tbilisi booking date, GE-XS2A §9.3.6).
  assert.equal(byEndpoint('data.tx-window', 'card-account transactions of card').status, 'pass');
  assert.match(byEndpoint('data.tx-window', 'card-account transactions of card').message, /^2 transactions/);
  assert.equal(byEndpoint('data.tx-ids', 'card-account transactions of card').status, 'fail');
  assert.match(byEndpoint('data.tx-ids', 'card-account transactions of card').message, /cardTransactionId/);
  assert.equal(byEndpoint('data.tx-window', 'transactions of acc').status, 'info');
  assert.equal(byEndpoint('data.tx-ids', 'transactions of acc').status, 'info');
  // GE-XS2A §9.4.7: card accounts return what accounts return (closingBooked + interimAvailable).
  const bal = byEndpoint('data.balance-minimum', 'card-account balances · card');
  assert.equal(bal.status, 'fail');
  assert.match(bal.message, /closingBooked/);
});

test('tx window: two days after dateTo fails, entryReference must be unique across booked and pending', () => {
  const ctx = newCtx();
  ctx.state.txWindow = { from: '2026-07-01', to: '2026-10-20' };
  ctx.state.accountReads = [{ id: 'acc', tx: ok({ transactions: { booked: [{ entryReference: 'e1', bookingDate: '2026-10-22' }], pending: [{ entryReference: 'e1' }] } }) }];
  runDataChecks(ctx);
  assert.equal(pick(ctx, 'data.tx-window')[0].status, 'fail');
  assert.equal(pick(ctx, 'data.tx-ids')[0].status, 'fail');
});

test('examples-valid: oneOf with {} and boolean exclusiveMinimum validate; requestBody $ref followed; uncompilable not counted', () => {
  const doc = {
    openapi: '3.0.1',
    servers: [{ url: '/0.8' }],
    paths: {
      '/v1/consents': {
        post: {
          requestBody: { $ref: '#/components/requestBodies/consent' },
          responses: { '201': { content: { 'application/json': { schema: { $ref: '#/components/schemas/consent' } } } } },
        },
      },
      '/v1/consents/{consentId}/authorisations': {
        post: {
          requestBody: {
            content: {
              'application/json': {
                schema: { oneOf: [{}, { type: 'object', required: ['psuData'], properties: { psuData: { type: 'object' } } }] },
                examples: { empty: { value: {} }, psu: { value: { psuData: { password: 'x' } } } },
              },
            },
          },
          responses: { '201': {} },
        },
      },
      '/v1/broken': {
        post: { requestBody: { content: { 'application/json': { schema: { $ref: '#/components/schemas/missing' }, examples: { a: { value: {} } } } } }, responses: { '200': {} } },
      },
    },
    components: {
      requestBodies: { consent: { content: { 'application/json': { schema: { $ref: '#/components/schemas/consent' }, examples: { one: { value: { frequencyPerDay: 1 } } } } } } },
      schemas: { consent: { type: 'object', properties: { frequencyPerDay: { type: 'integer', minimum: 0, exclusiveMinimum: true } } } },
    },
  };
  const spec = new Spec(doc, 'test', '/0.8');
  const ctx = newCtx(spec);
  runStaticSpecChecks(ctx);
  const ex = pick(ctx, 'spec.examples-valid')[0];
  assert.equal(ex.status, 'pass', ex.message);
  assert.match(ex.message, /All 3 JSON request examples/);
  assert.match(ex.message, /1 more could not be checked/);
  // The boolean exclusiveMinimum no longer stops live response validation, and it still means "> 0".
  assert.equal(spec.validate('POST', 'https://api.bank.ge/0.8/v1/consents', 201, { frequencyPerDay: 2 }).valid, true);
  assert.equal(spec.validate('POST', 'https://api.bank.ge/0.8/v1/consents', 201, { frequencyPerDay: 0 }).valid, false);
});

test('mTLS: 401 for the token is not proof of certificate enforcement; CERTIFICATE_MISSING is', () => {
  const run = (status: number, json: unknown) => {
    const ctx = newCtx();
    const r: HttpResponse = { status, ok: false, headers: {}, text: JSON.stringify(json), json, durationMs: 1, requestHeaders: {} };
    checkMtlsEnforced(ctx, r, 'GET /v1/accounts');
    return ctx.findings.map((x) => `${x.checkId}:${x.status}`);
  };
  assert.deepEqual(run(401, { tppMessages: [{ category: 'ERROR', code: 'TOKEN_MISSING' }] }), ['sec.mtls-enforced:info']);
  assert.deepEqual(run(403, {}), ['sec.mtls-enforced:info']);
  assert.deepEqual(run(401, { tppMessages: [{ category: 'ERROR', code: 'CERTIFICATE_MISSING' }] }), ['sec.mtls-enforced:pass']);
  assert.deepEqual(run(401, { TppMessages: [{ Code: 'certificate_invalid' }] }), ['sec.mtls-enforced:pass']);
});

test('uptime: coverage per period, partial first/current periods, incidents split on monitor gaps', () => {
  const mk = (ts: number, ok: boolean): Exchange => ({ targetId: 't', operation: 'monitor.front-door', method: 'GET', url: 'u', status: ok ? 401 : 503, ok, durationMs: 100, requestHeaders: {}, responseHeaders: {}, bodySnippet: '', ts: new Date(ts).toISOString() });
  const day = (d: string) => Date.parse(`${d}T00:00:00Z`) - 4 * 3600_000; // Tbilisi midnight
  const xs: Exchange[] = [];
  // 20 Oct: monitor starts at 12:00 Tbilisi (partial). 21 Oct: whole day, every 60 min. 22 Oct: now is 06:00 (partial).
  for (let h = 12; h < 24; h++) xs.push(mk(day('2026-10-20') + h * 3600_000, true));
  for (let h = 0; h < 24; h++) xs.push(mk(day('2026-10-21') + h * 3600_000, !(h === 3 || h === 4 || h === 10 || h === 11)));
  // Gap 14:00..18:00 on 21 Oct (no samples) inside a failure: drop the 12:00..16:00 samples.
  const gapped = xs.filter((x) => !(Date.parse(x.ts) > day('2026-10-21') + 11 * 3600_000 && Date.parse(x.ts) < day('2026-10-21') + 17 * 3600_000));
  gapped.splice(gapped.findIndex((x) => Date.parse(x.ts) === day('2026-10-21') + 17 * 3600_000), 1, mk(day('2026-10-21') + 17 * 3600_000, false));
  const now = day('2026-10-22') + 6 * 3600_000;
  const u = aggregate('t', 60, gapped, now, 4 * 3600_000, windowStart(3, now));
  const d = Object.fromEntries(u.daily.map((b) => [b.period, b]));
  assert.equal(d['2026-10-20'].partial, true);
  assert.equal(d['2026-10-20'].coveragePct, 50);
  assert.equal(d['2026-10-21'].partial, false);
  assert.equal(d['2026-10-21'].expected, 24);
  assert.equal(d['2026-10-21'].coveragePct, 79.17); // 19 of 24
  assert.equal(u.monthly[0].partial, true);
  // 03-04 h: one incident; 10-11 h then a 6 h gap, then 17 h failing: two incidents, not one spanning the gap.
  assert.equal(u.incidents.length, 3);
  assert.deepEqual(u.incidents.map((i) => i.samples), [1, 2, 2]);
  const csv = toCsv([u], {});
  assert.match(csv.split('\n')[0], /,p95_ms,coverage_pct$/);
  assert.match(csv, /2026-10-21,19,14,73\.68,19,100,,79\.17/);
});

test('like-for-like: each check counts once per target (worst verdict), so per-path findings do not weigh more', () => {
  const mk = (targetId: string, checkId: string, status: Finding['status'], severity: Finding['severity'] = 'none'): Finding => ({ targetId, checkId, layer: 'conformance', status, severity, title: '', message: '' });
  const fs: Finding[] = [
    ...['a', 'b', 'c', 'd'].flatMap((c) => [mk('x', c, 'pass'), mk('y', c, 'pass')]),
    // x: one failing path; y: the same check passes on 20 paths and fails on one.
    mk('x', 'e', 'fail', 'low'),
    ...Array.from({ length: 20 }, () => mk('y', 'e', 'pass')),
    mk('y', 'e', 'warn', 'low'),
    mk('y', 'e', 'fail', 'low'),
  ];
  const r = commonScores(fs, ['x', 'y'])!;
  assert.equal(r.scores.x, 80); // 4 / (4 + 1)
  assert.equal(r.scores.y, 80); // same verdicts once collapsed
});

test('spec.vrp: VRP operations found by path or summary; fixed recurring alone is reported as no VRP', async () => {
  const { runCrossBankSpecChecks } = await import('../src/checks/static-spec.checks');
  const mk = (paths: Record<string, any>) => {
    const ctx = newCtx(new Spec({ openapi: '3.0.1', info: { version: '0.8' }, paths }, 'test', '/0.8'));
    runCrossBankSpecChecks(ctx);
    return pick(ctx, 'spec.vrp')[0];
  };
  const withVrp = mk({ '/v2/sweeping/{payment-product}': { post: { summary: 'Initiate a variable recurring payment', responses: {} } } });
  assert.equal(withVrp.status, 'info');
  assert.match(withVrp.message, /1 VRP operation/);
  const fixedOnly = mk({ '/v1/periodic-payments/{payment-product}': { post: { responses: {} } } });
  assert.match(fixedOnly.message, /No VRP/);
  assert.match(fixedOnly.message, /Fixed-amount recurring payments are published/);
});

test('consent journey: counts person and TPP steps, info only', async () => {
  const { consentJourney } = await import('../src/flows/sandbox.flow');
  const ctx = newCtx();
  ctx.state.consentJourney = { via: 'browser', completed: true, screens: 3, typed: { user: 1, password: 1, otp: 1 }, choices: 2, clicks: 3, navigations: 5, hosts: ['login.bank.ge'] };
  for (const op of ['sandbox.consent', 'sandbox.consent.diag', 'sandbox.oauth-metadata', 'sandbox.token', 'sandbox.token'])
    ctx.http.exchanges.push({ targetId: 't', operation: op, method: 'POST', url: 'u', status: 200, ok: true, durationMs: 1, requestHeaders: {}, responseHeaders: {}, bodySnippet: '', ts: '' });
  consentJourney(ctx);
  const f = pick(ctx, 'ux.consent-journey')[0];
  assert.equal(f.status, 'info');
  assert.equal((f.evidence as any).tppSteps, 3, 'consent, OAuth metadata, token; .diag and retries not counted');
  assert.equal((f.evidence as any).typedTotal, 3);
  assert.match(f.message, /^Completed: the person faced 3 screen\(s\)/);
});

test('consent journey: a second login (extra consent) does not replace the first journey', async () => {
  const { consentJourney } = await import('../src/flows/sandbox.flow');
  const ctx = newCtx();
  ctx.state.consentJourney = { via: 'browser', completed: true, screens: 3, typed: { user: 1, password: 1, otp: 1 }, choices: 3, clicks: 3, navigations: 3, hosts: [] };
  ctx.state.extraLogins = [{ via: 'browser', completed: false, screens: 1, typed: { user: 1, password: 0, otp: 0 }, choices: 0, clicks: 1, navigations: 1, hosts: [] }];
  consentJourney(ctx);
  const f = pick(ctx, 'ux.consent-journey')[0];
  assert.match(f.message, /^Completed/);
  assert.match(f.message, /Scio ran 1 further login\(s\) to work around bank deviations .*0 completed/);
  assert.equal((f.evidence as any).screens, 3);
});

test('consent journey: an authorization request refused before any screen is not the journey', async () => {
  const { consentJourney } = await import('../src/flows/sandbox.flow');
  const ctx = newCtx();
  // As recordJourney leaves it: the invalid_scope bounce counted apart, the real login as the journey.
  ctx.state.rejectedAuth = 2;
  ctx.state.consentJourney = { via: 'browser', completed: true, screens: 2, typed: { user: 1, password: 1, otp: 1 }, choices: 0, clicks: 2, navigations: 4, hosts: ['a'] };
  consentJourney(ctx);
  const f = pick(ctx, 'ux.consent-journey')[0];
  assert.match(f.message, /faced 2 screen/);
  assert.match(f.message, /2 authorization request\(s\) were refused before any login screen/);
  assert.equal((f.evidence as any).rejectedAuthRequests, 2);
});
