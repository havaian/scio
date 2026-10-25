import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { ibanValid } from '../src/checks/data.checks';
import { breakIban, makeGeIban, TX_STATUS } from '../src/checks/pis.checks';
import { percentile, stats } from '../src/checks/performance.checks';
import { jwsHeaderProblems } from '../src/checks/live-conformance.checks';
import { checkMtlsEnforced } from '../src/checks/security.checks';
import { AuditContext } from '../src/checks/context';
import { HttpRecorder, HttpResponse, redactBody } from '../src/common/http';
import { layerScore, overallScore } from '../src/reports/report.service';
import { aggregate, isUp, toCsv } from '../src/monitor/uptime';
import { Exchange, Finding, Thresholds } from '../src/common/types';

const f = (status: Finding['status'], severity: Finding['severity'] = 'none', source?: 'ai'): Finding => ({ targetId: 't', checkId: 'c', layer: 'conformance', status, severity, title: '', message: '', source });

test('IBAN: generated Georgian IBANs pass mod-97, a changed check digit fails', () => {
  for (let i = 0; i < 50; i++) {
    const iban = makeGeIban();
    assert.match(iban, /^GE\d{2}TB\d{16}$/);
    assert.equal(ibanValid(iban), true, iban);
    assert.equal(ibanValid(breakIban(iban)), false);
  }
  assert.equal(ibanValid('GE78TB1121245063622479'), true);
  assert.equal(ibanValid('GE83TB7438345061622218'), false); // example IBAN from the mock spec
  assert.equal(ibanValid('DE89370400440532013000'), true);
});

test('percentile: with 10 samples p95 is the maximum (why p95 needs more samples)', () => {
  const v = [10, 20, 30, 40, 50, 60, 70, 80, 90, 1000];
  assert.equal(percentile(v, 50), 50);
  assert.equal(percentile(v, 95), 1000);
  assert.equal(percentile(v, 99), 1000);
  assert.equal(percentile([], 95), 0);
});

test('stats: 429 counts as available but as an error; timeouts as neither', () => {
  const x = (status: number): Exchange => ({ targetId: 't', operation: 'probe.a', method: 'GET', url: 'u', status, ok: status > 0 && status < 500, durationMs: 100, requestHeaders: {}, responseHeaders: {}, bodySnippet: '', ts: '' });
  const s = stats('a', [x(200), x(429), x(503), x(0)]);
  assert.equal(s.availabilityPct, 50);
  assert.equal(s.errorRatePct, 75);
  assert.deepEqual(s.statuses, { '200': 1, '429': 1, '503': 1, 'timeout/conn': 1 });
});

test('layerScore: severity-weighted, warnings half, info/skip/AI not scored', () => {
  assert.equal(layerScore([]), null);
  assert.equal(layerScore([f('info'), f('skip')]), null);
  assert.equal(layerScore([f('pass'), f('pass'), f('pass')]), 100);
  assert.equal(layerScore([f('pass'), f('fail', 'high')]), 25); // 1 / (1 + 3)
  assert.equal(layerScore([f('pass'), f('warn', 'medium')]), 50); // 1 / (1 + 1)
  assert.equal(layerScore([f('pass'), f('fail', 'high', 'ai')]), 100);
  assert.equal(overallScore({ conformance: 50, reliability: null, latency: 100, security: null, data: null }), 75);
});

test('isUp: HTTP below 500 and TLS refusals are up; timeouts and 5xx are down', () => {
  assert.equal(isUp(401), true);
  assert.equal(isUp(503), false);
  assert.equal(isUp(0, 'fetch failed (ERR_SSL_SSL/TLS_ALERT_HANDSHAKE_FAILURE)'), true);
  assert.equal(isUp(0, 'fetch failed (UNABLE_TO_GET_ISSUER_CERT_LOCALLY)'), true);
  assert.equal(isUp(0, 'fetch failed (UNABLE_TO_VERIFY_LEAF_SIGNATURE)'), true);
  assert.equal(isUp(0, 'fetch failed (UND_ERR_CONNECT_TIMEOUT)'), false);
  assert.equal(isUp(0, 'This operation was aborted (TimeoutError)'), false);
  assert.equal(isUp(0, 'fetch failed (ECONNREFUSED)'), false);
});

test('uptime: Tbilisi calendar days, monthly buckets and incidents', () => {
  const mk = (ts: string, ok: boolean): Exchange => ({ targetId: 't', operation: 'monitor.front-door', method: 'GET', url: 'u', status: ok ? 401 : 503, ok, durationMs: 200, requestHeaders: {}, responseHeaders: {}, bodySnippet: '', ts });
  const xs = [
    mk('2026-10-20T19:00:00.000Z', true), // 23:00 Tbilisi, 20 Oct
    mk('2026-10-20T20:30:00.000Z', false), // 00:30 Tbilisi, 21 Oct
    mk('2026-10-20T21:00:00.000Z', false),
    mk('2026-10-20T21:30:00.000Z', true),
  ];
  const u = aggregate('t', 30, xs, Date.parse('2026-10-21T00:00:00Z'));
  assert.deepEqual(u.daily.map((d) => [d.period, d.samples, d.uptimePct]), [['2026-10-20', 1, 100], ['2026-10-21', 3, 33.33]]);
  assert.deepEqual(u.monthly.map((m) => [m.period, m.uptimePct]), [['2026-10', 50]]);
  assert.equal(u.incidents.length, 1);
  assert.equal(u.incidents[0].samples, 2);
  assert.equal(u.last24h, 50);
  assert.match(toCsv([u], { t: 'Bank "A"' }), /t,"Bank ""A""",2026-10-21,3,1,33.33/);
});

test('JWS header: complete detached header passes, gaps are named', () => {
  const enc = (h: object) => Buffer.from(JSON.stringify(h)).toString('base64url');
  // GE-JWS §6, §8.1: x5c with the signing certificate (x5t#S256 only by agreement), sigD.mId = ETSI HttpHeaders.
  const good = { alg: 'PS256', b64: false, sigT: '2026-10-21T10:00:00Z', sigD: { pars: ['digest'], mId: 'http://uri.etsi.org/19182/HttpHeaders' }, x5c: ['MIIB'], crit: ['sigT', 'sigD', 'b64'] };
  assert.deepEqual(jwsHeaderProblems(`${enc(good)}..sig`), []);
  assert.deepEqual(jwsHeaderProblems(`${enc({ ...good, alg: 'none' })}..sig`), ['algorithm "none" not allowed']);
  assert.ok(jwsHeaderProblems(`${enc({ alg: 'RS256' })}..sig`).includes('b64 is not false'));
  assert.deepEqual(jwsHeaderProblems(`${enc(good)}.payload.sig`), ['payload not detached']);
  assert.deepEqual(jwsHeaderProblems('garbage'), ['not a JWS compact serialization']);
});

test('Digest format: SHA-256 base64 of the body reproduces the GE-JWS §9.4 example', () => {
  // GE-JWS §9.4: every line ends with 0x0A, including the last one.
  const body = [
    '{',
    '"instructedAmount": {"currency": "EUR", "amount": "123.50"},',
    '"debtorAccount": {"iban": "DE40100100103307118608"},',
    '"creditorName": "Merchant123",',
    '"creditorAccount": {"iban": "DE02100100109307118603"},',
    '"remittanceInformationUnstructured": "Ref Number Merchant"',
    '}',
  ].join('\n') + '\n';
  assert.equal(createHash('sha256').update(Buffer.from(body)).digest('base64'), '+xeh7JAayYPh8K13UnQCBBcniZzsyat+KDiuy8aZYdI=');
});

test('token responses are redacted in the exchange log', () => {
  const r = redactBody('{"access_token":"abc.def","token_type":"Bearer","refresh_token":"xyz","expires_in":300}');
  assert.equal(r, '{"access_token":"***","token_type":"Bearer","refresh_token":"***","expires_in":300}');
});

test('mTLS: alert = enforced, server-cert error = not determinable, reset = info only', () => {
  const saved = { a: process.env.HTTPS_PROXY, b: process.env.HTTP_PROXY };
  delete process.env.HTTPS_PROXY;
  delete process.env.HTTP_PROXY;
  try {
    const run = (error: string) => {
      const ctx = new AuditContext({ id: 't', name: 't', bank: 'b', mode: 'passive', simulated: false, baseUrl: 'https://x' }, new HttpRecorder('t', 1000), {} as Thresholds);
      const r: HttpResponse = { status: 0, ok: false, headers: {}, text: '', json: undefined, durationMs: 1, error, requestHeaders: {} };
      checkMtlsEnforced(ctx, r, 'GET /v1/accounts');
      return ctx.findings.map((x) => `${x.checkId}:${x.status}`);
    };
    assert.deepEqual(run('fetch failed (ERR_SSL_SSL/TLS_ALERT_HANDSHAKE_FAILURE)'), ['sec.mtls-enforced:pass']);
    assert.deepEqual(run('fetch failed (UNABLE_TO_GET_ISSUER_CERT_LOCALLY)'), ['sec.mtls-enforced:skip', 'sec.server-cert-chain:fail']);
    assert.deepEqual(run('fetch failed (ECONNRESET)'), ['sec.mtls-enforced:info']);
  } finally {
    if (saved.a) process.env.HTTPS_PROXY = saved.a;
    if (saved.b) process.env.HTTP_PROXY = saved.b;
  }
});

test('transaction status list holds the ISO 20022 codes used by Berlin Group', () => {
  for (const c of ['RCVD', 'ACTC', 'ACSC', 'RJCT', 'CANC', 'PATC']) assert.ok(TX_STATUS.has(c));
  assert.ok(!TX_STATUS.has('OK'));
});

test('schedule: next 06:00 Tashkent (UTC+5) is 01:00 UTC, today or tomorrow', () => {
  // Required lazily so the other tests do not load Nest decorators they do not need.
  const { AuditScheduler } = require('../src/audit/audit.scheduler');
  assert.equal(new Date(AuditScheduler.nextRun('06:00', Date.parse('2026-10-22T00:30:00Z'))).toISOString(), '2026-10-22T01:00:00.000Z');
  assert.equal(new Date(AuditScheduler.nextRun('06:00', Date.parse('2026-10-22T01:00:00Z'))).toISOString(), '2026-10-23T01:00:00.000Z');
  // 23:30 UTC is already 04:30 next day in Tashkent: the slot is the same Tashkent morning.
  assert.equal(new Date(AuditScheduler.nextRun('06:00', Date.parse('2026-10-22T23:30:00Z'))).toISOString(), '2026-10-23T01:00:00.000Z');
});

test('request signing: signing string matches the GE-JWS §9.5 example', () => {
  const { signingString } = require('../src/common/credentials');
  const headers = { Host: 'api.testbank.com', 'Content-Type': 'application/json', 'PSU-IP-Address': '192.168.8.78', 'PSU-Geo-Location': 'GEO:52.506931,13.144558', Digest: 'SHA-256=+xeh7JAayYPh8K13UnQCBBcniZzsyat+KDiuy8aZYdI=' };
  const pars = ['(request-target)', 'host', 'content-type', 'psu-ip-address', 'psu-geo-location', 'digest'];
  assert.equal(
    signingString('POST', 'https://api.testbank.com/v1/payments/sepa-credit-transfers', headers, pars),
    '(request-target): post /v1/payments/sepa-credit-transfers\nhost: api.testbank.com\ncontent-type: application/json\npsu-ip-address: 192.168.8.78\npsu-geo-location: GEO:52.506931,13.144558\ndigest: SHA-256=+xeh7JAayYPh8K13UnQCBBcniZzsyat+KDiuy8aZYdI=',
  );
});

test('request signing: detached JWS verifies and passes our own header checks', (t) => {
  const { execFileSync } = require('node:child_process');
  const { mkdtempSync, readFileSync } = require('node:fs');
  const { join } = require('node:path');
  const { tmpdir } = require('node:os');
  const { createPrivateKey, createVerify, X509Certificate } = require('node:crypto');
  const { jwsSigner, digestOf } = require('../src/common/credentials');
  const dir = mkdtempSync(join(tmpdir(), 'scio-cert-'));
  try {
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', join(dir, 'k.pem'), '-out', join(dir, 'c.pem'), '-days', '1', '-subj', '/CN=scio-test'], { stdio: 'ignore' });
  } catch {
    t.skip('openssl not available');
    return;
  }
  const cert = new X509Certificate(readFileSync(join(dir, 'c.pem')));
  const sign = jwsSigner(createPrivateKey(readFileSync(join(dir, 'k.pem'))), cert);
  const body = '{"a":1}';
  const headers = { 'Content-Type': 'application/json', 'X-Request-ID': 'r-1', 'PSU-IP-Address': '192.0.2.10' };
  const out = sign({ method: 'POST', url: 'https://bank.example/0.8/v1/consents', headers, body });
  assert.equal(out.Digest, digestOf(body));
  assert.deepEqual(jwsHeaderProblems(out['x-jws-signature']), []);
  const [h, , s] = out['x-jws-signature'].split('.');
  const ph = JSON.parse(Buffer.from(h, 'base64url').toString());
  assert.deepEqual(ph.sigD.pars, ['(request-target)', 'host', 'content-type', 'psu-ip-address', 'x-request-id', 'digest']);
  const input = `${h}.(request-target): post /0.8/v1/consents\nhost: bank.example\ncontent-type: application/json\npsu-ip-address: 192.0.2.10\nx-request-id: r-1\ndigest: ${out.Digest}`;
  assert.ok(createVerify('SHA256').update(input).verify(cert.publicKey, Buffer.from(s, 'base64url')));
});

test('sandbox login: form reader fills demo user, OTP, accounts and approve button', () => {
  const { parseForms, fillForm } = require('../src/flows/sandbox.flow');
  const html = `<form method="post" action="/login"><input type="hidden" name="__RequestVerificationToken" value="abc"><input name="UserName"><input type="password" name="Password"><button type="submit" name="action" value="login">Sign in</button></form>`;
  const f = parseForms(html)[0];
  assert.equal(f.method, 'POST');
  assert.deepEqual(fillForm(f, { user: 'demo', password: 'demo', otp: '1234' }), { __RequestVerificationToken: 'abc', UserName: 'demo', Password: 'demo', action: 'login' });
  const consent = parseForms(`<form method="post"><input type="text" name="OtpCode"><input type="checkbox" name="accounts" value="GE29NB0000000101904917"><button name="decision" value="deny">Deny</button><button name="decision" value="approve">Approve</button></form>`)[0];
  assert.deepEqual(fillForm(consent, { user: 'demo', password: 'demo', otp: '1234' }), { OtpCode: '1234', accounts: 'GE29NB0000000101904917', decision: 'approve' });
});

test('sandbox consent body: spec example with validity moved into the future', () => {
  const { consentBody } = require('../src/flows/sandbox.flow');
  const op = { requestBody: { content: { 'application/json': { examples: { a: { value: { access: { availableAccounts: 'allAccounts' }, validUntil: '2021-02-28', frequencyPerDay: 4 } } } } } } };
  const b = consentBody(op);
  assert.equal(b.access.availableAccounts, 'allAccounts');
  assert.ok(b.validUntil > new Date().toISOString().slice(0, 10));
  assert.equal(op.requestBody.content['application/json'].examples.a.value.validUntil, '2021-02-28');
});

test('uptime: the same sample falls on different calendar days in Tbilisi and Tashkent', () => {
  const { UPTIME_TZ } = require('../src/monitor/uptime');
  // 19:30 UTC = 23:30 Tbilisi (Oct 21) = 00:30 Tashkent (Oct 22).
  const x = (ts: string) => ({ targetId: 't', operation: 'monitor', method: 'GET', url: 'u', status: 200, ok: true, durationMs: 10, requestHeaders: {}, responseHeaders: {}, bodySnippet: '', ts });
  const xs = [x('2026-10-21T19:30:00.000Z')];
  const now = Date.parse('2026-10-22T00:00:00Z');
  assert.equal(aggregate('t', 5, xs, now, UPTIME_TZ.tbilisi.offsetMs).daily[0].period, '2026-10-21');
  assert.equal(aggregate('t', 5, xs, now, UPTIME_TZ.tashkent.offsetMs).daily[0].period, '2026-10-22');
  assert.match(toCsv([aggregate('t', 5, xs, now, UPTIME_TZ.tashkent.offsetMs)], {}, 'tashkent'), /^target_id,target_name,date_tashkent,/);
});

test('certificates: chain exported from .p12 is reordered so the key-matching certificate comes first', (t) => {
  const { execFileSync } = require('node:child_process');
  const { mkdtempSync, readFileSync } = require('node:fs');
  const { join } = require('node:path');
  const { tmpdir } = require('node:os');
  const { createPrivateKey } = require('node:crypto');
  const { certChain } = require('../src/common/credentials');
  const d = mkdtempSync(join(tmpdir(), 'scio-chain-'));
  try {
    const o = { stdio: 'ignore' };
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', join(d, 'ca.key'), '-out', join(d, 'ca.crt'), '-days', '1', '-subj', '/CN=ca'], o);
    execFileSync('openssl', ['req', '-newkey', 'rsa:2048', '-nodes', '-keyout', join(d, 'l.key'), '-out', join(d, 'l.csr'), '-subj', '/CN=leaf'], o);
    execFileSync('openssl', ['x509', '-req', '-in', join(d, 'l.csr'), '-CA', join(d, 'ca.crt'), '-CAkey', join(d, 'ca.key'), '-CAcreateserial', '-out', join(d, 'l.crt'), '-days', '1'], o);
  } catch {
    t.skip('openssl not available');
    return;
  }
  // CA first, as some exports order it.
  const bundle = Buffer.concat([readFileSync(join(d, 'ca.crt')), readFileSync(join(d, 'l.crt'))]);
  const chain = certChain(bundle, createPrivateKey(readFileSync(join(d, 'l.key'))));
  assert.equal(chain.length, 2);
  assert.match(chain[0].subject, /CN=leaf/);
});

test('sandbox consent: one-off access is corrected to frequencyPerDay 1', () => {
  const { consistentConsent } = require('../src/flows/sandbox.flow');
  assert.deepEqual(consistentConsent({ recurringIndicator: false, frequencyPerDay: 4 }), { recurringIndicator: false, frequencyPerDay: 1 });
  assert.equal(consistentConsent({ recurringIndicator: true, frequencyPerDay: 4 }), undefined);
});

test('GE-JWS header rules: x5c single entry, no x5t/jwk/cty, sigT format and clock window, ETSI mId', () => {
  const { jwsProtectedHeaderProblems } = require('../src/checks/live-conformance.checks');
  const good = { b64: false, x5c: ['MIIB'], crit: ['sigT', 'sigD', 'b64'], sigT: '2026-10-23T10:00:00Z', sigD: { pars: ['(request-target)', 'digest'], mId: 'http://uri.etsi.org/19182/HttpHeaders' }, alg: 'RS256' };
  assert.deepEqual(jwsProtectedHeaderProblems(good, new Date('2026-10-23T10:00:30Z')), []);
  const has = (h: any, re: RegExp, at?: Date) => assert.ok(jwsProtectedHeaderProblems(h, at).some((p: string) => re.test(p)), `${re} in ${JSON.stringify(jwsProtectedHeaderProblems(h, at))}`);
  has({ ...good, x5c: ['A', 'B'] }, /x5c holds 2/);
  has({ ...good, 'x5t#S256': 'abc' }, /used together/);
  has({ ...good, x5c: undefined, 'x5t#S256': 'abc' }, /without kid/);
  has({ ...good, x5t: 'sha1' }, /"x5t" must not/);
  has({ ...good, jwk: {} }, /"jwk" must not/);
  has({ ...good, sigT: '2026-10-23T10:00:00.123Z' }, /fractional/);
  has({ ...good, sigD: { pars: ['digest'], mId: 'urn:other' } }, /mId/);
  has(good, /in the future/, new Date('2026-10-23T09:59:50Z'));
  has(good, /s old/, new Date('2026-10-23T10:02:00Z'));
  has({ ...good, alg: 'HS256' }, /not allowed/);
});

test('Digest: SHA-512 is accepted (GE-JWS §5.1), a wrong hash is not', () => {
  const { digestMatches } = require('../src/checks/live-conformance.checks');
  const body = Buffer.from('{"a":1}');
  const s512 = createHash('sha512').update(body).digest('base64');
  const s256 = createHash('sha256').update(body).digest('base64');
  assert.equal(digestMatches(`SHA-512=${s512}`, body).ok, true);
  assert.equal(digestMatches(`SHA-256=${s256}`, { sha256: s256 }).ok, true);
  assert.equal(digestMatches(`SHA-256=${s512}`, body).ok, false);
  assert.equal(digestMatches('MD5=abc', body).ok, false);
});

test('error bodies: RFC 7807 with code passes, PascalCase tppMessages is named, code-status checked', () => {
  const { errorShape } = require('../src/checks/live-conformance.checks');
  // Credo, passive probe of the Oct 23 run.
  assert.deepEqual(errorShape({ type: 'https://berlingroup.com/error-codes/CERTIFICATE_MISSING', title: 'QWAC MTLS client certificate is missing', code: 'CERTIFICATE_MISSING' }), { shape: 'rfc7807', code: 'CERTIFICATE_MISSING' });
  // ProCredit, same run.
  assert.deepEqual(errorShape({ TppMessages: [{ Category: 'ERROR', Code: 'FORMAT_ERROR', Text: 'x' }] }), { shape: 'case', code: 'FORMAT_ERROR' });
  assert.equal(errorShape({ tppMessages: [{ category: 'ERROR', code: 'FORMAT_ERROR' }] }).shape, 'tpp');
  assert.equal(errorShape({ message: 'nope' }).shape, 'none');
  const ctx = new AuditContext({ id: 't', name: 't', bank: 't', mode: 'passive', simulated: false, baseUrl: 'https://x' } as any, new HttpRecorder('t', 1000), {} as Thresholds);
  const { checkErrorBodies } = require('../src/checks/live-conformance.checks');
  checkErrorBodies(ctx, [{ status: 401, bodySnippet: '{"TppMessages":[{"Category":"ERROR","Code":"FORMAT_ERROR"}]}', responseHeaders: {} }], 'unauthenticated error responses');
  const byId = Object.fromEntries(ctx.findings.map((x: Finding) => [x.checkId, x.status]));
  assert.equal(byId['live.error-format'], 'fail');
  assert.equal(byId['live.error-code-status'], 'fail');
});

test('isUp: expired or wrong-name server certificate is down', () => {
  assert.equal(isUp(0, 'fetch failed (CERT_HAS_EXPIRED)'), false);
  assert.equal(isUp(0, 'fetch failed (ERR_TLS_CERT_ALTNAME_INVALID)'), false);
  assert.equal(isUp(0, 'fetch failed (SELF_SIGNED_CERT_IN_CHAIN)'), true);
});

test('scoring: a layer needs minLayerChecks verdicts; like-for-like uses only shared checks', () => {
  const { commonScores } = require('../src/reports/report.service');
  assert.equal(layerScore([f('pass')], 3), null);
  assert.equal(layerScore([f('pass'), f('pass'), f('fail', 'low')], 3), 67);
  const mk = (targetId: string, checkId: string, status: Finding['status']): Finding => ({ ...f(status, status === 'fail' ? 'high' : 'none'), targetId, checkId });
  const fs = [
    ...['a', 'b', 'c', 'd', 'e'].map((c) => mk('x', c, 'pass')),
    mk('x', 'only-x', 'fail'),
    ...['a', 'b', 'c', 'd'].map((c) => mk('y', c, 'pass')),
    mk('y', 'e', 'fail'),
  ];
  const r = commonScores(fs, ['x', 'y']);
  assert.deepEqual(r.checkIds, ['a', 'b', 'c', 'd', 'e']);
  assert.equal(r.scores.x, 100);
  assert.equal(r.scores.y, 57);
  assert.equal(commonScores(fs, ['x']), null);
});

test('request signing: x5c holds only the signing certificate unless the chain fallback is on; JWS verifies', (t) => {
  const { execFileSync } = require('node:child_process');
  const { mkdtempSync, readFileSync } = require('node:fs');
  const { join } = require('node:path');
  const { tmpdir } = require('node:os');
  const { createPrivateKey, X509Certificate } = require('node:crypto');
  const { jwsSigner } = require('../src/common/credentials');
  const { verifyDetachedJws } = require('../src/checks/live-conformance.checks');
  const dir = mkdtempSync(join(tmpdir(), 'scio-cert-'));
  try {
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', join(dir, 'k.pem'), '-out', join(dir, 'c.pem'), '-days', '1', '-subj', '/CN=scio-test'], { stdio: 'ignore' });
  } catch {
    t.skip('openssl not available');
    return;
  }
  const cert = new X509Certificate(readFileSync(join(dir, 'c.pem')));
  const opts: any = {};
  const sign = jwsSigner(createPrivateKey(readFileSync(join(dir, 'k.pem'))), cert, [cert], opts);
  const headers = { 'Content-Type': 'application/json', 'X-Request-ID': 'r-1' };
  const url = 'https://bank.example/0.8/v1/consents';
  const x5cLen = (v: string) => JSON.parse(Buffer.from(v.split('.')[0], 'base64url').toString()).x5c.length;
  const one = sign({ method: 'POST', url, headers, body: '{}' });
  assert.equal(x5cLen(one['x-jws-signature']), 1);
  opts.x5cChain = true;
  assert.equal(x5cLen(sign({ method: 'POST', url, headers, body: '{}' })['x-jws-signature']), 2);
  // Round trip through the response verifier: same headers verify, a changed digest does not.
  const all = { ...headers, Digest: one.Digest };
  assert.equal(verifyDetachedJws(one['x-jws-signature'], 'POST', url, all).verified, true);
  assert.equal(verifyDetachedJws(one['x-jws-signature'], 'POST', url, { ...all, Digest: 'SHA-256=AAAA' }).verified, false);
});
