import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { redact, redactBody, redactUrl } from '../src/common/http';
import { renderDump, RawDump, scrubSecrets, stripQuery } from '../src/flows/browser-login';
import { mask } from '../src/ai/ai.checks';
import { DbService } from '../src/storage/db.service';
import { RunSummary } from '../src/common/types';

test('redact: every Authorization scheme keeps only the scheme', () => {
  const basic = Buffer.from('client-id:client-secret').toString('base64');
  const h = redact({ Authorization: `Basic ${basic}`, 'Proxy-Authorization': 'Bearer abc.def.ghi', authorization: 'opaque-token' });
  assert.equal(h.Authorization, 'Basic ***');
  assert.equal(h['Proxy-Authorization'], 'Bearer ***');
  assert.equal(h.authorization, '***');
  assert.ok(!JSON.stringify(h).includes(basic));
});

test('redact: API keys, secrets, passwords and cookies are masked; signatures and request ids stay', () => {
  const h = redact({
    'x-api-key': 'k1',
    apikey: 'k2',
    'X-IBM-Client-Secret': 's1',
    'x-psu-password': 'p1',
    Cookie: 'KEYCLOAK_SESSION=abc; AUTH_SESSION_ID=def',
    'x-jws-signature': 'eyJhbGciOiJQUzI1NiJ9..sig',
    'X-Request-ID': '5f0c1a3e-0000-4000-8000-000000000000',
  });
  assert.equal(h['x-api-key'], '***');
  assert.equal(h.apikey, '***');
  assert.equal(h['X-IBM-Client-Secret'], '***');
  assert.equal(h['x-psu-password'], '***');
  assert.equal(h.Cookie, 'KEYCLOAK_SESSION=***; AUTH_SESSION_ID=***');
  assert.equal(h['x-jws-signature'], 'eyJhbGciOiJQUzI1NiJ9..sig');
  assert.equal(h['X-Request-ID'], '5f0c1a3e-0000-4000-8000-000000000000');
});

test('redactBody: JSON and form-encoded secrets are masked, other fields stay', () => {
  const json = redactBody('{"client_secret":"s","password":"p","code_verifier":"v","refresh_token":"r","token_type":"Bearer","scope":"accounts"}');
  assert.equal(json, '{"client_secret":"***","password":"***","code_verifier":"***","refresh_token":"***","token_type":"Bearer","scope":"accounts"}');
  const form = redactBody('grant_type=authorization_code&client_secret=s&code_verifier=v&password=p&refresh_token=r&client_id=tpp');
  assert.equal(form, 'grant_type=authorization_code&client_secret=***&code_verifier=***&password=***&refresh_token=***&client_id=tpp');
});

test('redactUrl: secrets in a query string are masked', () => {
  assert.equal(redactUrl('https://bank.example/login?username=demo&password=demo&otp=1234'), 'https://bank.example/login?username=demo&password=***&otp=***');
  assert.equal(redactUrl('https://bank.example/v1/accounts?withBalance=true'), 'https://bank.example/v1/accounts?withBalance=true');
});

const field = (f: Partial<RawDump['fields'][number]>): RawDump['fields'][number] => ({ tag: 'input', type: 'text', name: '', id: '', desc: '', value: '', checked: false, disabled: false, form: 'yes', box: '100x20', text: '', ...f });

test('page dump: session links and typed or hidden values are removed, names and types stay', () => {
  const dump = renderDump({
    url: 'https://sso.bank.example/realms/psd2/login-actions/authenticate?session_code=SC&execution=EX&tab_id=TB',
    forms: [{ action: 'https://sso.bank.example/realms/psd2/login-actions/authenticate?session_code=SC&execution=EX&tab_id=TB', method: 'post', id: 'kc-form-login' }],
    fields: [
      field({ name: 'username', id: 'username', desc: 'username username', value: 'BOG_OB_SBX' }),
      field({ type: 'password', name: 'password', id: 'password', desc: 'password password', value: 'Secret123' }),
      field({ type: 'hidden', name: 'credentialId', value: 'cred-42' }),
      field({ type: 'tel', name: 'otp', desc: 'otp one-time-code', value: '4444' }),
      field({ type: 'checkbox', name: 'account', value: 'acc-1', checked: true }),
      field({ tag: 'button', type: 'submit', name: 'login', value: 'Sign in', text: 'Sign in' }),
    ],
    alerts: ['Invalid code'],
    accounts: ['<label><input type="checkbox" value="GE00XX123" name="acc"><a href="/consent?tab_id=TB">GE00XX123</a></label>'],
    scripts: ['/js/app.js?v=3'],
  });
  for (const secret of ['session_code', 'SC', 'EX', 'tab_id=TB', 'BOG_OB_SBX', 'Secret123', 'cred-42', '4444']) assert.ok(!dump.includes(secret), `${secret} leaked:\n${dump}`);
  assert.match(dump, /form action=https:\/\/sso\.bank\.example\/realms\/psd2\/login-actions\/authenticate\?\*\*\* method=post id=kc-form-login/);
  assert.match(dump, /input type=text name=username id=username value=\*\*\*/);
  assert.match(dump, /input type=password name=password id=password value=\*\*\*/);
  assert.match(dump, /input type=hidden name=credentialId id= value=\*\*\*/);
  assert.match(dump, /input type=tel name=otp id= value=\*\*\*/);
  assert.match(dump, /input type=checkbox name=account id= value=acc-1 checked/);
  assert.match(dump, /button type=submit name=login id= value=Sign in/);
  assert.match(dump, /account html: .*value="\*\*\*".*href="\/consent\?\*\*\*"/);
  assert.match(dump, /scripts: \/js\/app\.js\?\*\*\*/);
});

test('page dump: empty fields stay empty, query-less links are unchanged', () => {
  assert.equal(stripQuery('/login'), '/login');
  assert.equal(stripQuery('/login#top'), '/login');
  const dump = renderDump({ url: 'https://bank.example/login', forms: [], fields: [field({ name: 'username' })], alerts: [], accounts: [], scripts: [] });
  assert.match(dump, /name=username id= value= form=/);
});

test('scrubSecrets: the test user password and OTP never survive in steps or dumps', () => {
  const out = scrubSecrets('alert: wrong password Secret123 for OTP 4444; button text 12', ['Secret123', '4444', undefined, '12']);
  assert.equal(out, 'alert: wrong password *** for OTP ***; button text 12');
});

test('AI mask: IBANs in upper or lower case, compact or grouped, are masked; words are not', () => {
  assert.equal(mask('GE29NB0000000101904917'), '[IBAN]');
  assert.equal(mask('acc ge29nb0000000101904917 x'), 'acc [IBAN] x');
  assert.equal(mask('GE29 NB00 0000 0101 9049 17'), '[IBAN]');
  assert.equal(mask('de89 3704 0044 0532 0130 00.'), '[IBAN].');
  assert.equal(mask('ab12 this text stays'), 'ab12 this text stays');
  assert.equal(mask('X-Request-ID 5f0c1a3e-0000-4000-8000-000000000000'), 'X-Request-ID 5f0c1a3e-0000-4000-8000-000000000000');
});

test('runs: one running run blocks others across processes; quota counts API runs only; interrupted runs are failed', () => {
  const dir = mkdtempSync(join(tmpdir(), 'scio-db-'));
  const prev = process.env.DB_FILE;
  process.env.DB_FILE = join(dir, 'test.sqlite');
  try {
    const a = new DbService();
    const b = new DbService(); // second process (CLI) on the same file
    const now = new Date().toISOString();
    const old = new Date(Date.now() - 3 * 3600_000).toISOString();
    const run = (id: string, source: RunSummary['source'], startedAt = now): RunSummary => ({ id, startedAt, status: 'running', targets: ['tbc-mock'], thresholdsSource: 'test', source });

    assert.equal(a.createRunIfIdle(run('r1', 'schedule'), old), undefined);
    assert.equal(b.createRunIfIdle(run('r2', 'cli'), old)?.id, 'r1');
    assert.equal(b.getRun('r2'), undefined);
    a.finishRun('r1', 'done');
    assert.equal(b.createRunIfIdle(run('r3', 'api'), old), undefined);
    b.finishRun('r3', 'done');

    const since = new Date(Date.now() - 3600_000).toISOString();
    assert.equal(a.countRunsSince(since), 2);
    assert.equal(a.countRunsSince(since, { source: 'api' }), 1);

    // Left running by a stopped server; a live CLI run is spared until it is stale.
    a.createRun(run('r4', 'schedule'));
    a.createRun(run('r5', 'cli'));
    a.createRun(run('r6', 'cli', old));
    assert.equal(a.failInterruptedRuns(), 2);
    assert.equal(a.getRun('r4')?.status, 'failed');
    assert.equal(a.getRun('r4')?.error, 'interrupted (server restart)');
    assert.equal(a.getRun('r5')?.status, 'running');
    assert.equal(a.getRun('r6')?.status, 'failed');
    // Catch-up counts failed runs too, the quota does not.
    assert.equal(a.countRunsSince(since, { includeFailed: true }), 4);
    a.onModuleDestroy();
    b.onModuleDestroy();
  } finally {
    if (prev === undefined) delete process.env.DB_FILE;
    else process.env.DB_FILE = prev;
    rmSync(dir, { recursive: true, force: true });
  }
});

test('metrics: Prometheus text with monitor state, uptime and latest audit scores; escapes labels', async () => {
  const { renderMetrics } = await import('../src/metrics/metrics');
  const body = renderMetrics({
    uptime: { availabilityPct: 99.5, source: 'assumed', targets: [{ targetId: 'bank-a', name: 'Bank "A"', intervalMin: 5, last24h: 99.31, last7d: null, last30d: 98, daily: [], monthly: [], incidents: [] }] },
    latest: () => ({ ts: '2026-10-23T10:00:00Z', status: 0, error: 'timeout', durationMs: 15000 }),
  });
  assert.match(body, /# TYPE scio_monitor_up gauge/);
  assert.match(body, /scio_monitor_up\{target="bank-a",name="Bank \\"A\\""\} 0/);
  assert.match(body, /scio_uptime_percent\{target="bank-a",name="Bank \\"A\\"",window="24h"\} 99.31/);
  assert.doesNotMatch(body, /window="7d"/, 'null values are left out, not exported as 0');
  assert.doesNotMatch(body, /scio_audit_score/, 'no audit yet: monitor metrics only');
  assert.ok(body.endsWith('\n'));
});
