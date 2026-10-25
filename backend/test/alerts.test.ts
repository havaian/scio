import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DbService } from '../src/storage/db.service';
import { AlertsService } from '../src/alerts/alerts.service';
import { AlertChannel } from '../src/alerts/channels';
import { Exchange, Finding, TargetConfig, Thresholds } from '../src/common/types';

const T0 = Date.parse('2026-10-20T08:00:00Z');
const MIN = 60_000;
const target: TargetConfig = { id: 'bank-a', name: 'Bank A', bank: 'Bank A', mode: 'passive', simulated: false, baseUrl: 'https://a.example/0.8' };
const thresholds = { latencyP95Ms: 1000, certExpiryWarnDays: 30, monitor: { realIntervalMin: 5 }, alerts: { enabled: true, latencyWindowMin: 30, certRepeatDays: 7 } } as unknown as Thresholds;

/** Fresh temp database per test; the fake channel records messages instead of sending them. */
function setup() {
  const dir = mkdtempSync(join(tmpdir(), 'scio-alerts-'));
  const prev = process.env.DB_FILE;
  process.env.DB_FILE = join(dir, 'test.sqlite');
  const sent: string[] = [];
  const fake: AlertChannel = { name: 'fake', send: async (subject) => void sent.push(subject) };
  let now = T0;
  const make = (db = new DbService()) => {
    const s = new AlertsService(db);
    s.channels = [fake];
    s.targets = () => [target];
    s.thresholds = () => thresholds;
    s.now = () => now;
    s.clientCertExpiry = () => undefined;
    return s;
  };
  const db = new DbService();
  return {
    db,
    sent,
    make,
    setNow: (ms: number) => (now = ms),
    done: () => {
      db.onModuleDestroy();
      rmSync(dir, { recursive: true, force: true });
      if (prev === undefined) delete process.env.DB_FILE;
      else process.env.DB_FILE = prev;
    },
  };
}

function sample(ts: number, status: number, durationMs = 200, error?: string): Exchange {
  return { targetId: target.id, operation: 'monitor.front-door', method: 'GET', url: `${target.baseUrl}/v1/accounts`, status, ok: status > 0 && status < 500, durationMs, error, requestHeaders: {}, responseHeaders: {}, bodySnippet: '', ts: new Date(ts).toISOString() };
}

function finding(checkId: string, extra: Partial<Finding> = {}): Finding {
  return { targetId: target.id, checkId, layer: 'security', status: 'fail', severity: 'high', title: `Check ${checkId}`, endpoint: '/v1/accounts', message: 'm', ...extra };
}

function addRun(db: DbService, id: string, startedAt: number, findings: Finding[], targets = [target.id]) {
  db.createRun({ id, startedAt: new Date(startedAt).toISOString(), status: 'running', targets, thresholdsSource: 'test' });
  db.insertFindings(id, findings);
  db.finishRun(id, 'done');
}

test('alerts: down then recovered sends exactly 2 alerts; a restart does not re-alert', async () => {
  const h = setup();
  try {
    const s = h.make();
    h.db.insertExchanges(null, [sample(T0 - 10 * MIN, 401)]);
    await s.checkDown();
    assert.equal(h.sent.length, 0, 'up on first look: silent');
    for (let i = 0; i < 3; i++) {
      h.setNow(T0 + i * 5 * MIN);
      h.db.insertExchanges(null, [sample(T0 + i * 5 * MIN, 0, 15000, 'timeout')]);
      await s.checkDown();
    }
    assert.equal(h.sent.length, 1);
    assert.match(h.sent[0], /Bank A is DOWN/);
    // Restart while down: new instance on the same database.
    const s2 = h.make(new DbService());
    await s2.checkDown();
    assert.equal(h.sent.length, 1);
    for (let i = 3; i < 6; i++) {
      h.setNow(T0 + i * 5 * MIN);
      h.db.insertExchanges(null, [sample(T0 + i * 5 * MIN, 401)]);
      await s2.checkDown();
    }
    assert.equal(h.sent.length, 2);
    assert.match(h.sent[1], /Bank A is back UP/);
    await h.make(new DbService()).checkDown();
    assert.equal(h.sent.length, 2);
    assert.equal(h.db.recentAlerts().length, 2);
  } finally {
    h.done();
  }
});

test('alerts: latency alerts once when the median exceeds the threshold, then once on recovery', async () => {
  const h = setup();
  try {
    const s = h.make();
    // 4 slow samples: below the 5-sample minimum, no alert. Transport-only samples (status 0) do not count.
    h.db.insertExchanges(null, [0, 1, 2, 3].map((i) => sample(T0 - (20 - i) * MIN, 401, 3000)));
    h.db.insertExchanges(null, [sample(T0 - 10 * MIN, 0, 9000, 'CERT_REQUIRED')]);
    await s.checkLatency();
    assert.equal(h.sent.length, 0);
    h.db.insertExchanges(null, [sample(T0 - 5 * MIN, 401, 2500)]);
    await s.checkLatency();
    await s.checkLatency();
    assert.equal(h.sent.length, 1);
    assert.match(h.sent[0], /Bank A is slow/);
    // 40 min later the window holds only fast samples.
    h.setNow(T0 + 40 * MIN);
    h.db.insertExchanges(null, [0, 1, 2, 3, 4].map((i) => sample(T0 + (20 + i) * MIN, 401, 150)));
    await s.checkLatency();
    await s.checkLatency();
    assert.equal(h.sent.length, 2);
    assert.match(h.sent[1], /latency back to normal/);
  } finally {
    h.done();
  }
});

test('alerts: new high findings only for those absent in the previous run, each run processed once', async () => {
  const h = setup();
  try {
    const s = h.make();
    addRun(h.db, 'r1', T0 - 2 * 86400_000, [finding('sec.a')]);
    await s.checkNewFindings(); // first start: history is the baseline
    assert.equal(h.sent.length, 0);
    addRun(h.db, 'r2', T0 - 86400_000, [finding('sec.a'), finding('sec.b'), finding('sec.c', { severity: 'medium' }), finding('sec.d', { status: 'warn' })]);
    await s.checkNewFindings();
    await s.checkNewFindings();
    await h.make(new DbService()).checkNewFindings();
    assert.equal(h.sent.length, 1);
    assert.match(h.sent[0], /1 new high-severity finding - Bank A/);
    const msg = h.db.recentAlerts()[0].message;
    assert.match(msg, /Check sec\.b/);
    assert.doesNotMatch(msg, /sec\.a|sec\.c|sec\.d/);
  } finally {
    h.done();
  }
});

test('alerts: certificate within 30 days alerts once, not again within the repeat window, again after it', async () => {
  const h = setup();
  try {
    const s = h.make();
    const validTo = new Date(T0 + 10 * 86400_000).toUTCString();
    addRun(h.db, 'r1', T0 - 3600_000, [finding('sec.tls', { status: 'warn', severity: 'medium', endpoint: 'a.example', evidence: { validTo } })]);
    await s.checkCerts();
    assert.equal(h.sent.length, 1);
    assert.match(h.sent[0], /certificate expires in 10 days/);
    h.setNow(T0 + 3 * 86400_000);
    await s.checkCerts();
    await h.make(new DbService()).checkCerts();
    assert.equal(h.sent.length, 1);
    h.setNow(T0 + 8 * 86400_000);
    await s.checkCerts();
    assert.equal(h.sent.length, 2);
    // Expired test certificate alerts too.
    s.clientCertExpiry = () => new Date(T0).toUTCString();
    await s.checkCerts();
    assert.equal(h.sent.length, 3);
    assert.match(h.sent[2], /has EXPIRED/);
  } finally {
    h.done();
  }
});

test('alerts: bank server certificate is still checked when the latest run was mock-only', async () => {
  const h = setup();
  try {
    const s = h.make();
    const validTo = new Date(T0 + 5 * 86400_000).toUTCString();
    addRun(h.db, 'r1', T0 - 6 * 3600_000, [finding('sec.tls', { status: 'warn', severity: 'medium', endpoint: 'a.example', evidence: { validTo } })]);
    // Later 15:00 / 21:00 slots audit the mock only: no sec.tls for bank-a.
    addRun(h.db, 'r2', T0 - 3600_000, [], ['tbc-mock']);
    await s.checkCerts();
    assert.equal(h.sent.length, 1);
    assert.match(h.sent[0], /Bank A - certificate expires in 5 days/);
  } finally {
    h.done();
  }
});

test('alerts: latencyAlertMs overrides latencyP95Ms', async () => {
  const h = setup();
  try {
    const s = h.make();
    s.thresholds = () => ({ ...thresholds, alerts: { ...(thresholds as any).alerts, latencyAlertMs: 500 } }) as any;
    h.db.insertExchanges(null, [0, 1, 2, 3, 4].map((i) => sample(T0 - (20 - i) * MIN, 401, 700)));
    await s.checkLatency();
    assert.equal(h.sent.length, 1, '700 ms median > 500 ms alert threshold, though < latencyP95Ms 1000');
  } finally {
    h.done();
  }
});

test('alerts: one summary per finished audit; history before first start is skipped; restart does not repeat', async () => {
  const h = setup();
  try {
    const s = h.make();
    s.report = () => undefined;
    addRun(h.db, 'r1', T0 - 2 * 86400_000, [finding('sec.a')]);
    await s.checkFinishedRuns(); // first start: r1 is history
    assert.equal(h.sent.length, 0);
    addRun(h.db, 'r2', T0 - 86400_000, [finding('sec.a'), finding('sec.b')]);
    await s.checkFinishedRuns();
    await s.checkFinishedRuns();
    const s2 = h.make(new DbService());
    s2.report = () => undefined;
    await s2.checkFinishedRuns();
    assert.equal(h.sent.length, 1);
    assert.match(h.sent[0], /Scio: audit r2 finished - 1 target, 1 new high-severity/);
    const msg = h.db.recentAlerts()[0].message;
    assert.match(msg, /- bank-a: n\/a, 2 fail, 1 NEW high/);
    assert.equal(h.db.recentAlerts()[0].rule, 'audit-finished');
  } finally {
    h.done();
  }
});

test('alerts: one failing channel does not block the other', async () => {
  const h = setup();
  try {
    const s = h.make();
    const ok: string[] = [];
    s.channels = [
      { name: 'broken', send: async () => { throw new Error('smtp down'); } },
      { name: 'good', send: async (subject) => void ok.push(subject) },
    ];
    await s.notify('down', target.id, 'k', 'Scio: test', 'body');
    assert.equal(ok.length, 1);
    const row = h.db.recentAlerts()[0];
    assert.equal(row.channels, 'broken:failed,good:ok');
    assert.equal(row.ok, true);
  } finally {
    h.done();
  }
});
