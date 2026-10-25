import { test } from 'node:test';
import assert from 'node:assert/strict';
import { aggregate } from '../src/monitor/uptime';
import { hourCell, MONITOR_OPS, profileRows } from '../src/monitor/latency-profile';
import { authenticatedTarget } from '../src/monitor/ais-probe';
import { Exchange, TargetConfig } from '../src/common/types';

const mk = (ts: string, operation: string, durationMs = 100, status = 200, error?: string): Exchange => ({ targetId: 't', operation, method: 'GET', url: 'u', status, ok: status > 0 && status < 500, durationMs, error, requestHeaders: {}, responseHeaders: {}, bodySnippet: '', ts });

test('latency profile: buckets by Tbilisi hour across midnight UTC', () => {
  const xs = [
    mk('2026-10-21T19:30:00Z', MONITOR_OPS.frontDoor, 100), // 23:30 Tbilisi
    mk('2026-10-21T20:10:00Z', MONITOR_OPS.frontDoor, 200), // 00:10 Tbilisi, next day
    mk('2026-10-21T23:55:00Z', MONITOR_OPS.frontDoor, 300), // 03:55 Tbilisi
    mk('2026-10-22T00:05:00Z', MONITOR_OPS.frontDoor, 400), // 04:05 Tbilisi (UTC date changed)
  ];
  const [row] = profileRows(xs);
  assert.equal(row.operation, MONITOR_OPS.frontDoor);
  assert.equal(row.hours.length, 24);
  assert.equal(row.hours[23].samples, 1);
  assert.equal(row.hours[0].p50, 200);
  assert.equal(row.hours[3].p50, 300);
  assert.equal(row.hours[4].p50, 400);
  assert.equal(row.hours.reduce((n, h) => n + h.samples, 0), 4);
});

test('latency profile: p50 and p95 with few samples; latency only from HTTP answers, up% from all', () => {
  const at = '2026-10-21T05:00:00Z';
  const one = hourCell(9, [mk(at, MONITOR_OPS.accounts, 150)]);
  assert.equal(one.p50, 150);
  assert.equal(one.p95, null); // fewer than 3 answers: no p95
  const three = hourCell(9, [mk(at, MONITOR_OPS.accounts, 300), mk(at, MONITOR_OPS.accounts, 100), mk(at, MONITOR_OPS.accounts, 200)]);
  assert.equal(three.p50, 200);
  assert.equal(three.p95, 300);
  const mixed = hourCell(9, [mk(at, MONITOR_OPS.accounts, 100), mk(at, MONITOR_OPS.accounts, 15000, 0, 'timeout'), mk(at, MONITOR_OPS.accounts, 120, 503)]);
  assert.equal(mixed.samples, 3);
  assert.equal(mixed.httpSamples, 2);
  assert.equal(mixed.p50, 100);
  assert.equal(mixed.upPct, 33.33);
  assert.deepEqual(hourCell(0, []), { hour: 0, samples: 0, httpSamples: 0, p50: null, p95: null, upPct: null });
});

test('latency profile: setup calls are excluded; authenticated rows only when sampled', () => {
  const at = '2026-10-21T11:00:00Z'; // 15:00 Tbilisi
  const rows = profileRows([mk(at, MONITOR_OPS.setup, 5000), mk(at, MONITOR_OPS.balances, 80)]);
  assert.deepEqual(rows.map((r) => r.operation), [MONITOR_OPS.frontDoor, MONITOR_OPS.balances]);
  assert.equal(rows[0].hours[15].samples, 0);
  assert.equal(rows[1].hours[15].p50, 80);
  assert.equal(profileRows([mk(at, MONITOR_OPS.setup)]).length, 1); // front door only
});

test('front-door uptime is unaffected by authenticated monitor samples', () => {
  const now = Date.parse('2026-10-22T00:00:00Z');
  const door = [mk('2026-10-21T10:00:00Z', MONITOR_OPS.frontDoor, 100, 401), mk('2026-10-21T10:05:00Z', MONITOR_OPS.frontDoor, 100, 401)];
  const ais = [mk('2026-10-21T10:01:00Z', MONITOR_OPS.setup, 900, 503), mk('2026-10-21T10:02:00Z', MONITOR_OPS.accounts, 100, 503), mk('2026-10-21T10:03:00Z', MONITOR_OPS.transactions, 100, 0, 'timeout')];
  const mixed = [...door, ...ais].sort((a, b) => a.ts.localeCompare(b.ts));
  assert.deepEqual(aggregate('t', 5, mixed, now), aggregate('t', 5, door, now));
  assert.equal(aggregate('t', 5, mixed, now).daily[0].uptimePct, 100);
});

test('authenticated probes only on simulated full-mode targets', () => {
  const t = (p: Partial<TargetConfig>): TargetConfig => ({ id: 'x', name: 'x', bank: 'x', mode: 'full', simulated: true, baseUrl: 'https://x', ...p });
  assert.equal(authenticatedTarget(t({})), true);
  assert.equal(authenticatedTarget(t({ simulated: false })), false);
  assert.equal(authenticatedTarget(t({ mode: 'passive' })), false);
  assert.equal(authenticatedTarget(t({ specOnly: true })), false);
});

test('monitor: latency over the last 24 h uses answered HTTP samples only, p95 from 20 samples', () => {
  const now = Date.parse('2026-10-24T12:00:00Z');
  const at = (minAgo: number) => new Date(now - minAgo * 60_000).toISOString();
  // 25 answered samples in the last 24 h (100..340 ms), one TLS-only answer, one 503, and one sample older than 24 h.
  const xs = [
    mk(at(26 * 60), 'monitor.front-door', 9999),
    ...Array.from({ length: 25 }, (_, i) => mk(at(25 - i), 'monitor.front-door', 100 + i * 10)),
    mk(at(0.5), 'monitor.front-door', 50, 0, 'certificate required'),
    mk(at(0.2), 'monitor.front-door', 8000, 503),
  ];
  const l = aggregate('t', 5, xs, now).latency24h;
  assert.equal(l.samples, 25);
  assert.equal(l.p50, 220);
  assert.ok(l.p95 !== null && l.p95 >= 320 && l.p95 <= 340);
  // Fewer than 20 samples: median only.
  assert.equal(aggregate('t', 5, xs.slice(0, 10), now).latency24h.p95, null);
});
