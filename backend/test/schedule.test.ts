import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DEFAULT_SLOTS, describeSchedule, resolveSchedule, tbilisiDayStart } from '../src/audit/audit.service';
import { fmtTbilisi } from '../src/reports/report.html';

// Required lazily, like unit.test.ts, so the Nest decorators load only here.
const { AuditScheduler } = require('../src/audit/audit.scheduler');
const TBILISI = 4 * 3600_000;
const iso = (ms: number) => new Date(ms).toISOString();

test('schedule: next slot in Tbilisi time (09:00 = 05:00 UTC), across midnight', () => {
  // 04:30 UTC = 08:30 Tbilisi: next is 09:00 all targets.
  let n = AuditScheduler.nextSlot(DEFAULT_SLOTS, Date.parse('2026-10-22T04:30:00Z'), TBILISI);
  assert.equal(iso(n.at), '2026-10-22T05:00:00.000Z');
  assert.equal(n.slot.targets, 'all');
  // Exactly at 15:00 Tbilisi: that slot is not "next" any more, 21:00 is.
  n = AuditScheduler.nextSlot(DEFAULT_SLOTS, Date.parse('2026-10-22T11:00:00Z'), TBILISI);
  assert.equal(iso(n.at), '2026-10-22T17:00:00.000Z');
  assert.equal(n.slot.targets, 'all');
  // 22:00 Tbilisi: next is tomorrow's 09:00.
  n = AuditScheduler.nextSlot(DEFAULT_SLOTS, Date.parse('2026-10-22T18:00:00Z'), TBILISI);
  assert.equal(iso(n.at), '2026-10-23T05:00:00.000Z');
  // 21:30 UTC is already 01:30 on the 23rd in Tbilisi: still that morning's 09:00.
  n = AuditScheduler.nextSlot(DEFAULT_SLOTS, Date.parse('2026-10-22T21:30:00Z'), TBILISI);
  assert.equal(iso(n.at), '2026-10-23T05:00:00.000Z');
});

test('schedule: Tbilisi day starts at 20:00 UTC the day before', () => {
  assert.equal(iso(tbilisiDayStart(Date.parse('2026-10-22T19:59:00Z'))), '2026-10-21T20:00:00.000Z');
  assert.equal(iso(tbilisiDayStart(Date.parse('2026-10-22T20:00:00Z'))), '2026-10-22T20:00:00.000Z');
  assert.equal(fmtTbilisi('2026-10-22T20:00:00Z'), '23 Oct 2026, 00:00 GET (UTC+4)');
});

test('schedule: "all" slots audit every target each time, "simulated" slots the mock only', () => {
  const targets = [{ id: 'tbc-mock', simulated: true }, { id: 'bog' }, { id: 'tbc', simulated: false }];
  assert.deepEqual(AuditScheduler.slotTargets({ time: '09:00', targets: 'all' }, targets), ['tbc-mock', 'bog', 'tbc']);
  // Every default slot is "all", so 15:00 and 21:00 audit the real banks too, whatever ran earlier that day.
  for (const slot of DEFAULT_SLOTS) assert.deepEqual(AuditScheduler.slotTargets(slot, targets), ['tbc-mock', 'bog', 'tbc']);
  assert.deepEqual(AuditScheduler.slotTargets({ time: '15:00', targets: 'simulated' }, targets), ['tbc-mock']);
  assert.deepEqual(AuditScheduler.slotTargets({ time: '21:00', targets: 'simulated' }, [{ id: 'bog' }]), []);
});

test('schedule: catch-up runs the most recent passed slot once, only if nothing started since', () => {
  const seen: string[] = [];
  const none = (since: string) => (seen.push(since), 0);
  // 16:00 Tbilisi: the 15:00 slot is due, checked since 15:00 Tbilisi.
  let due = AuditScheduler.catchUp(DEFAULT_SLOTS, Date.parse('2026-10-22T12:00:00Z'), TBILISI, none);
  assert.equal(due.slot.time, '15:00');
  assert.equal(seen.pop(), '2026-10-22T11:00:00.000Z');
  // A run started after 15:00: nothing to catch up.
  assert.equal(AuditScheduler.catchUp(DEFAULT_SLOTS, Date.parse('2026-10-22T12:00:00Z'), TBILISI, () => 1), null);
  // 01:00 Tbilisi (21:00 UTC the day before): no slot has passed today yet, so yesterday's 21:00 is not caught up.
  assert.equal(AuditScheduler.catchUp(DEFAULT_SLOTS, Date.parse('2026-10-22T21:00:00Z'), TBILISI, none), null);
  // 23:59 Tbilisi: the 21:00 slot.
  due = AuditScheduler.catchUp(DEFAULT_SLOTS, Date.parse('2026-10-22T19:59:00Z'), TBILISI, none);
  assert.equal(due.slot.time, '21:00');
});

test('schedule: config with slots, legacy timeTashkent, defaults', () => {
  const c = resolveSchedule({ timezone: 'Asia/Tbilisi', slots: [{ time: '10:00', targets: 'simulated' }, { time: '25:00' }] });
  assert.equal(c.legacy, false);
  assert.deepEqual(c.slots, [{ time: '10:00', targets: 'simulated' }]);
  assert.equal(c.offsetMs, TBILISI);
  // No slots but timeTashkent: one daily audit of all targets at that Tashkent time, as before.
  const l = resolveSchedule({ timeTashkent: '06:00' });
  assert.equal(l.legacy, true);
  assert.equal(l.timezone, 'Asia/Tashkent');
  assert.deepEqual(l.slots, [{ time: '06:00', targets: 'all' }]);
  assert.deepEqual(resolveSchedule({}).slots, DEFAULT_SLOTS);
  assert.equal(describeSchedule({}), '09:00 (all targets), 15:00 (all targets), 21:00 (all targets) Tbilisi time');
});
