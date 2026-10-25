import { Injectable, Logger, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { loadThresholds } from '../common/config';
import { DbService } from '../storage/db.service';
import { fmtTbilisi } from '../reports/report.html';
import { AuditService, ScheduleSlot, resolveSchedule } from './audit.service';

const TASHKENT_OFFSET_MS = 5 * 3600_000; // UTC+5, no daylight saving

export interface ScheduleInfo {
  enabled: boolean;
  /** HH:MM of the first slot (kept for older clients; see slots). */
  time: string;
  timezone: string;
  nextAt: string | null;
  /** Whether audits may also be started from the dashboard/API (otherwise schedule + CLI only). */
  manualRuns: boolean;
  /** All daily slots, HH:MM in `timezone`. */
  slots: ScheduleSlot[];
  /** The slot that runs next (at = ISO UTC). */
  next: (ScheduleSlot & { at: string }) | null;
}

/** A slot on a given day, as a UTC timestamp. */
export interface SlotAt {
  slot: ScheduleSlot;
  at: number;
}

/**
 * Automated audits at the schedule slots (default 09:00, 15:00 and 21:00 Tbilisi time, all targets each time).
 * A slot's targets come from the slot alone: "all" audits every target, real banks included, whatever ran earlier that day
 * (CLI test runs no longer turn a scheduled audit into a mock-only one). "simulated" slots audit the organizers' mock only.
 * If the server was down at today's most recent slot and no audit started since that slot's time, that slot runs shortly after start-up.
 * Legacy config (schedule.timeTashkent without slots): one daily audit of every target at that Tashkent time, as before.
 * Disable with AUDIT_SCHEDULE_ENABLED=false (the CLI does this for itself).
 */
@Injectable()
export class AuditScheduler implements OnModuleInit, OnModuleDestroy {
  private readonly log = new Logger('Schedule');
  private timer?: NodeJS.Timeout;
  private next: SlotAt | null = null;

  constructor(
    private readonly audit: AuditService,
    private readonly db: DbService,
  ) {}

  private config() {
    const s = loadThresholds().schedule;
    return { ...resolveSchedule(s), enabled: process.env.AUDIT_SCHEDULE_ENABLED !== 'false' && s?.enabled !== false };
  }

  info(): ScheduleInfo {
    const c = this.config();
    const next = c.enabled && this.next ? { ...this.next.slot, at: new Date(this.next.at).toISOString() } : null;
    return { enabled: c.enabled, time: c.slots[0].time, timezone: c.timezone, nextAt: next?.at ?? null, manualRuns: c.manualRuns, slots: c.slots, next };
  }

  /** Next occurrence of HH:MM local time after `from` (default offset: Tashkent, the legacy schedule). */
  static nextRun(time: string, from = Date.now(), offsetMs = TASHKENT_OFFSET_MS): number {
    const [h, m] = time.split(':').map(Number);
    const local = from + offsetMs;
    const dayStartLocal = Math.floor(local / 86400_000) * 86400_000;
    let at = dayStartLocal + (h * 60 + m) * 60_000 - offsetMs;
    if (at <= from) at += 86400_000;
    return at;
  }

  /** The earliest slot strictly after `from`. */
  static nextSlot(slots: ScheduleSlot[], from: number, offsetMs: number): SlotAt {
    return slots.map((slot) => ({ slot, at: AuditScheduler.nextRun(slot.time, from, offsetMs) })).reduce((a, b) => (b.at < a.at ? b : a));
  }

  /** Today's most recent slot that has already passed (local day of `now`), or null if none has yet. */
  static latestSlotToday(slots: ScheduleSlot[], now: number, offsetMs: number): SlotAt | null {
    const dayStart = Math.floor((now + offsetMs) / 86400_000) * 86400_000 - offsetMs;
    const passed = slots.map((slot) => ({ slot, at: AuditScheduler.nextRun(slot.time, dayStart - 1, offsetMs) })).filter((s) => s.at <= now);
    return passed.length ? passed.reduce((a, b) => (b.at > a.at ? b : a)) : null;
  }

  /**
   * Catch-up after a restart: today's most recent passed slot, if no run started since `sinceOf(slot)`.
   * Any run counts, failed or interrupted ones too, so a failing audit is not repeated on every restart.
   */
  static catchUp(slots: ScheduleSlot[], now: number, offsetMs: number, runsSince: (iso: string) => number, sinceOf = (s: SlotAt) => s.at): SlotAt | null {
    const last = AuditScheduler.latestSlotToday(slots, now, offsetMs);
    return last && runsSince(new Date(sinceOf(last)).toISOString()) === 0 ? last : null;
  }

  /**
   * Target ids for a slot. "simulated": the mock only. "all": every target, real banks included.
   * Empty means nothing to run.
   */
  static slotTargets(slot: ScheduleSlot, targets: { id: string; simulated?: boolean }[]): string[] {
    const onlySimulated = slot.targets === 'simulated';
    return targets.filter((t) => !onlySimulated || t.simulated).map((t) => t.id);
  }

  onModuleInit() {
    const c = this.config();
    if (!c.enabled) return;
    // Catch up: today's most recent slot has passed and nothing started since (e.g. the server was down at that time).
    // Legacy schedule: any run started today counts, as before.
    const due = AuditScheduler.catchUp(c.slots, Date.now(), c.offsetMs, (iso) => this.db.countRunsSince(iso, { includeFailed: true }), c.legacy ? (s) => Math.floor((s.at + c.offsetMs) / 86400_000) * 86400_000 - c.offsetMs : undefined);
    if (due) {
      const t = setTimeout(() => this.fire(due.slot, 'catch-up'), 60_000);
      t.unref();
    }
    this.arm();
  }

  onModuleDestroy() {
    if (this.timer) clearTimeout(this.timer);
  }

  private arm() {
    const c = this.config();
    // Never re-arm the slot that just fired, even if the timer woke a moment early.
    const next = AuditScheduler.nextSlot(c.slots, Math.max(Date.now(), this.next?.at ?? 0), c.offsetMs);
    this.next = next;
    this.timer = setTimeout(() => {
      this.fire(next.slot, 'scheduled');
      this.arm();
    }, next.at - Date.now());
    this.timer.unref();
    this.log.log(`next audit at ${fmtTbilisi(new Date(next.at).toISOString())} (${next.slot.time} ${c.legacy ? 'Tashkent' : 'Tbilisi'}, ${next.slot.targets} targets)`);
  }

  private fire(slot: ScheduleSlot, reason: string) {
    try {
      let ids: string[] | undefined;
      if (!this.config().legacy) {
        const targets = this.audit.targets();
        ids = AuditScheduler.slotTargets(slot, targets);
        if (!ids.length) {
          this.log.warn(`${reason} audit (${slot.time}) skipped: no targets to run`);
          return;
        }
      }
      const run = this.audit.start(ids, 'schedule');
      this.log.log(`${reason} audit (${slot.time}) started: ${run.id} (${run.targets.join(', ')})`);
    } catch (e: any) {
      // e.g. an audit is already running or real banks were probed too recently: skip this slot, the next one is armed.
      this.log.warn(`${reason} audit (${slot.time}) skipped: ${e?.message ?? e}`);
    }
  }
}
