import { Injectable, Logger, OnModuleDestroy, OnModuleInit, Optional } from '@nestjs/common';
import { loadCredentials } from '../common/credentials';
import { loadTargets, loadThresholds } from '../common/config';
import { loadStandardMap } from '../common/standards';
import { Finding, TargetConfig, Thresholds } from '../common/types';
import { isUp, TBILISI_OFFSET_MS } from '../monitor/uptime';
import { DbService } from '../storage/db.service';
import { ReportService } from '../reports/report.service';
import type { Report } from '../reports/report.service';
import { AlertChannel, channelsFromEnv, sendAll } from './channels';

export interface AlertsConfig {
  enabled?: boolean;
  pollSec?: number;
  latencyWindowMin?: number;
  /** Median (ms) of front-door samples in the window above which a target is "slow". Falls back to latencyP95Ms. */
  latencyAlertMs?: number;
  certRepeatDays?: number;
  rules?: { down?: boolean; latency?: boolean; newHighFindings?: boolean; certExpiry?: boolean; auditFinished?: boolean };
}

export type AlertRule = 'down' | 'recovered' | 'latency' | 'latency-ok' | 'new-high-findings' | 'cert-expiry' | 'audit-finished';

const MONITOR_OP = 'monitor.front-door';
const DAY_MS = 86400_000;

/** "23 Oct 2026 14:05 Tbilisi". Tbilisi has no daylight saving, so a fixed offset is exact. */
export function tbilisiTime(ms: number): string {
  const d = new Date(ms + TBILISI_OFFSET_MS);
  const mon = d.toLocaleString('en-GB', { month: 'short', timeZone: 'UTC' });
  return `${d.getUTCDate()} ${mon} ${d.getUTCFullYear()} ${d.toISOString().slice(11, 16)} Tbilisi`;
}

function duration(ms: number): string {
  const m = Math.max(1, Math.round(ms / 60_000));
  if (m < 60) return `${m} min`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h} h ${m % 60} min`;
  return `${Math.floor(h / 24)} d ${h % 24} h`;
}

function median(xs: number[]): number {
  const s = [...xs].sort((a, b) => a - b);
  const mid = Math.floor(s.length / 2);
  return s.length % 2 ? s[mid] : (s[mid - 1] + s[mid]) / 2;
}

/**
 * Telegram and email alerts. Polls the database every alerts.pollSec (no hooks into the monitor or audits):
 * target down / recovered, slow front door, new high-severity findings after a run, certificates close to expiry.
 * Per-rule state lives in alert_state so a restart does not re-alert; every alert is logged in alerts_sent.
 */
@Injectable()
export class AlertsService implements OnModuleInit, OnModuleDestroy {
  private readonly log = new Logger('Alerts');
  private timer?: NodeJS.Timeout;
  private busy = false;
  private lastCertCheck = 0;

  /** Overridable for tests: delivery channels, targets, thresholds and clock. */
  channels: AlertChannel[] = channelsFromEnv();
  targets: () => TargetConfig[] = () => loadTargets().filter((t) => !t.specOnly);
  thresholds: () => Thresholds & { alerts?: AlertsConfig } = () => loadThresholds() as Thresholds & { alerts?: AlertsConfig };
  now: () => number = () => Date.now();
  /** The team's test certificate expiry per target (read-only use of loadCredentials). */
  clientCertExpiry: (t: TargetConfig) => string | undefined = (t) => {
    if (!t.credentials) return undefined;
    const c = loadCredentials(t);
    return typeof c === 'string' ? undefined : c.certExpires;
  };

  /** Report of a finished run for the audit summary (overridable for tests). Undefined when it cannot be built. */
  report: (runId: string) => Report | undefined = (runId) => this.reports?.build(runId);

  constructor(
    private readonly db: DbService,
    @Optional() private readonly reports?: ReportService,
  ) {}

  private get cfg(): AlertsConfig {
    return this.thresholds().alerts ?? {};
  }

  get enabled(): boolean {
    return process.env.ALERTS_ENABLED !== 'false' && this.cfg.enabled !== false && this.channels.length > 0;
  }

  channelNames(): string[] {
    return this.channels.map((c) => c.name);
  }

  onModuleInit() {
    if (!this.enabled) {
      this.log.log(this.channels.length ? 'alerts off' : 'alerts off: no channel configured');
      return;
    }
    const every = Math.max(10, this.cfg.pollSec ?? 60) * 1000;
    this.timer = setInterval(() => void this.tick(), every);
    this.timer.unref();
    this.log.log(`alerts on (${this.channelNames().join(', ')}), every ${every / 1000} s`);
  }

  onModuleDestroy() {
    clearInterval(this.timer);
  }

  private async tick() {
    if (this.busy) return;
    this.busy = true;
    try {
      await this.evaluate();
    } finally {
      this.busy = false;
    }
  }

  /** Runs every enabled rule once. A failing rule is logged and does not stop the others. */
  async evaluate() {
    const rules = this.cfg.rules ?? {};
    const steps: [string, boolean | undefined, () => Promise<void>][] = [
      ['down', rules.down, () => this.checkDown()],
      ['latency', rules.latency, () => this.checkLatency()],
      ['newHighFindings', rules.newHighFindings, () => this.checkNewFindings()],
      ['auditFinished', rules.auditFinished, () => this.checkFinishedRuns()],
      ['certExpiry', rules.certExpiry, async () => {
        // Certificates change slowly: checked once a day (and at start-up); repeats are limited by certRepeatDays.
        if (this.now() - this.lastCertCheck < DAY_MS) return;
        this.lastCertCheck = this.now();
        await this.checkCerts();
      }],
    ];
    for (const [name, on, run] of steps) {
      if (on === false) continue;
      try {
        await run();
      } catch (e: any) {
        this.log.warn(`rule ${name} failed: ${e?.message ?? e}`);
      }
    }
  }

  private link(path: string): string {
    const base = (process.env.PUBLIC_URL ?? '').replace(/\/$/, '');
    return base ? `\n${base}${path}` : '';
  }

  /** Sends to every channel and logs the attempt. Never throws. */
  async notify(rule: AlertRule, targetId: string | undefined, key: string, subject: string, body: string) {
    const text = `${subject}\n${body}`.slice(0, 4000);
    const results = await sendAll(this.channels, subject, text);
    for (const r of results) if (!r.ok) this.log.warn(`${rule} ${key}: ${r.name} failed: ${r.error}`);
    try {
      this.db.insertAlert({
        ts: new Date(this.now()).toISOString(),
        rule,
        targetId,
        key,
        message: text,
        channels: results.map((r) => `${r.name}:${r.ok ? 'ok' : 'failed'}`).join(','),
        ok: results.some((r) => r.ok),
      });
    } catch (e: any) {
      this.log.warn(`could not log alert: ${e?.message ?? e}`);
    }
  }

  private intervalMin(t: TargetConfig): number {
    const m = this.thresholds().monitor ?? {};
    return t.simulated ? m.simulatedIntervalMin ?? 5 : m.realIntervalMin ?? 30;
  }

  /** Rule 1: the latest monitor sample decides (failures are already confirmed by a re-check in the monitor). */
  async checkDown() {
    for (const t of this.targets()) {
      const x = this.db.latestMonitorSample(t.id, MONITOR_OP);
      if (!x) continue;
      // An old sample (monitor stopped) says nothing about now.
      if (this.now() - Date.parse(x.ts) > Math.max(3 * this.intervalMin(t), 15) * 60_000) continue;
      const up = isUp(x.status, x.error);
      const key = `down:${t.id}`;
      const prev = this.db.alertState<{ down: boolean; since: string; reason?: string }>(key);
      if (!prev) {
        // First look at this target: an up target is recorded silently, a down one alerts.
        this.db.setAlertState(key, { down: !up, since: x.ts, reason: up ? undefined : x.error ?? `HTTP ${x.status}` });
        if (up) continue;
      } else if (prev.down === !up) continue;
      else this.db.setAlertState(key, { down: !up, since: x.ts, reason: up ? undefined : x.error ?? `HTTP ${x.status}` });

      if (!up) {
        const reason = x.error ?? `HTTP ${x.status}`;
        await this.notify('down', t.id, `${t.id}:${x.ts}`, `Scio: ${t.name} is DOWN`, `Since ${tbilisiTime(Date.parse(x.ts))}\nReason: ${reason}\nURL: ${x.url}${this.link('/uptime')}`);
      } else {
        const outage = prev ? Date.parse(x.ts) - Date.parse(prev.since) : 0;
        await this.notify('recovered', t.id, `${t.id}:${x.ts}`, `Scio: ${t.name} is back UP`, `Recovered ${tbilisiTime(Date.parse(x.ts))} after ${duration(outage)} down${prev?.reason ? ` (${prev.reason})` : ''}${this.link('/uptime')}`);
      }
    }
  }

  /**
   * Rule 2: slow when the median (p50) of HTTP-answered samples in the window exceeds alerts.latencyAlertMs (latencyP95Ms
   * when unset; a p95 needs >= 20 samples, about 100 min at a 5-min interval, too slow for an alert). The median ignores
   * one slow sample but catches a target that is slow most of the time; "all samples" would miss a slow API with one fast answer.
   */
  async checkLatency() {
    const th = this.thresholds();
    const windowMin = this.cfg.latencyWindowMin ?? 30;
    const limit = this.cfg.latencyAlertMs ?? th.latencyP95Ms;
    const since = new Date(this.now() - windowMin * 60_000).toISOString();
    for (const t of this.targets()) {
      const ms = this.db.monitorSamplesFor(t.id, MONITOR_OP, since).filter((x) => x.status > 0).map((x) => x.durationMs);
      if (ms.length < 5) continue;
      const p50 = Math.round(median(ms));
      const slow = p50 > limit;
      const key = `latency:${t.id}`;
      const prev = this.db.alertState<{ slow: boolean; since: string }>(key);
      if ((prev?.slow ?? false) === slow) continue;
      this.db.setAlertState(key, { slow, since: new Date(this.now()).toISOString() });
      const when = tbilisiTime(this.now());
      if (slow) await this.notify('latency', t.id, `${t.id}:${since}`, `Scio: ${t.name} is slow`, `Median response ${p50} ms over the last ${windowMin} min (${ms.length} samples), alert threshold ${limit} ms (median).\n${when}${this.link('/uptime')}`);
      else await this.notify('latency-ok', t.id, `${t.id}:${since}`, `Scio: ${t.name} latency back to normal`, `Median response ${p50} ms over the last ${windowMin} min, alert threshold ${limit} ms (median).\n${when}${this.link('/uptime')}`);
    }
  }

  /** Rule 3: high-severity failures absent from the previous finished run that included the same target. */
  async checkNewFindings() {
    const runs = this.db.doneRuns();
    const marker = this.db.alertState<string>('findings:lastRun');
    if (marker === undefined) {
      // First start: earlier runs are history, not news.
      this.db.setAlertState('findings:lastRun', runs[runs.length - 1]?.id ?? '');
      return;
    }
    const start = marker ? runs.findIndex((r) => r.id === marker) + 1 : 0;
    // A marker no longer in the database (runs cleared) means everything left was already seen.
    if (marker && start === 0) {
      this.db.setAlertState('findings:lastRun', runs[runs.length - 1]?.id ?? '');
      return;
    }
    const names = new Map(this.targets().map((t) => [t.id, t]));
    const map = loadStandardMap().checks;
    const high = (fs: Finding[], targetId: string) => fs.filter((f) => f.targetId === targetId && f.status === 'fail' && f.severity === 'high');
    const fkey = (f: Finding) => `${f.checkId}|${f.endpoint ?? ''}`;
    for (let i = start; i < runs.length; i++) {
      const run = runs[i];
      const findings = this.db.findings(run.id);
      for (const targetId of run.targets) {
        const prevRun = runs.slice(0, i).reverse().find((r) => r.targets.includes(targetId));
        // No earlier run of this target: nothing to compare with (its first audit is the baseline).
        if (!prevRun) continue;
        const before = new Set(high(this.db.findings(prevRun.id), targetId).map(fkey));
        const fresh = high(findings, targetId).filter((f) => !before.has(fkey(f)));
        if (!fresh.length) continue;
        const t = names.get(targetId);
        const lines = fresh.slice(0, 10).map((f) => {
          const clause = map[f.checkId]?.refs?.join('; ');
          return `- ${f.title}${f.endpoint ? ` (${f.endpoint})` : ''}${f.fix ? `\n  Fix: ${f.fix}` : ''}${clause ? `\n  Clause: ${clause}` : ''}`;
        });
        if (fresh.length > 10) lines.push(`- and ${fresh.length - 10} more`);
        await this.notify(
          'new-high-findings',
          targetId,
          `${run.id}:${targetId}`,
          `Scio: ${fresh.length} new high-severity finding${fresh.length > 1 ? 's' : ''} - ${t?.name ?? targetId}`,
          `Audit ${run.id} finished ${tbilisiTime(Date.parse(run.finishedAt ?? run.startedAt))}.\n${lines.join('\n')}${this.link('/findings')}`,
        );
      }
      this.db.setAlertState('findings:lastRun', run.id);
    }
  }

  /** High-severity failures of targetId in runs[i] that the previous finished run of the same target did not have. */
  private freshHigh(runs: ReturnType<DbService['doneRuns']>, i: number, targetId: string, findings: Finding[]): Finding[] | undefined {
    const prevRun = runs.slice(0, i).reverse().find((r) => r.targets.includes(targetId));
    if (!prevRun) return undefined;
    const high = (fs: Finding[]) => fs.filter((f) => f.targetId === targetId && f.status === 'fail' && f.severity === 'high');
    const fkey = (f: Finding) => `${f.checkId}|${f.endpoint ?? ''}`;
    const before = new Set(high(this.db.findings(prevRun.id)).map(fkey));
    return high(findings).filter((f) => !before.has(fkey(f)));
  }

  /**
   * Rule 5: one summary per finished audit (scheduled or CLI): targets, overall and like-for-like scores with check
   * counts, failures, new high-severity failures per bank. Runs finished before the first start are history, not news.
   */
  async checkFinishedRuns() {
    const runs = this.db.doneRuns();
    const marker = this.db.alertState<string>('finished:lastRun');
    if (marker === undefined) {
      this.db.setAlertState('finished:lastRun', runs[runs.length - 1]?.id ?? '');
      return;
    }
    const start = marker ? runs.findIndex((r) => r.id === marker) + 1 : 0;
    if (marker && start === 0) {
      this.db.setAlertState('finished:lastRun', runs[runs.length - 1]?.id ?? '');
      return;
    }
    for (let i = start; i < runs.length; i++) {
      const run = runs[i];
      let rep: Report | undefined;
      try {
        rep = this.report(run.id);
      } catch (e: any) {
        this.log.warn(`audit summary ${run.id}: report failed: ${e?.message ?? e}`);
      }
      const findings = this.db.findings(run.id);
      const lines: string[] = [];
      let newHighTotal = 0;
      for (const targetId of run.targets) {
        const t = rep?.targets.find((x) => x.id === targetId);
        const fresh = this.freshHigh(runs, i, targetId, findings);
        newHighTotal += fresh?.length ?? 0;
        const fails = findings.filter((f) => f.targetId === targetId && f.status === 'fail' && f.source !== 'ai').length;
        const score = t ? (t.overall !== null ? `${t.overall} on ${t.evaluated} checks` : `no score (${t.evaluated} checks)`) : 'n/a';
        const lfl = rep?.common && targetId in rep.common.scores ? `, like-for-like ${rep.common.scores[targetId]}` : '';
        const nh = fresh === undefined ? ' (first audit: baseline)' : fresh.length ? `, ${fresh.length} NEW high` : '';
        lines.push(`- ${t?.name ?? targetId}${t ? ` [${t.access}]` : ''}: ${score}${lfl}, ${fails} fail${nh}`);
      }
      const when = tbilisiTime(Date.parse(run.finishedAt ?? run.startedAt));
      const th = rep ? `\nThresholds: ${rep.thresholds.source}${rep.thresholds.source === 'assumed' ? ' (assumptions until NBG publishes indicators)' : ''}.` : '';
      await this.notify(
        'audit-finished',
        undefined,
        run.id,
        `Scio: audit ${run.id} finished - ${run.targets.length} target${run.targets.length === 1 ? '' : 's'}${newHighTotal ? `, ${newHighTotal} new high-severity` : ''}`,
        `Finished ${when}${run.source ? ` (${run.source})` : ''}.\n${lines.join('\n')}${th}${this.link('/')}`,
      );
      this.db.setAlertState('finished:lastRun', run.id);
    }
  }

  /** Rule 4: bank server certificates (latest run's sec.tls evidence) and the team's test certificates. */
  async checkCerts() {
    const warnDays = this.thresholds().certExpiryWarnDays ?? 30;
    const repeatMs = (this.cfg.certRepeatDays ?? 7) * DAY_MS;
    const targets = this.targets();
    const byId = new Map(targets.map((t) => [t.id, t]));
    const certs: { targetId: string; kind: string; what: string; validTo: string }[] = [];
    // Latest sec.tls evidence per target, from the newest run that has it: mock-only slots (15:00, 21:00) carry no
    // real-bank TLS findings, so "the latest run" alone would hide real banks' server certificates most of the day.
    const runs = this.db.doneRuns();
    const seen = new Set<string>();
    for (let i = runs.length - 1; i >= 0 && seen.size < targets.length; i--) {
      const found = new Set<string>();
      for (const f of this.db.findings(runs[i].id)) {
        const validTo = (f.evidence as any)?.validTo;
        if (f.checkId !== 'sec.tls' || typeof validTo !== 'string' || seen.has(f.targetId) || !byId.has(f.targetId)) continue;
        certs.push({ targetId: f.targetId, kind: 'server', what: `Server certificate of ${f.endpoint ?? 'the API host'}`, validTo });
        found.add(f.targetId);
      }
      for (const id of found) seen.add(id);
    }
    for (const t of targets) {
      const validTo = this.clientCertExpiry(t);
      if (validTo) certs.push({ targetId: t.id, kind: 'client', what: 'Our test certificate', validTo });
    }
    for (const c of certs) {
      const exp = Date.parse(c.validTo);
      if (!Number.isFinite(exp)) continue;
      const daysLeft = Math.floor((exp - this.now()) / DAY_MS);
      if (daysLeft > warnDays) continue;
      const key = `${c.kind}:${c.targetId}:${c.what}:${c.validTo}`;
      const last = this.db.lastAlertAt('cert-expiry', key);
      if (last && this.now() - Date.parse(last) < repeatMs) continue;
      const name = byId.get(c.targetId)?.name ?? c.targetId;
      const state = exp <= this.now() ? 'has EXPIRED' : `expires in ${daysLeft} day${daysLeft === 1 ? '' : 's'}`;
      await this.notify('cert-expiry', c.targetId, key, `Scio: ${name} - certificate ${state}`, `${c.what} ${state}: valid until ${tbilisiTime(exp)}.${this.link('/banks')}`);
    }
  }
}
