import { ConflictException, ForbiddenException, HttpException, HttpStatus, Injectable, Logger } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { HttpRecorder } from '../common/http';
import { loadTargets, loadThresholds } from '../common/config';
import { Finding, RunSummary, TargetConfig, Thresholds } from '../common/types';
import { AuditContext } from '../checks/context';
import { runStaticSpecChecks } from '../checks/static-spec.checks';
import { runLiveConformance } from '../checks/live-conformance.checks';
import { runActiveSecurity } from '../checks/security.checks';
import { runDataChecks } from '../checks/data.checks';
import { runProbes } from '../checks/performance.checks';
import { runPassive } from '../checks/passive.checks';
import { runPis } from '../checks/pis.checks';
import { runLoans } from '../checks/loans.checks';
import { runFullFlow } from '../flows/full.flow';
import { runSandboxFlow } from '../flows/sandbox.flow';
import { runBisFlow } from '../flows/bis.flow';
import { loadCredentials } from '../common/credentials';
import { Spec } from '../spec/spec';
import { DbService } from '../storage/db.service';
import { JevClient } from '../ai/jev.client';
import { runAi } from '../ai/ai.checks';
import { qvac } from '../ai/qvac.engine';
import { clusterFindings, generateTests, summarize } from '../ai/qvac.checks';
import { fmtTbilisi } from '../reports/report.html';

/** A run still 'running' after this long is treated as abandoned (e.g. a killed CLI) and no longer blocks new runs. */
const RUNNING_STALE_MS = 2 * 3600_000;
const staleBefore = () => new Date(Date.now() - RUNNING_STALE_MS).toISOString();

const TBILISI_OFFSET_MS = 4 * 3600_000; // UTC+4, no daylight saving
const OFFSETS: Record<string, number> = { 'Asia/Tbilisi': TBILISI_OFFSET_MS, 'Asia/Tashkent': 5 * 3600_000 };

/** Start of the Tbilisi calendar day containing `now` (UTC ms). */
export const tbilisiDayStart = (now = Date.now()) => Math.floor((now + TBILISI_OFFSET_MS) / 86400_000) * 86400_000 - TBILISI_OFFSET_MS;

/** One daily schedule slot: HH:MM local time; "all" targets or the "simulated" ones (the organizers' mock) only. */
export interface ScheduleSlot {
  time: string;
  targets: 'all' | 'simulated';
}

export const DEFAULT_SLOTS: ScheduleSlot[] = [
  { time: '09:00', targets: 'all' },
  { time: '15:00', targets: 'all' },
  { time: '21:00', targets: 'all' },
];

/**
 * Schedule config (thresholds.json "schedule") with defaults. Shared with AuditScheduler, which imports this file
 * (the scheduler file imports AuditService, so the helpers live here to avoid a circular import).
 * Legacy: no slots but timeTashkent set means one daily audit of every target at that Tashkent time.
 */
export function resolveSchedule(s: Thresholds['schedule'] = {}) {
  const valid = (t?: string) => /^([01]\d|2[0-3]):[0-5]\d$/.test(t ?? '');
  const manualRuns = s.manualRuns === true;
  if (!s.slots?.length && valid(s.timeTashkent))
    return { legacy: true, timezone: 'Asia/Tashkent', offsetMs: OFFSETS['Asia/Tashkent'], slots: [{ time: s.timeTashkent!, targets: 'all' as const }], manualRuns };
  const slots = (s.slots ?? []).filter((x) => valid(x.time)).map((x): ScheduleSlot => ({ time: x.time, targets: x.targets === 'simulated' ? 'simulated' : 'all' }));
  const timezone = s.timezone && OFFSETS[s.timezone] !== undefined ? s.timezone : 'Asia/Tbilisi';
  return { legacy: false, timezone, offsetMs: OFFSETS[timezone], slots: slots.length ? slots : DEFAULT_SLOTS, manualRuns };
}

/** e.g. "09:00 (all targets), 15:00 (all targets), 21:00 (all targets) Tbilisi time"; a "simulated" slot reads "mock only". */
export function describeSchedule(s?: Thresholds['schedule']) {
  const r = resolveSchedule(s);
  return `${r.slots.map((x) => `${x.time} (${x.targets === 'all' ? 'all targets' : 'mock only'})`).join(', ')} ${r.timezone === 'Asia/Tashkent' ? 'Tashkent' : 'Tbilisi'} time`;
}

/**
 * One informational finding per target with a published spec: which other targets publish the very same template
 * (the same set of operations, method and path). Shared templates explain identical findings across banks, and one
 * fix to the template repairs every bank that uses it. Not scored: a shared vendor template is no deviation by itself.
 */
export function sharedSpecTemplates(specOps: Map<string, string[]>, targets: { id: string; name: string; bank?: string }[]): Finding[] {
  const key = (ops: string[]) => ops.join('\n');
  const groups = new Map<string, string[]>();
  for (const [id, ops] of specOps) if (ops.length) groups.set(key(ops), [...(groups.get(key(ops)) ?? []), id]);
  const label = (id: string) => {
    const t = targets.find((x) => x.id === id);
    return t?.bank ?? t?.name ?? id;
  };
  const out: Finding[] = [];
  for (const [id, ops] of specOps) {
    if (!ops.length) continue;
    const others = (groups.get(key(ops)) ?? []).filter((x) => x !== id && label(x) !== label(id));
    out.push({
      targetId: id,
      checkId: 'spec.shared-template',
      layer: 'conformance',
      status: 'info',
      severity: 'none',
      title: 'Published spec shared with other banks',
      message: others.length
        ? `Same OpenAPI template as ${others.map(label).join(', ')}: all ${ops.length} operations identical. Identical findings across these banks come from one template, and one fix to it repairs all of them.`
        : `No other audited bank publishes this template (${ops.length} operations).`,
      actual: others.length ? `${ops.length} identical operations; shared with ${others.map(label).join(', ')}` : `${ops.length} operations, unique`,
      evidence: { operations: ops.length, sharedWith: others },
    });
  }
  return out;
}

@Injectable()
export class AuditService {
  private readonly log = new Logger(AuditService.name);
  private running = new Set<string>();

  readonly jev = new JevClient();

  constructor(private readonly db: DbService) {}

  targets(): TargetConfig[] {
    return loadTargets();
  }

  isRunning(): boolean {
    return this.running.size > 0 || !!this.db.runningSince(staleBefore());
  }

  /**
   * Daily quota for dashboard/API runs (resources: real-bank probes, AI calls, local model time).
   * Days are Tbilisi calendar days (UTC+4, no daylight saving). Counted from the database, so a restart does not reset it.
   */
  quota(): { limit: number; used: number; remaining: number | null; resetsAt: string; timezone: string } {
    const limit = loadThresholds().maxRunsPerDay ?? 0;
    const dayStart = tbilisiDayStart();
    const used = this.db.countRunsSince(new Date(dayStart).toISOString(), { source: 'api' });
    return { limit, used, remaining: limit > 0 ? Math.max(0, limit - used) : null, resetsAt: new Date(dayStart + 86400_000).toISOString(), timezone: 'Asia/Tbilisi' };
  }

  /** Starts a run and returns immediately; poll the run for status. `cli` and `schedule` runs skip the daily quota and are not counted in it. */
  start(targetIds?: string[], source: 'api' | 'cli' | 'schedule' = 'api'): RunSummary {
    const all = loadTargets();
    const targets = targetIds?.length ? all.filter((t) => targetIds.includes(t.id)) : all;
    const thresholds = loadThresholds();
    // Guardrails: one audit at a time, and a minimum gap between runs that probe real banks.
    // Both are read from the database, so they also hold between the server and the CLI (a second process).
    if (this.running.size || this.db.runningSince(staleBefore())) throw new ConflictException('An audit is already running. Wait for it to finish.');
    if (source === 'api' && thresholds.schedule?.manualRuns !== true)
      throw new ForbiddenException(`Audits run automatically every day at ${describeSchedule(thresholds.schedule)}. Manual runs are switched off (schedule.manualRuns).`);
    if (source === 'api') {
      const q = this.quota();
      if (q.remaining === 0)
        throw new HttpException(`Daily limit reached: ${q.limit} audit${q.limit === 1 ? '' : 's'} per day. Next one possible after midnight Tbilisi time (${fmtTbilisi(q.resetsAt)}). Earlier results stay available under Runs.`, HttpStatus.TOO_MANY_REQUESTS);
    }
    const touchesReal = targets.some((t) => !t.simulated);
    const gapMs = (thresholds.minRunIntervalSec ?? 60) * 1000;
    // Guardrail: real banks are never hammered. Last start time of a run that touched a non-simulated target
    // (from the database; a target no longer in the config counts as real).
    const simulated = new Set(all.filter((t) => t.simulated).map((t) => t.id));
    const lastReal = this.db.runsStartedSince(new Date(Date.now() - gapMs).toISOString()).find((r) => r.targets.some((id) => !simulated.has(id)));
    const wait = lastReal ? Date.parse(lastReal.startedAt) + gapMs - Date.now() : 0;
    if (touchesReal && wait > 0)
      throw new HttpException(`Real bank endpoints were probed less than ${thresholds.minRunIntervalSec ?? 60} s ago. Retry in ${Math.ceil(wait / 1000)} s.`, HttpStatus.TOO_MANY_REQUESTS);
    const run: RunSummary = {
      id: new Date().toISOString().replace(/[-:]/g, '').replace(/\..+/, '') + '-' + randomUUID().slice(0, 6),
      startedAt: new Date().toISOString(),
      status: 'running',
      targets: targets.map((t) => t.id),
      thresholdsSource: thresholds.source,
      source,
    };
    // Checked again inside the insert transaction: another process may have started a run since the check above.
    if (this.db.createRunIfIdle(run, staleBefore())) throw new ConflictException('An audit is already running. Wait for it to finish.');
    this.running.add(run.id);
    this.execute(run, targets)
      .then(() => this.db.finishRun(run.id, 'done'))
      .catch((e) => {
        this.log.error(e?.stack ?? e);
        this.db.finishRun(run.id, 'failed', String(e?.message ?? e));
      })
      .finally(() => this.running.delete(run.id));
    return run;
  }

  /** Runs to completion (used by the CLI). */
  async runToCompletion(targetIds?: string[], onProgress?: (msg: string) => void): Promise<RunSummary> {
    const run = this.start(targetIds, 'cli');
    while (this.running.has(run.id)) await new Promise((r) => setTimeout(r, 500));
    onProgress?.('done');
    return this.db.getRun(run.id)!;
  }

  private async execute(run: RunSummary, targets: TargetConfig[]) {
    const thresholds = loadThresholds();
    // Targets run in parallel: they are different hosts.
    const all: Finding[] = [];
    // Published spec of each target as its set of operations, compared across targets once all have run.
    const specOps = new Map<string, string[]>();
    await Promise.all(
      targets.map(async (target) => {
        const http = new HttpRecorder(target.id, thresholds.requestTimeoutMs);
        const ctx = new AuditContext(target, http, thresholds);
        try {
          this.log.log(`[${run.id}] ${target.id}: start (${target.mode})`);
          if (target.mode === 'full') {
            ctx.spec = await Spec.load(target, http);
            runStaticSpecChecks(ctx);
            await runFullFlow(ctx);
            // PIS and deposit/loan journeys run before the live conformance pass, so their responses
            // feed the shared schema, error-format, X-Request-ID and signature checks.
            await runPis(ctx);
            await runLoans(ctx);
            await runLiveConformance(ctx);
            await runActiveSecurity(ctx);
            runDataChecks(ctx);
            const acc = ctx.state.accountReads?.[0]?.id;
            const probes = [
              { operation: 'discovery', path: ctx.oauthUrl('/.well-known/oauth-authorization-server'), absolute: true, auth: false },
              { operation: 'accounts', path: '/v1/accounts' },
              ...(acc
                ? [
                    { operation: 'balances', path: `/v1/accounts/${encodeURIComponent(acc)}/balances` },
                    { operation: 'transactions', path: `/v1/accounts/${encodeURIComponent(acc)}/transactions?bookingStatus=booked&dateFrom=${ctx.state.txWindow.from}` },
                  ]
                : []),
              // Per API, not only AIS: payment status and deposit/loan lists with their own tokens.
              ...(ctx.state.pis?.token
                ? [{ operation: 'payment-status', path: `/v1/payments/${ctx.state.pis.product}/${ctx.state.pis.paymentId}/status`, token: ctx.state.pis.token, consent: false }]
                : []),
              ...(ctx.state.v2?.token && ctx.state.savingsList?.status === 200
                ? [{ operation: 'savings', path: '/v2/savings', token: ctx.state.v2.token, consentId: ctx.state.v2.consentId }]
                : []),
              ...(ctx.state.v2?.token && ctx.state.loansList?.status === 200
                ? [{ operation: 'loans', path: '/v2/loans', token: ctx.state.v2.token, consentId: ctx.state.v2.consentId }]
                : []),
            ];
            if (ctx.state.token) await runProbes(ctx, probes);
          } else if (target.mode === 'bis') {
            // TBC Business Integration Services - Accounts: proprietary, judged against TBC's own documentation.
            await runBisFlow(ctx);
          } else {
            // Passive targets with a published spec still get every static spec check and the cross-bank comparison.
            if (target.specFile || target.specUrl) {
              ctx.spec = await Spec.load(target, http);
              if (ctx.spec) runStaticSpecChecks(ctx);
            }
            if (!target.specOnly) await runPassive(ctx);
            // Sandboxes with a test certificate from the bank portal: full consent + SCA + AIS journey.
            if (target.credentials) {
              const creds = loadCredentials(target);
              if (typeof creds === 'string') {
                ctx.add({ checkId: 'flow.sandbox', layer: 'conformance', status: 'skip', severity: 'none', title: 'Sandbox flow', message: `Not run: ${creds}. The sandbox journey starts once the bank's test certificate is in certs/ (README, "Bank sandboxes").` });
              } else {
                http.useClient({ dispatcher: creds.dispatcher, signer: creds.signer, signBase: target.baseUrl });
                await runSandboxFlow(ctx, `Client certificate ${creds.certSubject}, valid until ${creds.certExpires}`, creds.tppId, creds.signerOptions);
              }
            }
          }
          await runAi(ctx, this.jev);
          if (qvac.enabled) {
            try {
              if (target.mode === 'full') await generateTests(ctx);
              const summary = await summarize(ctx);
              if (summary) this.db.putRunAi(run.id, 'summary', target.id, summary);
            } catch (e: any) {
              ctx.add({ checkId: 'ai.qvac', layer: 'conformance', status: 'skip', severity: 'none', title: 'Local AI (QVAC)', message: `QVAC unavailable, local AI features skipped: ${e?.message ?? e}` });
            }
          }
        } catch (e: any) {
          ctx.add({ checkId: 'run.error', layer: 'reliability', status: 'fail', severity: 'medium', title: 'Audit run error', message: `The auditor stopped on this target: ${e?.message ?? e}` });
          this.log.error(`[${run.id}] ${target.id}: ${e?.stack ?? e}`);
        } finally {
          if (ctx.spec) specOps.set(target.id, [...new Set(ctx.spec.operations.map((o) => `${o.method} ${o.path}`))].sort());
          this.db.insertFindings(run.id, ctx.findings as Finding[]);
          all.push(...ctx.findings);
          this.db.insertExchanges(run.id, http.exchanges);
          this.db.insertStats(run.id, target.id, ctx.state.endpointStats ?? []);
          this.log.log(`[${run.id}] ${target.id}: ${ctx.findings.length} findings, ${http.exchanges.length} calls`);
        }
      }),
    );

    // Run level: banks that publish the same spec template (identical operations). Informational, never scored.
    const shared = sharedSpecTemplates(specOps, targets);
    if (shared.length) {
      this.db.insertFindings(run.id, shared);
      all.push(...shared);
    }

    // Run level: group similar findings across banks into shared root causes.
    if (qvac.enabled) {
      try {
        this.db.putRunAi(run.id, 'clusters', null, await clusterFindings(all));
      } catch (e: any) {
        this.log.warn(`clustering skipped: ${e?.message ?? e}`);
      }
    }
  }
}
