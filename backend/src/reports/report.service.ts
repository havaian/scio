import { Injectable, NotFoundException } from '@nestjs/common';
import { loadTargets, loadThresholds } from '../common/config';
import { loadStandardMap, StandardRef } from '../common/standards';
import { Exchange, Finding, Layer, LAYERS, RunSummary, Severity, Status, TargetConfig } from '../common/types';
import { DbService } from '../storage/db.service';
import { qvac } from '../ai/qvac.engine';
import { MonitorService } from '../monitor/monitor.service';

/** Failure weight per severity. A pass counts 1, a warning counts half of its failure weight. */
export const SEVERITY_WEIGHT: Record<Severity, number> = { high: 3, medium: 2, low: 1, none: 1 };

/**
 * Layer score, 0-100: passed checks / (passed + weighted problems).
 * Fail = severity weight (high 3, medium 2, low 1), warn = half of that, pass = 1.
 * Info, skip and AI-generated findings are not scored. Null when nothing was evaluated.
 */
export function layerScore(findings: Finding[], minChecks = 1): number | null {
  let passed = 0;
  let penalty = 0;
  let verdicts = 0;
  for (const f of findings) {
    if (f.source === 'ai') continue;
    if (f.status === 'pass') passed += 1;
    else if (f.status === 'fail') penalty += SEVERITY_WEIGHT[f.severity];
    else if (f.status === 'warn') penalty += SEVERITY_WEIGHT[f.severity] / 2;
    if (f.status === 'pass' || f.status === 'fail' || f.status === 'warn') verdicts++;
  }
  // One or two checks are not a layer score (e.g. "data 100" from a single spec check).
  if (verdicts < minChecks) return null;
  const total = passed + penalty;
  return total ? Math.round((passed / total) * 100) : null;
}

/**
 * Reliability and latency findings each aggregate many calls and carry their own sample minimum (latencyMinSamples,
 * at least 5 journey calls), so the per-layer check minimum applies only to the check-count layers.
 */
export const SAMPLE_LAYERS: Layer[] = ['reliability', 'latency'];

/** Rule-based verdicts (pass, fail, warn) per layer: how much each layer score rests on. */
export function layerCounts(findings: Finding[]): Record<Layer, number> {
  const out = Object.fromEntries(LAYERS.map((l) => [l, 0])) as Record<Layer, number>;
  for (const f of findings) if (f.source !== 'ai' && (f.status === 'pass' || f.status === 'fail' || f.status === 'warn')) out[f.layer]++;
  return out;
}

/**
 * Like-for-like comparison: the checks every compared target received a verdict on, scored the same way for all.
 * Overall scores rest on different check sets (mock: full suite; spec-only bank: static checks), so they do not rank banks.
 * Each check counts once per target (its worst verdict), so per-path or per-account checks do not outweigh the rest.
 */
export function commonScores(findings: Finding[], targetIds: string[], minChecks = 5): { checkIds: string[]; scores: Record<string, number | null> } | null {
  if (targetIds.length < 2) return null;
  const verdict = (f: Finding) => f.source !== 'ai' && (f.status === 'pass' || f.status === 'fail' || f.status === 'warn');
  const sets = targetIds.map((t) => new Set(findings.filter((f) => f.targetId === t && verdict(f)).map((f) => f.checkId)));
  const common = [...sets[0]].filter((id) => sets.every((s) => s.has(id))).sort();
  if (common.length < minChecks) return null;
  const inCommon = new Set(common);
  const scores = Object.fromEntries(targetIds.map((t) => [t, layerScore(worstPerCheck(findings.filter((f) => f.targetId === t && inCommon.has(f.checkId) && verdict(f))))]));
  return { checkIds: common, scores };
}

/** One finding per checkId: fail over warn over pass, then the highest severity. */
export function worstPerCheck(findings: Finding[]): Finding[] {
  const out = new Map<string, Finding>();
  for (const f of findings) {
    const cur = out.get(f.checkId);
    if (!cur || STATUS_RANK[f.status] < STATUS_RANK[cur.status] || (f.status === cur.status && SEV_RANK[f.severity] < SEV_RANK[cur.severity])) out.set(f.checkId, f);
  }
  return [...out.values()];
}

/** Overall score: mean of the layers that were evaluated. */
export function overallScore(scores: Record<Layer, number | null>): number | null {
  const vals = LAYERS.map((l) => scores[l]).filter((v): v is number => v !== null);
  return vals.length ? Math.round(vals.reduce((a, b) => a + b, 0) / vals.length) : null;
}

const STATUS_RANK: Record<Status, number> = { fail: 0, warn: 1, pass: 2, info: 3, skip: 4 };
const SEV_RANK: Record<Severity, number> = { high: 0, medium: 1, low: 2, none: 3 };

export interface MatrixCell {
  status: Status;
  severity: Severity;
  count: number;
  message: string;
}

export type TargetAccess = 'mock' | 'full' | 'sandbox' | 'pending' | 'bis' | 'spec' | 'probes';

export interface TargetReport {
  id: string;
  name: string;
  bank: string;
  mode: 'full' | 'passive' | 'bis';
  simulated: boolean;
  /**
   * How far Scio could go with this target: mock (organizers' simulated API, full flow), sandbox (bank sandbox journey with
   * certificates the team obtained), pending (sandbox configured, certificates not received yet), bis (TBC proprietary API),
   * spec (published OpenAPI document only), probes (public endpoints, read-only).
   */
  access: TargetAccess;
  baseUrl: string;
  source?: string;
  note?: string;
  scores: Record<Layer, number | null>;
  /** Rule-based verdicts per layer; a layer with fewer than minLayerChecks is not scored. */
  layerChecks: Record<Layer, number>;
  overall: number | null;
  /** Rule-based checks with a verdict (pass, fail, warn). Below minEvaluatedChecks no score is given. */
  evaluated: number;
  counts: Record<Status, number>;
  endpointStats: any[];
}

export interface Report {
  run: RunSummary;
  ai: { enabled: boolean; note?: string; models: string[]; triaged: number; auto: number; review: number; human: number; disagreements: number };
  local: { enabled: boolean; note?: string; summaries: any[]; clusters: any | null };
  standards: { documents: Record<string, { title: string; url: string }> };
  generatedAt: string;
  thresholds: { source: string; availabilityPct: number; errorRatePct: number; latencyP95Ms: number; latencyMinSamples: number; minEvaluatedChecks: number; minLayerChecks: number };
  /** Like-for-like ranking of the real banks that got a score: only the checks all of them received. */
  common: { targets: string[]; checkIds: string[]; scores: Record<string, number | null> } | null;
  targets: TargetReport[];
  matrix: { checkId: string; title: string; layer: Layer; standard?: StandardRef | null; cells: Record<string, MatrixCell | null> }[];
  findings: (Finding & { standard?: StandardRef | null })[];
  totals: { findings: number; failures: number; warnings: number; calls: number };
  /** Continuous monitor, last 31 days (independent of this run), Tbilisi calendar days. */
  uptime?: ReturnType<MonitorService['uptime']>;
  /** The same samples bucketed by Tashkent calendar days. */
  uptimeTashkent?: ReturnType<MonitorService['uptime']>;
  /** Monitor sampling intervals from config (monitor.simulatedIntervalMin / realIntervalMin). */
  monitorIntervals?: { simulatedMin: number; realMin: number };
}

@Injectable()
export class ReportService {
  constructor(
    private readonly db: DbService,
    private readonly monitor: MonitorService,
  ) {}

  /** Built reports per run id; reused while the run's status is unchanged (a finished run's findings do not change). */
  private cache = new Map<string, { status: string; at: number; report: Report }>();

  /** Full report for a run; without an id, the most recent completed run. */
  build(runId?: string): Report {
    const id = runId ?? this.db.latestDoneRunId();
    if (!id) throw new NotFoundException('No completed audit run yet. Start one with POST /api/runs.');
    const run = this.db.getRun(id);
    if (!run) throw new NotFoundException(`Run ${id} not found`);
    // Running runs are rebuilt every time; finished ones are cached for 10 min (config edits show up after that).
    // Uptime is attached fresh each time (the monitor caches it for ~60 s).
    const hit = this.cache.get(id);
    const report = hit && hit.status === run.status && run.status !== 'running' && Date.now() - hit.at < 600_000 ? hit.report : this.buildRun(id, run);
    if (report !== hit?.report && run.status !== 'running') this.cache.set(id, { status: run.status, at: Date.now(), report });
    return { ...report, generatedAt: new Date().toISOString(), uptime: this.monitor.uptime(31, 'tbilisi'), uptimeTashkent: this.monitor.uptime(31, 'tashkent'), monitorIntervals: this.monitor.intervals() };
  }

  private buildRun(id: string, run: RunSummary): Report {

    const thresholds = loadThresholds();
    const map = loadStandardMap();
    const configured = new Map(loadTargets().map((t) => [t.id, t]));
    const findings = this.db.findings(id).map((f) => ({ ...f, standard: map.checks[f.checkId] ?? null }));
    const stats = this.db.stats(id);

    const minChecks = thresholds.minEvaluatedChecks ?? 10;
    const minLayer = thresholds.minLayerChecks ?? 3;
    const targets: TargetReport[] = run.targets.map((tid) => {
      const cfg: Partial<TargetConfig> = configured.get(tid) ?? { id: tid, name: tid, bank: tid, mode: 'passive', simulated: false, baseUrl: '' };
      const own = findings.filter((f) => f.targetId === tid);
      const counts = { pass: 0, fail: 0, warn: 0, info: 0, skip: 0 } as Record<Status, number>;
      for (const f of own) if (f.source !== 'ai') counts[f.status]++;
      // Too few evaluated checks to score fairly (e.g. one passive probe): show no score, only the count.
      const evaluated = counts.pass + counts.fail + counts.warn;
      const scored = evaluated >= minChecks;
      const scores = Object.fromEntries(LAYERS.map((l) => [l, scored ? layerScore(own.filter((f) => f.layer === l), SAMPLE_LAYERS.includes(l) ? 1 : minLayer) : null])) as Record<Layer, number | null>;
      return {
        id: tid,
        name: cfg.name ?? tid,
        bank: cfg.bank ?? tid,
        mode: cfg.mode ?? 'passive',
        simulated: !!cfg.simulated,
        access: accessOf(cfg, own),
        baseUrl: cfg.baseUrl ?? '',
        source: cfg.source,
        note: cfg.note,
        scores,
        layerChecks: layerCounts(own),
        overall: overallScore(scores),
        evaluated,
        counts,
        endpointStats: stats.filter((s) => s.targetId === tid).map((s) => s.data),
      };
    });

    // Incompatibility matrix: one row per rule-based check, one cell per target (worst result wins).
    const rows = new Map<string, Report['matrix'][number]>();
    for (const f of findings) {
      if (f.source === 'ai' || f.checkId.startsWith('ai.') || f.checkId === 'run.error') continue;
      let row = rows.get(f.checkId);
      if (!row) {
        row = { checkId: f.checkId, title: f.title, layer: f.layer, standard: f.standard, cells: Object.fromEntries(run.targets.map((t) => [t, null])) };
        rows.set(f.checkId, row);
      }
      const cell = row.cells[f.targetId];
      if (!cell) {
        row.cells[f.targetId] = { status: f.status, severity: f.severity, count: 1, message: f.message };
      } else {
        cell.count++;
        const worse = STATUS_RANK[f.status] < STATUS_RANK[cell.status] || (f.status === cell.status && SEV_RANK[f.severity] < SEV_RANK[cell.severity]);
        if (worse) Object.assign(cell, { status: f.status, severity: f.severity, message: f.message });
      }
    }
    const matrix = [...rows.values()].sort((a, b) => LAYERS.indexOf(a.layer) - LAYERS.indexOf(b.layer) || a.checkId.localeCompare(b.checkId));

    // AI (Jev, or QVAC as fallback) triage statistics.
    const triaged = findings.filter((f) => f.ai);
    const models = new Set<string>(triaged.map((f) => f.ai.model).filter(Boolean));
    for (const f of findings) if (f.checkId === 'ai.error-quality') for (const g of (f.evidence as any[]) ?? []) if (g?.model) models.add(g.model);
    const aiStatus = findings.find((f) => f.checkId === 'ai.status');
    const runAi = this.db.runAi(id);
    const summaries = runAi.filter((r) => r.kind === 'summary').map((r) => r.data);
    const clusters = runAi.find((r) => r.kind === 'clusters')?.data ?? null;
    const qvacSkip = findings.find((f) => f.checkId === 'ai.qvac');

    return {
      run,
      ai: {
        enabled: triaged.length > 0,
        note: aiStatus?.message,
        models: [...models],
        triaged: triaged.length,
        auto: triaged.filter((f) => f.ai.gate === 'auto').length,
        review: triaged.filter((f) => f.ai.gate === 'review').length,
        human: triaged.filter((f) => f.ai.gate === 'human').length,
        disagreements: triaged.filter((f) => f.ai.agreesWithRules === false).length,
      },
      local: {
        enabled: summaries.length > 0 || clusters !== null,
        note: qvacSkip?.message ?? (qvac.enabled ? undefined : 'QVAC_ENABLED is not true'),
        summaries,
        clusters,
      },
      standards: { documents: map.documents },
      generatedAt: new Date().toISOString(),
      thresholds: {
        source: thresholds.source,
        availabilityPct: thresholds.availabilityPct,
        errorRatePct: thresholds.errorRatePct,
        latencyP95Ms: thresholds.latencyP95Ms,
        latencyMinSamples: thresholds.latencyMinSamples ?? 20,
        minEvaluatedChecks: minChecks,
        minLayerChecks: minLayer,
      },
      common: (() => {
        const ids = targets.filter((t) => t.overall !== null && !t.simulated).map((t) => t.id);
        const c = commonScores(findings, ids);
        return c ? { targets: ids, ...c } : null;
      })(),
      targets,
      matrix,
      findings,
      totals: {
        findings: findings.length,
        failures: findings.filter((f) => f.status === 'fail').length,
        warnings: findings.filter((f) => f.status === 'warn').length,
        calls: this.db.countExchanges(id),
      },
    };
  }

  /** Raw request/response log of a run, optionally for one target. */
  exchanges(runId: string, target?: string): Exchange[] {
    const all = this.db.exchanges(runId);
    return target ? all.filter((x) => x.targetId === target) : all;
  }
}

/** Access level reached for a target (see TargetReport.access). A sandbox whose certificate is missing counts as pending. */
function accessOf(cfg: Partial<TargetConfig>, own: { checkId: string; status: string; message: string }[]): TargetAccess {
  if (cfg.simulated) return 'mock';
  if (cfg.mode === 'full') return 'full';
  if (cfg.mode === 'bis') return 'bis';
  if (cfg.credentials) return own.some((f) => f.checkId === 'flow.sandbox' && f.status === 'skip' && /^Not run/.test(f.message)) ? 'pending' : 'sandbox';
  return cfg.specOnly ? 'spec' : 'probes';
}
