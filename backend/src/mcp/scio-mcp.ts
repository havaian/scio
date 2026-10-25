import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import { commonScores } from '../reports/report.service';
import type { Report, TargetReport } from '../reports/report.service';
import type { MonitorService } from '../monitor/monitor.service';
import { LAYERS, Severity, Status } from '../common/types';

export type Uptime = ReturnType<MonitorService['uptime']>;

export interface ScioMcpDeps {
  /** Latest completed audit report (ReportService.build()). Throws when there is no completed run. */
  report: () => Report;
  /** Monitor uptime over the last `days` days (Tbilisi calendar days). */
  uptime: (days: number) => Uptime;
  /** Optional latency profile from the monitor (MonitorService.latencyProfile), included in get_uptime when present. */
  latencyProfile?: (days: number) => any;
}

/** What each access level means, so answers do not over-claim. */
export const ACCESS_MEANING: Record<string, string> = {
  mock: "organizers' simulated API (full flow, negative tests); describes the mock, not a bank's production API",
  full: 'test environment built for testing; full active flow',
  sandbox: "bank's real sandbox, reached with the team's test certificates (consent, OAuth, AIS journey)",
  pending: "sandbox configured but the bank's test certificates were not received yet; only public probes and the spec were checked",
  bis: 'TBC Business Integration Services: proprietary read-only API, not a Berlin Group/NBG XS2A interface',
  spec: "published OpenAPI document only: static spec checks, nothing about the running API",
  probes: 'public endpoints only (unauthenticated, read-only probes and the published spec); no authorised journey',
};

const INSTRUCTIONS = `Scio audits Georgian open banking APIs against the NBG standard (GE-XS2A, GE-IAA, GE-JWS implementation guides) and the Berlin Group NextGenPSD2 guidelines. All tools are read-only and answer from Scio's latest completed audit run and its uptime monitor.

Data provenance - always say which kind of evidence an answer rests on:
- access "mock": the organizers' simulated TBC API. Results describe the mock, not any bank's production system.
- access "sandbox": the bank's real sandbox, reached with test certificates. Still a test environment, not production.
- access "pending" / "probes": only public, unauthenticated probes and the published spec. Consent, OAuth and account flows were NOT exercised, so do not claim a flow works or fails.
- access "spec": only the published OpenAPI document was checked; nothing is known about the running API.
- access "bis": TBC's proprietary API, not an XS2A interface.
Overall scores rest on different check sets per target, so they do not rank banks; use the like-for-like score (common) for comparisons. Thresholds (availability, error rate, latency) are assumptions until NBG publishes indicators (thresholds.source says so). Standard clause references with verified=false are Scio's mapping, not yet checked against the clause text. Scio's verdicts are technical test results, not regulatory compliance determinations. Cite the run id and clause refs in answers.`;

const SEV_RANK: Record<Severity, number> = { high: 0, medium: 1, low: 2, none: 3 };
const STATUS_RANK: Record<Status, number> = { fail: 0, warn: 1, pass: 2, info: 3, skip: 4 };
const MAX_TEXT = 60_000;

const clip = (s: unknown, n = 400): string | undefined => {
  if (s === undefined || s === null || s === '') return undefined;
  const v = String(s);
  return v.length > n ? `${v.slice(0, n)}...` : v;
};

/** Concise text first, then the same data as JSON (structuredContent for clients that read it). Size-capped. */
function ok(summary: string, data: Record<string, unknown>): CallToolResult {
  let json = JSON.stringify(data);
  let structured: Record<string, unknown> = data;
  if (json.length > MAX_TEXT) {
    json = `${json.slice(0, MAX_TEXT)}... [truncated]`;
    structured = { truncated: true, note: 'Result too large; narrow the query (bank, layer, limit, days).' };
  }
  return { content: [{ type: 'text', text: summary }, { type: 'text', text: json }], structuredContent: structured };
}

const fail = (message: string): CallToolResult => ({ isError: true, content: [{ type: 'text', text: message }] });

/** Runs a tool body; errors (no run yet, unknown bank) become tool errors the model can read. */
const safe = (fn: () => CallToolResult): CallToolResult => {
  try {
    return fn();
  } catch (e: any) {
    return fail(e?.message ?? String(e));
  }
};

interface Candidate {
  id: string;
  name?: string;
  bank?: string;
}

/**
 * Bank argument: target id, or case-insensitive bank/name match. Exact id, then exact bank or name, then every word of
 * the query found in id + bank + name ("tbc mock", "BoG", "silk"). Several matches -> error listing them.
 */
export function resolveTarget(query: string, targets: Candidate[]): Candidate {
  const q = query.trim().toLowerCase();
  const list = () => targets.map((t) => `${t.id} (${t.name ?? t.bank ?? t.id})`).join(', ');
  const exact = targets.find((t) => t.id.toLowerCase() === q);
  if (exact) return exact;
  const byName = targets.filter((t) => t.bank?.toLowerCase() === q || t.name?.toLowerCase() === q);
  if (byName.length === 1) return byName[0];
  const words = q.split(/[\s,]+/).filter(Boolean);
  const hay = (t: Candidate) => `${t.id} ${t.bank ?? ''} ${t.name ?? ''}`.toLowerCase();
  const pool = byName.length ? byName : targets;
  const hits = pool.filter((t) => words.length && words.every((w) => hay(t).includes(w)));
  if (hits.length === 1) return hits[0];
  if (hits.length > 1) throw new Error(`"${query}" matches several targets: ${hits.map((t) => t.id).join(', ')}. Pass one target id.`);
  throw new Error(`Unknown bank "${query}". Target ids: ${list()}.`);
}

const runInfo = (r: Report) => ({ runId: r.run.id, startedAt: r.run.startedAt, finishedAt: r.run.finishedAt, status: r.run.status });
const thresholdsNote = (r: Report) =>
  `Thresholds source: "${r.thresholds.source}"${r.thresholds.source === 'assumed' ? ' (assumptions until NBG publishes indicators)' : ''}.`;

const findingView = (f: Report['findings'][number]) => ({
  targetId: f.targetId,
  checkId: f.checkId,
  layer: f.layer,
  status: f.status,
  severity: f.severity,
  title: f.title,
  endpoint: f.endpoint,
  message: clip(f.message),
  expected: clip(f.expected, 300),
  actual: clip(f.actual, 300),
  fix: clip(f.fix, 400),
  reference: f.reference,
  standard: f.standard ? { refs: f.standard.refs, verified: f.standard.verified } : null,
  source: f.source ?? 'rules',
});

const refsText = (s?: { refs: string[]; verified: boolean } | null) => (s?.refs?.length ? `[${s.refs.join('; ')}${s.verified ? '' : ', unverified'}]` : '[no clause mapped]');

const targetSummary = (t: TargetReport, r: Report) => ({
  id: t.id,
  name: t.name,
  bank: t.bank,
  access: t.access,
  accessMeaning: ACCESS_MEANING[t.access],
  overall: t.overall,
  evaluatedChecks: t.evaluated,
  likeForLike: r.common && t.id in r.common.scores ? r.common.scores[t.id] : null,
  fail: t.counts.fail,
  warn: t.counts.warn,
  pass: t.counts.pass,
});

export function createScioMcpServer(deps: ScioMcpDeps): McpServer {
  const server = new McpServer({ name: 'scio', version: '0.1.0' }, { instructions: INSTRUCTIONS });
  const readOnly = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false };
  const bankArg = z.string().min(1).max(100).describe('Target id (e.g. bog-sandbox) or bank name (e.g. "Bank of Georgia", "Silk", "tbc mock")');

  server.registerTool(
    'list_banks',
    {
      title: 'List audited banks',
      description: 'Targets in the latest audit run: access level (what Scio could reach), overall score with check count, like-for-like score, fail/warn counts, run time.',
      annotations: readOnly,
    },
    async () =>
      safe(() => {
        const r = deps.report();
        const targets = r.targets.map((t) => targetSummary(t, r));
        const lines = targets.map(
          (t) =>
            `- ${t.id} (${t.name}) access=${t.access} overall=${t.overall ?? 'n/a'} on ${t.evaluatedChecks} checks, like-for-like=${t.likeForLike ?? 'n/a'}, fail=${t.fail} warn=${t.warn}`,
        );
        const common = r.common ? `Like-for-like score: ${r.common.checkIds.length} checks every scored real bank received (${r.common.targets.join(', ')}).` : 'No like-for-like comparison in this run.';
        const summary = [`Run ${r.run.id} (${r.run.status}, finished ${r.run.finishedAt ?? 'n/a'}).`, ...lines, common, 'Overall scores rest on different check sets; compare banks with the like-for-like score.', thresholdsNote(r)].join('\n');
        return ok(summary, { run: runInfo(r), thresholds: r.thresholds, common: r.common ? { targets: r.common.targets, checks: r.common.checkIds.length, scores: r.common.scores } : null, targets });
      }),
  );

  server.registerTool(
    'get_bank_report',
    {
      title: 'Bank report',
      description: 'One target: per-layer scores with check counts, top failures and warnings (severity order) with expected/actual, fix and the standard clause, plus the target note and limitations.',
      inputSchema: { bank: bankArg, limit: z.number().int().min(1).max(25).optional().describe('Top problems to return (default 10)') },
      annotations: readOnly,
    },
    async ({ bank, limit }) =>
      safe(() => {
        const r = deps.report();
        const t = r.targets.find((x) => x.id === resolveTarget(bank, r.targets).id)!;
        const own = r.findings.filter((f) => f.targetId === t.id && f.source !== 'ai' && (f.status === 'fail' || f.status === 'warn'));
        own.sort((a, b) => STATUS_RANK[a.status] - STATUS_RANK[b.status] || SEV_RANK[a.severity] - SEV_RANK[b.severity] || a.checkId.localeCompare(b.checkId));
        // One entry per check (its worst occurrence), with how often it occurred.
        const byCheck = new Map<string, { f: (typeof own)[number]; occurrences: number }>();
        for (const f of own) {
          const cur = byCheck.get(f.checkId);
          if (cur) cur.occurrences++;
          else byCheck.set(f.checkId, { f, occurrences: 1 });
        }
        const top = [...byCheck.values()].slice(0, limit ?? 10).map(({ f, occurrences }) => ({ ...findingView(f), occurrences }));
        const layers = Object.fromEntries(LAYERS.map((l) => [l, { score: t.scores[l], checks: t.layerChecks[l] }]));
        const limitations: string[] = [`Access: ${t.access} - ${ACCESS_MEANING[t.access]}.`];
        if (t.note) limitations.push(`Note: ${t.note}`);
        if (t.overall === null) limitations.push(`No overall score: ${t.evaluated} rule-based verdicts, ${r.thresholds.minEvaluatedChecks} needed.`);
        const unscored = LAYERS.filter((l) => t.scores[l] === null);
        if (t.overall !== null && unscored.length) limitations.push(`Layers without a score (too few checks or not evaluated): ${unscored.join(', ')}.`);
        if (t.counts.skip) limitations.push(`${t.counts.skip} checks were skipped (not reachable at this access level).`);
        const summary = [
          `Run ${r.run.id}: ${t.name} (${t.id}), access=${t.access}, overall=${t.overall ?? 'n/a'} on ${t.evaluated} checks.`,
          `Layers: ${LAYERS.map((l) => `${l} ${t.scores[l] ?? 'n/a'} (${t.layerChecks[l]} checks)`).join(', ')}.`,
          top.length ? 'Top problems:' : 'No failures or warnings.',
          ...top.map((f) => `- [${f.status}/${f.severity}] ${f.checkId}: ${f.message ?? f.title} ${refsText(f.standard)}${f.fix ? ` Fix: ${f.fix}` : ''}`),
          ...limitations,
          thresholdsNote(r),
        ].join('\n');
        return ok(summary, {
          run: runInfo(r),
          target: { ...targetSummary(t, r), baseUrl: t.baseUrl, source: t.source, note: t.note, counts: t.counts },
          layers,
          topProblems: top,
          problemChecks: byCheck.size,
          limitations,
          thresholds: r.thresholds,
        });
      }),
  );

  server.registerTool(
    'get_findings',
    {
      title: 'Search findings',
      description: 'Findings of the latest run filtered by bank, layer, status, severity or check id (most severe first).',
      inputSchema: {
        bank: bankArg.optional(),
        layer: z.enum(['conformance', 'reliability', 'latency', 'security', 'data']).optional(),
        status: z.enum(['pass', 'fail', 'warn', 'info', 'skip']).optional(),
        severity: z.enum(['high', 'medium', 'low', 'none']).optional(),
        checkId: z.string().max(100).optional().describe('Exact check id, or a prefix such as "flow." or "security."'),
        limit: z.number().int().min(1).max(50).optional().describe('Max findings (default 20, max 50)'),
      },
      annotations: readOnly,
    },
    async ({ bank, layer, status, severity, checkId, limit }) =>
      safe(() => {
        const r = deps.report();
        const tid = bank ? resolveTarget(bank, r.targets).id : undefined;
        const hits = r.findings.filter(
          (f) => (!tid || f.targetId === tid) && (!layer || f.layer === layer) && (!status || f.status === status) && (!severity || f.severity === severity) && (!checkId || f.checkId === checkId || f.checkId.startsWith(checkId)),
        );
        hits.sort((a, b) => STATUS_RANK[a.status] - STATUS_RANK[b.status] || SEV_RANK[a.severity] - SEV_RANK[b.severity] || a.targetId.localeCompare(b.targetId) || a.checkId.localeCompare(b.checkId));
        const out = hits.slice(0, limit ?? 20).map(findingView);
        const summary = [
          `Run ${r.run.id}: ${hits.length} findings match, showing ${out.length}.`,
          ...out.map((f) => `- ${f.targetId} [${f.status}/${f.severity}] ${f.checkId}: ${f.message ?? f.title} ${refsText(f.standard)}`),
        ].join('\n');
        return ok(summary, { run: runInfo(r), total: hits.length, returned: out.length, findings: out });
      }),
  );

  server.registerTool(
    'compare_banks',
    {
      title: 'Compare banks',
      description: 'Compare 2-4 targets: like-for-like score on the checks all of them received, and the checks where their verdicts differ, with clause refs.',
      inputSchema: { banks: z.array(bankArg).min(2).max(4) },
      annotations: readOnly,
    },
    async ({ banks }) =>
      safe(() => {
        const r = deps.report();
        const ids = [...new Set(banks.map((b) => resolveTarget(b, r.targets).id))];
        if (ids.length < 2) throw new Error(`Need two different targets; got ${ids.join(', ')}.`);
        const ts = ids.map((id) => r.targets.find((t) => t.id === id)!);
        const rows = r.matrix
          .filter((row) => {
            const st = ids.map((id) => row.cells[id]?.status).filter(Boolean);
            return st.length >= 2 && new Set(st).size > 1;
          })
          .sort((a, b) => LAYERS.indexOf(a.layer) - LAYERS.indexOf(b.layer) || a.checkId.localeCompare(b.checkId));
        const shown = rows.slice(0, 60).map((row) => ({
          checkId: row.checkId,
          title: row.title,
          layer: row.layer,
          standard: row.standard ? { refs: row.standard.refs, verified: row.standard.verified } : null,
          verdicts: Object.fromEntries(ids.map((id) => [id, row.cells[id] ? { status: row.cells[id]!.status, severity: row.cells[id]!.severity, message: clip(row.cells[id]!.message, 200) } : null])),
        }));
        const common = commonScores(r.findings, ids);
        const summary = [
          `Run ${r.run.id}: ${ts.map((t) => `${t.id} (access=${t.access}, overall=${t.overall ?? 'n/a'})`).join(' vs ')}.`,
          common ? `Like-for-like on ${common.checkIds.length} shared checks: ${ids.map((id) => `${id} ${common.scores[id] ?? 'n/a'}`).join(', ')}.` : 'Too few shared checks for a like-for-like score.',
          `${rows.length} checks with differing verdicts${rows.length > shown.length ? `, showing ${shown.length}` : ''}:`,
          ...shown.map((row) => `- ${row.checkId} ${refsText(row.standard)}: ${ids.map((id) => `${id}=${row.verdicts[id]?.status ?? '-'}`).join(' ')}`),
          ts.some((t) => t.access !== ts[0].access) ? 'Targets were reached at different access levels; differences may reflect what Scio could test, not only the bank.' : '',
        ]
          .filter(Boolean)
          .join('\n');
        return ok(summary, {
          run: runInfo(r),
          targets: ts.map((t) => targetSummary(t, r)),
          likeForLike: common ? { checks: common.checkIds.length, scores: common.scores } : null,
          differing: rows.length,
          rows: shown,
        });
      }),
  );

  server.registerTool(
    'explain_check',
    {
      title: 'Explain a check',
      description: 'A check: its standard clauses (refs, verified flag, note) and the verdict for every target in the latest run.',
      inputSchema: { checkId: z.string().min(1).max(100) },
      annotations: readOnly,
    },
    async ({ checkId }) =>
      safe(() => {
        const r = deps.report();
        const row = r.matrix.find((m) => m.checkId === checkId);
        const f = r.findings.find((x) => x.checkId === checkId);
        if (!row && !f) {
          const near = [...new Set(r.matrix.map((m) => m.checkId))].filter((id) => id.includes(checkId) || checkId.includes(id.split('.')[0])).slice(0, 15);
          throw new Error(`Check "${checkId}" not in run ${r.run.id}.${near.length ? ` Similar: ${near.join(', ')}.` : ''}`);
        }
        const standard = row?.standard ?? f?.standard ?? null;
        const documents = Object.fromEntries((standard?.refs ?? []).map((ref) => ref.split(' ')[0]).filter((k) => r.standards.documents[k]).map((k) => [k, r.standards.documents[k]]));
        const verdicts = Object.fromEntries(
          r.targets.map((t) => {
            const c = row?.cells[t.id];
            return [t.id, c ? { status: c.status, severity: c.severity, count: c.count, message: clip(c.message, 300) } : null];
          }),
        );
        const sample = f ? { expected: clip(f.expected, 300), fix: clip(f.fix, 400), reference: f.reference } : {};
        const summary = [
          `Run ${r.run.id}: ${checkId} - ${row?.title ?? f?.title} (layer ${row?.layer ?? f?.layer}).`,
          `Standard: ${refsText(standard)}${standard?.note ? ` ${standard.note}` : ''}`,
          ...Object.entries(verdicts).map(([id, v]) => `- ${id}: ${v ? `${v.status}/${v.severity} ${v.message ?? ''}` : 'not checked'}`),
        ].join('\n');
        return ok(summary, { run: runInfo(r), checkId, title: row?.title ?? f?.title, layer: row?.layer ?? f?.layer, standard, documents, ...sample, verdicts });
      }),
  );

  server.registerTool(
    'get_uptime',
    {
      title: 'Uptime',
      description: 'Continuous monitor (independent of audit runs): uptime over the last N days (Tbilisi calendar days) with sample coverage and incidents. Daily buckets when one bank is given.',
      inputSchema: { bank: bankArg.optional(), days: z.number().int().min(1).max(31).optional().describe('Days, default 7, max 31') },
      annotations: readOnly,
    },
    async ({ bank, days }) =>
      safe(() => {
        const n = days ?? 7;
        const u = deps.uptime(n);
        // Bank names come from the report when there is one; uptime alone has ids and names.
        let names: Candidate[] = u.targets.map((t) => ({ id: t.targetId, name: t.name }));
        try {
          const rep = deps.report();
          names = names.map((c) => ({ ...c, bank: rep.targets.find((t) => t.id === c.id)?.bank }));
        } catch {
          // no completed run: ids and names only
        }
        const tid = bank ? resolveTarget(bank, names).id : undefined;
        const rows = u.targets.filter((t) => !tid || t.targetId === tid);
        const view = rows.map((t) => {
          const up = t.daily.reduce((a, b) => a + b.up, 0);
          const samples = t.daily.reduce((a, b) => a + b.samples, 0);
          const expected = t.daily.reduce((a, b) => a + b.expected, 0);
          return {
            targetId: t.targetId,
            name: t.name,
            probeAccess: (t as any).access,
            intervalMin: t.intervalMin,
            windowUptimePct: samples ? Math.round((up / samples) * 10000) / 100 : null,
            windowCoveragePct: expected ? Math.min(100, Math.round((samples / expected) * 1000) / 10) : null,
            samples,
            last24h: t.last24h,
            last7d: t.last7d,
            last30d: t.last30d,
            lastSample: t.lastSample,
            daily: tid ? t.daily.map((d) => ({ period: d.period, uptimePct: d.uptimePct, coveragePct: d.coveragePct, samples: d.samples, partial: d.partial, p50: d.p50, p95: d.p95 })) : undefined,
            monthly: t.monthly.map((d) => ({ period: d.period, uptimePct: d.uptimePct, coveragePct: d.coveragePct, samples: d.samples, partial: d.partial })),
            incidents: t.incidents.slice(-20),
            incidentCount: t.incidents.length,
          };
        });
        let latency: any;
        if (deps.latencyProfile) {
          try {
            latency = deps.latencyProfile(n);
            if (tid && Array.isArray(latency?.targets)) latency = { ...latency, targets: latency.targets.filter((x: any) => (x?.targetId ?? x?.id) === tid) };
          } catch (e: any) {
            latency = { error: e?.message ?? String(e) };
          }
        }
        const summary = [
          `Uptime monitor, last ${n} days (${u.timezone}), target availability ${u.availabilityPct}% (thresholds source "${u.source}"${u.source === 'assumed' ? ', an assumption' : ''}). Monitor data is independent of audit runs.`,
          u.enabled ? '' : 'The monitor is not sampling in this process; figures come from samples stored by the server.',
          ...view.map((t) => `- ${t.targetId}: ${t.windowUptimePct ?? 'n/a'}% up over ${t.samples} samples, coverage ${t.windowCoveragePct ?? 'n/a'}%, ${t.incidentCount} incidents`),
          'Coverage below 100% means samples are missing (monitor down or started later); uptime is over the samples taken.',
        ]
          .filter(Boolean)
          .join('\n');
        return ok(summary, { days: n, timezone: u.timezone, availabilityTargetPct: u.availabilityPct, thresholdsSource: u.source, monitorEnabled: u.enabled, intervals: u.intervals, targets: view, ...(latency !== undefined ? { latencyProfile: latency } : {}) });
      }),
  );

  return server;
}
