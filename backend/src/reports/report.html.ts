import { Layer, LAYERS, Status } from '../common/types';
import { Report } from './report.service';

/** Short label for how far Scio got with a target (TargetReport.access). */
const ACCESS_LABEL: Record<string, string> = {
  mock: "organizers' mock · full flow",
  full: 'full flow',
  sandbox: 'bank sandbox · mTLS + signed',
  pending: 'sandbox · awaiting certificates',
  bis: 'proprietary API (BIS)',
  spec: 'published spec only',
  probes: 'public probes',
};

/** Printable, self-contained HTML report (no external assets). */

const LAYER_LABEL: Record<Layer, string> = {
  conformance: 'Standard compatibility',
  reliability: 'Performance & reliability',
  latency: 'Latency',
  security: 'Security',
  data: 'Data quality',
};
const STATUS_LABEL: Record<Status, string> = { pass: 'Pass', fail: 'Fail', warn: 'Warn', info: 'Info', skip: 'Skip' };
const SEV_RANK: Record<string, number> = { high: 0, medium: 1, low: 2, none: 3 };

/** Display time in Georgian time, e.g. "23 Oct 2026, 13:00 GET (UTC+4)"; whatever the server's zone is. */
export const fmtTbilisi = (iso?: string) =>
  iso ? `${new Date(iso).toLocaleString('en-GB', { timeZone: 'Asia/Tbilisi', dateStyle: 'medium', timeStyle: 'short' })} GET (UTC+4)` : '';

const esc = (v: unknown) =>
  String(v ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');

const score = (v: number | null | undefined) =>
  v === null || v === undefined ? '<span class="muted">-</span>' : `<b class="${v >= 85 ? 'good' : v >= 60 ? 'mid' : 'bad'}">${v}</b>`;

const badge = (s: Status, sev?: string) =>
  `<span class="badge ${s}">${STATUS_LABEL[s]}${s === 'fail' && sev && sev !== 'none' ? ` · ${esc(sev)}` : ''}</span>`;

export function renderHtml(r: Report): string {
  const names = Object.fromEntries(r.targets.map((t) => [t.id, t.name]));
  const docUrl = (ref: string) => r.standards.documents[ref.split(' ')[0]]?.url;
  const refs = (f: { checkId: string; standard?: { refs: string[]; verified: boolean } | null; reference?: string }) => {
    const unverified = f.standard && !f.standard.verified ? ' <span class="muted">(unverified)</span>' : '';
    if (f.standard?.refs?.length)
      return f.standard.refs.map((x) => (docUrl(x) ? `<a href="${esc(docUrl(x))}">${esc(x)}</a>` : esc(x))).join(', ') + unverified;
    // A mapped check with no clause (e.g. latency targets) says so instead of borrowing the finding's general reference.
    if (f.standard) return `<span class="muted">no clause${/^(lat|rel)\./.test(f.checkId) ? ' (assumed threshold)' : ''}</span>${unverified}`;
    return f.reference ? esc(f.reference) : '<span class="muted">no clause</span>';
  };

  const scorecard = `
    <table>
      <thead><tr><th>Target</th>${LAYERS.map((l) => `<th class="c">${LAYER_LABEL[l]}</th>`).join('')}<th class="c">Overall</th><th class="c">Fail / warn</th></tr></thead>
      <tbody>${r.targets
        .map(
          (t) => `<tr><td><b>${esc(t.name)}</b><div class="muted small">${ACCESS_LABEL[t.access] ?? t.access} · <code>${esc(t.baseUrl)}</code>${t.source ? ` · <a href="${esc(t.source)}">source</a>` : ''}</div>${t.note ? `<div class="muted small">${esc(t.note)}</div>` : ''}</td>${LAYERS.map((l) => `<td class="c">${score(t.scores[l])}<div class="muted small">${t.layerChecks?.[l] ?? 0} chk</div></td>`).join('')}<td class="c">${t.evaluated < r.thresholds.minEvaluatedChecks ? '<span class="muted">-</span>' : score(t.overall)}<div class="muted small">${t.evaluated} check${t.evaluated === 1 ? '' : 's'}</div></td><td class="c">${t.counts.fail} / ${t.counts.warn}</td></tr>`,
        )
        .join('')}</tbody>
    </table>`;

  const summaries = r.local.summaries.length
    ? `<h2>Plain-language summaries</h2><p class="muted small">Written locally by a small language model from computed facts only; numbers are checked by code.</p>${r.local.summaries
        .map(
          (s: any) => `<div class="box"><div class="muted small">${esc(names[s.targetId] ?? s.targetId)} · ${s.verified ? 'checked against data' : 'needs review: ' + esc(s.issues.join('; '))}</div><b>${esc(s.headline)}</b><p>${esc(s.summary)}</p><ul>${s.actions.map((a: string) => `<li>${esc(a)}</li>`).join('')}</ul></div>`,
        )
        .join('')}`
    : '';

  const matrix = `
    <table class="matrix">
      <thead><tr><th>Layer</th><th>Check</th>${r.targets.map((t) => `<th class="c">${esc(t.name)}</th>`).join('')}</tr></thead>
      <tbody>${r.matrix
        .map(
          (m) => `<tr><td class="muted small">${LAYER_LABEL[m.layer]}</td><td>${esc(m.title)}<div class="muted small"><code>${esc(m.checkId)}</code> · ${refs(m)}</div></td>${r.targets
            .map((t) => {
              const c = m.cells[t.id];
              return `<td class="c" title="${esc(c?.message)}">${c ? badge(c.status, c.severity) : '<span class="muted">·</span>'}</td>`;
            })
            .join('')}</tr>`,
        )
        .join('')}</tbody>
    </table>`;

  const minN = r.thresholds.latencyMinSamples;
  const quality = r.targets
    .filter((t) => t.endpointStats.length)
    .map(
      (t) => `<h3>${esc(t.name)}</h3>
      <table>
        <thead><tr><th>Endpoint</th><th class="r">Calls</th><th class="r">Available</th><th class="r">Errors</th><th class="r">p50 ms</th><th class="r">p95 ms</th><th class="r">p99 ms</th><th class="r">Max ms</th><th class="r">Server p50</th><th>Status codes</th></tr></thead>
        <tbody>${t.endpointStats
          .map(
            (s: any) => `<tr><td><code>${esc(s.operation)}</code></td><td class="r">${s.samples}</td><td class="r">${s.availabilityPct}%</td><td class="r">${s.errorRatePct}%</td><td class="r">${s.p50}</td><td class="r">${s.samples >= minN ? s.p95 : '<span class="muted" title="too few samples">n&lt;' + minN + '</span>'}</td><td class="r">${s.samples >= minN ? s.p99 : '<span class="muted">-</span>'}</td><td class="r">${s.max}</td><td class="r">${s.serverP50 ?? '-'}</td><td class="small"><code>${esc(Object.entries(s.statuses).map(([k, v]) => `${k}×${v}`).join(' '))}</code></td></tr>`,
          )
          .join('')}</tbody>
      </table>`,
    )
    .join('');

  const findings = r.targets
    .map((t) => {
      const list = r.findings
        .filter((f) => f.targetId === t.id && (f.status === 'fail' || f.status === 'warn'))
        .sort((a, b) => (a.status === b.status ? 0 : a.status === 'fail' ? -1 : 1) || SEV_RANK[a.severity] - SEV_RANK[b.severity]);
      if (!list.length) return `<h3>${esc(t.name)}</h3><p class="muted">No failures or warnings.</p>`;
      return `<h3>${esc(t.name)}</h3>${list
        .map(
          (f) => `<div class="finding">
            <div>${badge(f.status, f.severity)} <b>${esc(f.title)}</b>${f.source === 'ai' ? ' <span class="muted small">AI-generated · not scored</span>' : ''}</div>
            <div class="muted small">${LAYER_LABEL[f.layer]}${f.endpoint ? ` · <code>${esc(f.endpoint)}</code>` : ''} · <code>${esc(f.checkId)}</code></div>
            <p>${esc(f.message)}</p>
            ${f.expected || f.actual ? `<div class="mono small">expected: ${esc(f.expected ?? '-')}<br>actual: ${esc(f.actual ?? '-')}</div>` : ''}
            ${f.fix ? `<p><b>Fix:</b> ${esc(f.fix)}</p>` : ''}
            <div class="small">Standard: ${refs(f)}</div>
            ${f.ai ? `<div class="small muted">AI triage (advisory): ${esc(f.ai.impact)} · owner ${esc(f.ai.owner)} · ${esc(f.ai.gate)}${f.ai.agreesWithRules ? '' : ` · disagrees with rules (AI ${esc(f.ai.aiSeverity)}, rules ${esc(f.severity)})`}</div>` : ''}
          </div>`,
        )
        .join('')}`;
    })
    .join('');

  const pctCell = (v: number | null | undefined) =>
    v === null || v === undefined ? '<span class="muted">-</span>' : `<span class="${v >= r.thresholds.availabilityPct ? 'good' : 'bad'}">${v}%</span>`;
  // Partial periods show their figure in neutral colour with the coverage, not judged against the threshold.
  const monthCell = (b?: { uptimePct: number | null; coveragePct?: number | null; partial?: boolean }) =>
    !b
      ? '<td class="r"><span class="muted">-</span></td>'
      : `<td class="r">${b.partial ? (b.uptimePct === null ? '<span class="muted">-</span>' : `${b.uptimePct}%`) : pctCell(b.uptimePct)}<div class="muted small">${b.coveragePct ?? '-'}% cov${b.partial ? ', partial' : ''}</div></td>`;
  // Table by Tbilisi calendar days (banks, NBG). All times in the report are Georgian time, so no Tashkent table.
  const uptimeTable = (u?: Report['uptime']) => {
    const up = u?.targets.filter((t) => t.lastSample) ?? [];
    const months = [...new Set(up.flatMap((t) => t.monthly.map((m) => m.period)))].sort();
    return up.length
    ? `<h3>${esc(u!.timezone)}</h3><table>
        <thead><tr><th>Target</th><th class="r">Interval</th><th class="r">24 h</th><th class="r">p50 / p95 24 h</th><th class="r">7 days</th><th class="r">30 days</th>${months.map((m) => `<th class="r">${m}</th>`).join('')}<th class="r">Incidents</th></tr></thead>
        <tbody>${up
          .map(
            (t) =>
              `<tr><td>${esc(names[t.targetId] ?? t.targetId)}</td><td class="r">${t.intervalMin} min</td><td class="r">${pctCell(t.last24h)}</td><td class="r">${t.latency24h?.samples ? `${t.latency24h.p50} / ${t.latency24h.p95 ?? '-'} ms<div class="muted small">${t.latency24h.samples} samples</div>` : '<span class="muted">-</span>'}</td><td class="r">${pctCell(t.last7d)}</td><td class="r">${pctCell(t.last30d)}</td>${months.map((m) => monthCell(t.monthly.find((x) => x.period === m))).join('')}<td class="r">${t.incidents.length}</td></tr>`,
          )
          .join('')}</tbody>
      </table>`
    : '<p class="muted">No monitor samples yet. The monitor runs while the Scio server is up.</p>';
  };
  const uptime = uptimeTable(r.uptime);

  const docs = Object.entries(r.standards.documents)
    .map(([k, d]) => `<li><b>${esc(k)}</b>: <a href="${esc(d.url)}">${esc(d.title)}</a></li>`)
    .join('');

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Crect width='64' height='64' rx='14' fill='%230B1220'/%3E%3Cpath d='M12 18 L26 32 L12 46' fill='none' stroke='%23F8FAFC' stroke-width='7' stroke-linecap='round' stroke-linejoin='round'/%3E%3Crect x='34' y='16' width='16' height='32' rx='3' fill='%234ADE80'/%3E%3C/svg%3E">
<title>Scio audit report ${esc(r.run.id)}</title>
<style>
  :root { --fg:#0f172a; --muted:#64748b; --border:#e2e8f0; --brand:#16a34a; --bg:#fff; --good:#1a7f37; --mid:#9a6700; --bad:#cf222e; }
  body { font: 14px/1.5 system-ui, -apple-system, Segoe UI, Roboto, sans-serif; color: var(--fg); background: var(--bg); max-width: 1100px; margin: 0 auto; padding: 24px 16px; }
  h1 { font-size: 22px; margin: 0 0 4px; } h2 { font-size: 17px; margin: 28px 0 8px; border-bottom: 1px solid var(--border); padding-bottom: 4px; } h3 { font-size: 15px; margin: 18px 0 6px; }
  table { width: 100%; border-collapse: collapse; margin: 8px 0; } th, td { border-bottom: 1px solid var(--border); padding: 6px 8px; text-align: left; vertical-align: top; }
  th { font-size: 12px; color: var(--muted); font-weight: 600; } .c { text-align: center; } .r { text-align: right; font-variant-numeric: tabular-nums; }
  .muted { color: var(--muted); } .small { font-size: 12px; } code, .mono { font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 12px; }
  .good { color: var(--good); } .mid { color: var(--mid); } .bad { color: var(--bad); }
  .badge { display: inline-block; border: 1px solid var(--border); border-radius: 4px; padding: 0 5px; font-size: 11px; white-space: nowrap; }
  .badge.pass { color: var(--good); } .badge.fail { color: var(--bad); } .badge.warn { color: var(--mid); } .badge.info, .badge.skip { color: var(--muted); }
  .box, .finding { border: 1px solid var(--border); border-radius: 6px; padding: 10px 12px; margin: 8px 0; page-break-inside: avoid; }
  .logo { font: 700 20px/1 ui-monospace, 'JetBrains Mono', Menlo, Consolas, monospace; display: inline-flex; align-items: center; gap: 6px; margin-bottom: 10px; }
  .logo .p { color: var(--muted); font-weight: 500; } .logo .cur { display: inline-block; width: 9px; height: 18px; border-radius: 2px; background: var(--brand); }
  .note { background: #f1f5f9; border: 1px solid var(--border); border-radius: 6px; padding: 10px 12px; }
  .matrix td, .matrix th { font-size: 12px; } a { color: inherit; }
  @media print { body { padding: 0; } h2 { page-break-after: avoid; } }
</style></head>
<body>
<div class="logo" role="img" aria-label="Scio"><span class="p">&gt;</span><span>scio</span><span class="cur"></span></div>
<h1>Open banking API audit</h1>
<div class="muted">Run <code>${esc(r.run.id)}</code> · started ${esc(fmtTbilisi(r.run.startedAt))} · ${esc(r.run.status)} · generated ${esc(fmtTbilisi(r.generatedAt))}</div>
<div class="muted small">${r.totals.calls} API calls · ${r.totals.findings} results · ${r.totals.failures} failures · ${r.totals.warnings} warnings</div>

<h2>Scope and assumptions</h2>
<div class="note small">
  The organizers supplied only the TBC mock API (simulated data; its results describe the mock, not the real bank).
  Access to real bank sandboxes was obtained by the Scio team directly from the banks: test certificates (QWAC for mTLS, QSealC for request signing)
  from developer portals or issued on request, plus the banks' test users. Those sandboxes run the real journey: consent, signed requests, OAuth, bank login, account reads.
  Banks whose certificates have not arrived yet, and banks with no reachable sandbox, get static checks of their published spec and read-only probes.
  Thresholds are <b>${esc(r.thresholds.source)}</b>${r.thresholds.source === 'assumed' ? ' until NBG regulatory indicators are confirmed' : ''}:
  availability ≥ ${r.thresholds.availabilityPct}%, errors ≤ ${r.thresholds.errorRatePct}%, p95 ≤ ${r.thresholds.latencyP95Ms} ms (p95/p99 reported only with ≥ ${minN} samples).
  Score per layer: passed / (passed + weighted problems), only for targets with at least ${r.thresholds.minEvaluatedChecks} evaluated checks and layers with at least ${r.thresholds.minLayerChecks} (reliability and latency: sample counts instead); fail weighs by severity (high 3, medium 2, low 1), warning half; info, skipped and AI-generated results are not scored.
</div>

<h2>Scorecard</h2>
${scorecard}
${r.common ? `<h3>Like-for-like comparison</h3><p class="muted small">Overall scores rest on different check sets. Here every real bank is scored on the same ${r.common.checkIds.length} checks, the ones all of them received, each counted once (its worst result): ${r.common.checkIds.map((c) => `<code>${esc(c)}</code>`).join(' ')}.</p><table><tr><th>#</th><th>Bank</th><th class="c">Score</th></tr>${[...r.common.targets].sort((a, b) => (r.common!.scores[b] ?? -1) - (r.common!.scores[a] ?? -1)).map((id, i) => `<tr><td>${i + 1}</td><td>${esc(r.targets.find((t) => t.id === id)?.name ?? id)}</td><td class="c">${score(r.common!.scores[id])}</td></tr>`).join('')}</table>` : ''}
${summaries}

<h2>Incompatibility report</h2>
<p class="muted small">One row per check, one column per bank or environment. Empty cell: check not applicable to that target (for example, a journey step the target was not reached at).</p>
${matrix}

<h2>Quality report</h2>
<p class="muted small">Availability, error rate and response times from repeated calls during the run, measured from the auditor's location. Server p50 is bank-reported processing time (Server-Timing).</p>
${quality || '<p class="muted">No timing samples in this run.</p>'}

<h2>Uptime (continuous monitor)</h2>
<p class="muted small">Independent of this run: one unauthenticated, read-only request per target every ${r.monitorIntervals?.simulatedMin ?? '?'} min (mock) or ${r.monitorIntervals?.realMin ?? '?'} min (real banks; spec-only banks are not sampled), aggregated by calendar day and month in Tbilisi time (UTC+4). p50 / p95 24 h: response times of those samples with an HTTP answer, shown for context and not scored (p95 needs 20 samples). Coverage is samples taken against samples expected for the period; partial periods (monitor not running the whole period) are not judged against the threshold. Daily figures: <code>/api/uptime.csv?tz=tbilisi</code>.</p>
${uptime}

<h2>Findings and fixes</h2>
${findings}

<h2>Standards referenced</h2>
<ul class="small">${docs}</ul>
</body></html>`;
}
