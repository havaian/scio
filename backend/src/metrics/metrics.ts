import { LAYERS } from '../common/types';
import type { Report } from '../reports/report.service';
import type { TargetUptime } from '../monitor/uptime';
import { isUp } from '../monitor/uptime';

/**
 * Prometheus text exposition (format 0.0.4) of what the dashboard already shows: monitor state and uptime per target,
 * and the latest audit's scores and finding counts. Read-only; lets Grafana (or any Prometheus scraper) chart Scio
 * without a second data store. Gauges only: every value is recomputed from the database at scrape time.
 */
export interface MetricsInput {
  /** Latest completed audit, or undefined when there is none yet. */
  report?: Report;
  /** Monitor uptime per target (MonitorService.uptime). */
  uptime: { availabilityPct: number; source: string; targets: TargetUptime[] };
  /** Latest monitor sample per target (status, error, duration). */
  latest: (targetId: string) => { ts: string; status: number; error?: string; durationMs: number } | undefined;
}

const esc = (v: string) => v.replace(/\\/g, '\\\\').replace(/\n/g, '\\n').replace(/"/g, '\\"');
const labels = (l: Record<string, string | undefined>) => {
  const parts = Object.entries(l)
    .filter(([, v]) => v !== undefined && v !== '')
    .map(([k, v]) => `${k}="${esc(String(v))}"`);
  return parts.length ? `{${parts.join(',')}}` : '';
};

export function renderMetrics(input: MetricsInput): string {
  const out: string[] = [];
  const families = new Map<string, { help: string; rows: string[] }>();
  const gauge = (name: string, help: string, l: Record<string, string | undefined>, value: number | null | undefined) => {
    if (value === null || value === undefined || !Number.isFinite(value)) return;
    if (!families.has(name)) families.set(name, { help, rows: [] });
    families.get(name)!.rows.push(`${name}${labels(l)} ${value}`);
  };

  // Monitor
  gauge('scio_availability_threshold_percent', 'Availability threshold (assumed until NBG publishes indicators when source="assumed").', { source: input.uptime.source }, input.uptime.availabilityPct);
  for (const t of input.uptime.targets) {
    const base = { target: t.targetId, name: t.name };
    const x = input.latest(t.targetId);
    if (x) {
      gauge('scio_monitor_up', 'Latest monitor sample: 1 up, 0 down (same rule as the uptime figures and alerts).', base, isUp(x.status, x.error) ? 1 : 0);
      gauge('scio_monitor_http_status', 'HTTP status of the latest monitor sample (0 = no HTTP answer, judged on the TLS handshake).', base, x.status);
      gauge('scio_monitor_duration_ms', 'Response time of the latest monitor sample in milliseconds.', base, x.durationMs);
      gauge('scio_monitor_last_sample_timestamp_seconds', 'Unix time of the latest monitor sample.', base, Math.round(Date.parse(x.ts) / 1000));
    }
    for (const [window, v] of [['24h', t.last24h], ['7d', t.last7d], ['30d', t.last30d]] as const) gauge('scio_uptime_percent', 'Monitor uptime over a rolling window, percent of samples up.', { ...base, window }, v);
    gauge('scio_incidents', 'Outage incidents in the monitor window (most recent 50 at most).', base, t.incidents.length);
  }

  // Latest audit
  const r = input.report;
  if (r) {
    const run = { run: r.run.id };
    const finished = Date.parse(r.run.finishedAt ?? r.run.startedAt);
    gauge('scio_audit_last_run_timestamp_seconds', 'Unix time the latest completed audit finished.', run, Number.isFinite(finished) ? Math.round(finished / 1000) : undefined);
    for (const t of r.targets) {
      const base = { target: t.id, bank: t.bank, access: t.access };
      gauge('scio_audit_score', 'Latest audit score 0-100 per layer ("overall" = mean of scored layers). Absent when too few checks.', { ...base, layer: 'overall' }, t.overall);
      for (const l of LAYERS) gauge('scio_audit_score', 'Latest audit score 0-100 per layer ("overall" = mean of scored layers). Absent when too few checks.', { ...base, layer: l }, t.scores[l]);
      gauge('scio_audit_evaluated_checks', 'Rule-based checks with a verdict behind the overall score.', base, t.evaluated);
      if (r.common && t.id in r.common.scores) gauge('scio_audit_like_for_like_score', 'Score on the checks every scored real bank received (the fair cross-bank comparison).', base, r.common.scores[t.id]);
    }
    // Finding counts per target, status and severity (rule-based only; AI output is advisory and never counted).
    const counts = new Map<string, { target: string; status: string; severity: string; n: number }>();
    for (const f of r.findings) {
      if (f.source === 'ai') continue;
      const k = `${f.targetId}|${f.status}|${f.severity}`;
      const c = counts.get(k) ?? { target: f.targetId, status: f.status, severity: f.severity, n: 0 };
      c.n++;
      counts.set(k, c);
    }
    for (const c of counts.values()) gauge('scio_audit_findings', 'Findings of the latest audit by target, status and severity (rule-based).', { target: c.target, status: c.status, severity: c.severity }, c.n);
  }

  for (const [name, f] of families) {
    out.push(`# HELP ${name} ${f.help}`, `# TYPE ${name} gauge`, ...f.rows);
  }
  return `${out.join('\n')}\n`;
}
