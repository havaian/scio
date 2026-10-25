import { Exchange } from '../common/types';
import { api } from '../flows/full.flow';
import { AuditContext, sleep } from './context';

export function percentile(values: number[], p: number): number {
  if (!values.length) return 0;
  const s = [...values].sort((a, b) => a - b);
  const idx = Math.min(s.length - 1, Math.max(0, Math.ceil((p / 100) * s.length) - 1));
  return Math.round(s[idx]);
}

export interface EndpointStats {
  operation: string;
  samples: number;
  availabilityPct: number;
  errorRatePct: number;
  p50: number;
  p95: number;
  p99: number;
  max: number;
  serverP50?: number;
  statuses: Record<string, number>;
}

/** Availability counts any HTTP answer below 500; errors are timeouts, 5xx and 429. */
export function stats(operation: string, xs: Exchange[]): EndpointStats {
  const durations = xs.filter((x) => x.status > 0).map((x) => x.durationMs);
  const server = xs.map((x) => x.serverTimingMs).filter((v): v is number => typeof v === 'number');
  const available = xs.filter((x) => x.status > 0 && x.status < 500).length;
  const errors = xs.filter((x) => x.status === 0 || x.status >= 500 || x.status === 429).length;
  const statuses: Record<string, number> = {};
  for (const x of xs) statuses[x.status === 0 ? 'timeout/conn' : String(x.status)] = (statuses[x.status === 0 ? 'timeout/conn' : String(x.status)] ?? 0) + 1;
  return {
    operation,
    samples: xs.length,
    availabilityPct: xs.length ? Math.round((available / xs.length) * 1000) / 10 : 0,
    errorRatePct: xs.length ? Math.round((errors / xs.length) * 1000) / 10 : 0,
    p50: percentile(durations, 50),
    p95: percentile(durations, 95),
    p99: percentile(durations, 99),
    max: Math.round(Math.max(0, ...durations)),
    serverP50: server.length ? percentile(server, 50) : undefined,
    statuses,
  };
}

/**
 * Latency verdict. With fewer than latencyMinSamples calls, p95 and p99 are just the slowest call,
 * so the median is judged instead and the finding says so.
 */
export function latencyFinding(ctx: AuditContext, s: EndpointStats, assumed: string, severityIfSlow?: 'high' | 'medium' | 'low') {
  const t = ctx.thresholds;
  const minN = t.latencyMinSamples ?? 20;
  const enough = s.samples >= minN;
  const value = enough ? s.p95 : s.p50;
  const ok = value <= t.latencyP95Ms;
  const server = s.serverP50 !== undefined ? `; server-reported p50 ${s.serverP50} ms, so ~${Math.max(0, s.p50 - s.serverP50)} ms is network and TLS from the probe location` : '';
  ctx.add({
    checkId: 'lat.p95',
    layer: 'latency',
    status: ok ? 'pass' : enough ? 'fail' : 'warn',
    severity: ok ? 'none' : severityIfSlow ?? (value > t.latencyP95Ms * 2 ? 'high' : 'medium'),
    title: 'Response time',
    endpoint: s.operation,
    message: enough
      ? `p50 ${s.p50} ms, p95 ${s.p95} ms, p99 ${s.p99} ms, max ${s.max} ms over ${s.samples} calls${server}.`
      : `p50 ${s.p50} ms, max ${s.max} ms over ${s.samples} calls. Too few samples for p95 (needs ${minN}), so the median is judged${server}.`,
    expected: `${enough ? 'p95' : 'p50'} <= ${t.latencyP95Ms} ms${assumed}`,
    actual: `${enough ? 'p95' : 'p50'} ${value} ms (n=${s.samples})`,
    fix: ok ? undefined : 'Profile this endpoint; for transaction lists, page results and index by account and booking date.',
    // No clause sets a latency target: no reference, the report shows "no clause (assumed threshold)".
    evidence: s,
  });
}

/** Layers 2 and 3: repeated probes of the main read endpoints, compared with thresholds. */
export async function runProbes(ctx: AuditContext, probes: { operation: string; path: string; absolute?: boolean; auth?: boolean; consent?: boolean; token?: string; consentId?: string }[]) {
  const t = ctx.thresholds;
  for (let i = 0; i < t.probeRepetitions; i++) {
    for (const p of probes) {
      await api(ctx, `probe.${p.operation}`, 'GET', p.path, { absolute: p.absolute, auth: p.auth, consent: p.consent ?? p.auth, token: p.token, consentId: p.consentId, validate: false });
      await sleep(t.probeSpacingMs);
    }
  }
  const all = ctx.http.exchanges.filter((x) => x.operation.startsWith('probe.'));
  const byOp = new Map<string, Exchange[]>();
  for (const x of all) byOp.set(x.operation.slice(6), [...(byOp.get(x.operation.slice(6)) ?? []), x]);

  ctx.state.endpointStats = [] as EndpointStats[];
  for (const [op, xs] of byOp) {
    const s = stats(op, xs);
    ctx.state.endpointStats.push(s);
    const assumed = t.source === 'assumed' ? ' (assumed threshold until NBG indicators are confirmed)' : '';

    const availOk = s.availabilityPct >= t.availabilityPct && s.errorRatePct <= t.errorRatePct;
    ctx.add({
      checkId: 'rel.availability',
      layer: 'reliability',
      status: availOk ? 'pass' : 'fail',
      severity: availOk ? 'none' : s.availabilityPct < 95 ? 'high' : 'medium',
      title: 'Availability and error rate',
      endpoint: op,
      message: `${s.availabilityPct}% available, ${s.errorRatePct}% errors over ${s.samples} calls. Status mix: ${Object.entries(s.statuses).map(([k, v]) => `${k}×${v}`).join(', ')}.`,
      expected: `>= ${t.availabilityPct}% available, <= ${t.errorRatePct}% errors${assumed}`,
      actual: `${s.availabilityPct}% / ${s.errorRatePct}%`,
      fix: availOk ? undefined : 'Investigate 5xx and timeouts in this window; publish a status page and return Retry-After with 429/503 so TPPs can back off.',
      // No clause sets a numeric availability target; the standard map lists the 503 and Retry-After clauses.
      evidence: s,
    });

    latencyFinding(ctx, s, assumed);
  }

  // Retry-After on throttling or outage.
  const throttled = all.filter((x) => x.status === 429 || x.status === 503);
  if (throttled.length) {
    const noRetry = throttled.filter((x) => !x.responseHeaders['retry-after']);
    ctx.add({ checkId: 'rel.retry-after', layer: 'reliability', status: noRetry.length ? 'fail' : 'pass', severity: noRetry.length ? 'low' : 'none', title: 'Retry-After on 429/503', message: noRetry.length ? `${noRetry.length} of ${throttled.length} throttling/outage responses lack Retry-After.` : `All ${throttled.length} throttling/outage responses carry Retry-After.`, fix: noRetry.length ? 'Send Retry-After with 429 and 503 responses.' : undefined, reference: 'RFC 9110 (Retry-After)' });
  }
}
