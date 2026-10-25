import { Exchange } from '../common/types';
import { percentile } from '../checks/performance.checks';

/**
 * Uptime aggregation for NBG-style daily and monthly availability metrics.
 * Days and months are calendar periods in Tbilisi time (UTC+4) or Tashkent time (UTC+5); neither has daylight saving.
 */
export const TBILISI_OFFSET_MS = 4 * 3600_000;

/** Operation of the uptime samples. The authenticated monitor calls (AIS_OP_PREFIX) are latency samples only, never uptime. */
export const FRONT_DOOR_OP = 'monitor.front-door';
export const AIS_OP_PREFIX = 'monitor.ais.';

/** Calendar used for daily and monthly buckets. */
export const UPTIME_TZ = {
  tbilisi: { offsetMs: TBILISI_OFFSET_MS, label: 'Asia/Tbilisi (UTC+4)', iana: 'Asia/Tbilisi' },
  tashkent: { offsetMs: 5 * 3600_000, label: 'Asia/Tashkent (UTC+5)', iana: 'Asia/Tashkent' },
} as const;
export type UptimeTz = keyof typeof UPTIME_TZ;
export const parseTz = (v?: string): UptimeTz => (v === 'tashkent' ? 'tashkent' : 'tbilisi');

export interface UptimeBucket {
  period: string; // YYYY-MM-DD or YYYY-MM
  samples: number;
  up: number;
  uptimePct: number | null;
  /** Samples with an HTTP answer. The rest were judged on the TLS handshake alone (alive, but the API itself unseen). */
  httpSamples: number;
  p50: number | null;
  p95: number | null;
  /** Samples expected over the whole calendar period (period length / interval). */
  expected: number;
  /** Samples taken against samples expected, capped at 100. */
  coveragePct: number | null;
  /** The period is not wholly observed: it began before the window or the monitor's first sample, or has not ended. Not judged against the threshold. */
  partial: boolean;
}

export interface Incident {
  start: string;
  end: string;
  samples: number;
  reason: string;
}

export interface TargetUptime {
  targetId: string;
  name?: string;
  intervalMin: number;
  lastSample?: { ts: string; up: boolean; status: number; error?: string };
  last24h: number | null;
  last7d: number | null;
  last30d: number | null;
  /**
   * Latency of the monitor's front-door samples with an HTTP answer over the last 24 h (one light request per interval).
   * Shown next to the audit's own timings so real banks have a latency figure resting on enough samples; never scored.
   * p95 only with at least 20 samples, as everywhere else.
   */
  latency24h: { samples: number; p50: number | null; p95: number | null };
  daily: UptimeBucket[];
  monthly: UptimeBucket[];
  incidents: Incident[];
}

const pct = (up: number, n: number) => (n ? Math.round((up / n) * 10000) / 100 : null);

/** UTC start and end of a local calendar day (YYYY-MM-DD) or month (YYYY-MM). */
function periodBounds(period: string, offsetMs: number): [number, number] {
  const [y, m, d] = period.split('-').map(Number);
  if (d) return [Date.UTC(y, m - 1, d) - offsetMs, Date.UTC(y, m - 1, d + 1) - offsetMs];
  return [Date.UTC(y, m - 1, 1) - offsetMs, Date.UTC(y, m, 1) - offsetMs];
}

/** Coverage context: interval, the window start, the monitor's first sample and now (all UTC ms). */
interface Span {
  intervalMs: number;
  since: number;
  first: number;
  now: number;
  offsetMs: number;
}

function bucket(period: string, xs: Exchange[], span: Span): UptimeBucket {
  const up = xs.filter((x) => x.ok);
  const d = up.filter((x) => x.status > 0).map((x) => x.durationMs);
  const [start, end] = periodBounds(period, span.offsetMs);
  const expected = Math.max(1, Math.round((end - start) / span.intervalMs));
  const partial = start < span.since || start < span.first - span.intervalMs || end > span.now;
  return { period, samples: xs.length, up: up.length, uptimePct: pct(up.length, xs.length), httpSamples: xs.filter((x) => x.status > 0).length, p50: d.length ? percentile(d, 50) : null, p95: d.length >= 20 ? percentile(d, 95) : null, expected, coveragePct: Math.min(100, pct(xs.length, expected) ?? 0), partial };
}

function groupBy(xs: Exchange[], key: (x: Exchange) => string, span: Span): UptimeBucket[] {
  const m = new Map<string, Exchange[]>();
  for (const x of xs) m.set(key(x), [...(m.get(key(x)) ?? []), x]);
  return [...m.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => bucket(k, v, span));
}

/** Start of the local calendar day `days - 1` days before today, so the first daily bucket is a whole day. */
export function windowStart(days: number, now = Date.now(), offsetMs = TBILISI_OFFSET_MS): number {
  const localToday = Math.floor((now + offsetMs) / 86400_000) * 86400_000;
  return localToday - (days - 1) * 86400_000 - offsetMs;
}

/**
 * Samples must be monitor exchanges of one target, sorted by ts (authenticated monitor.ais.* calls are ignored). `ok` = the service answered.
 * `windowFrom`: start of the queried window (defaults to the first sample), used to flag partial periods.
 */
export function aggregate(targetId: string, intervalMin: number, xs: Exchange[], now = Date.now(), offsetMs = TBILISI_OFFSET_MS, windowFrom?: number): TargetUptime {
  const local = (iso: string) => new Date(Date.parse(iso) + offsetMs).toISOString();
  // Re-derive up/down from status and error, so a corrected rule also applies to stored history.
  // Authenticated probe calls do not count: they run on another schedule and would skew uptime and coverage.
  xs = xs.filter((x) => !x.operation.startsWith(AIS_OP_PREFIX)).map((x) => ({ ...x, ok: isUp(x.status, x.error) }));
  const since = (ms: number) => {
    const s = xs.filter((x) => Date.parse(x.ts) >= now - ms);
    return pct(s.filter((x) => x.ok).length, s.length);
  };

  // Consecutive failed samples form one incident; a monitor gap of more than two intervals ends it (nothing is known in between).
  const intervalMs = intervalMin * 60_000;
  const incidents: Incident[] = [];
  let cur: Incident | undefined;
  let prev: number | undefined;
  for (const x of xs) {
    const t = Date.parse(x.ts);
    if (cur && prev !== undefined && t - prev > 2 * intervalMs) {
      incidents.push(cur);
      cur = undefined;
    }
    prev = t;
    if (!x.ok) {
      const reason = x.error ?? `HTTP ${x.status}`;
      if (cur) Object.assign(cur, { end: x.ts, samples: cur.samples + 1 });
      else cur = { start: x.ts, end: x.ts, samples: 1, reason };
    } else if (cur) {
      incidents.push(cur);
      cur = undefined;
    }
  }
  if (cur) incidents.push(cur);

  const last = xs[xs.length - 1];
  const first = xs.length ? Date.parse(xs[0].ts) : now;
  // Same rule as a daily bucket: answered samples with an HTTP status (TLS-only answers carry no API timing).
  const recent = xs.filter((x) => Date.parse(x.ts) >= now - 86400_000 && x.ok && x.status > 0).map((x) => x.durationMs);
  const span: Span = { intervalMs, since: windowFrom ?? first, first, now, offsetMs };
  return {
    targetId,
    intervalMin,
    lastSample: last ? { ts: last.ts, up: last.ok, status: last.status, error: last.error } : undefined,
    last24h: since(86400_000),
    last7d: since(7 * 86400_000),
    last30d: since(30 * 86400_000),
    latency24h: { samples: recent.length, p50: recent.length ? percentile(recent, 50) : null, p95: recent.length >= 20 ? percentile(recent, 95) : null },
    daily: groupBy(xs, (x) => local(x.ts).slice(0, 10), span),
    monthly: groupBy(xs, (x) => local(x.ts).slice(0, 7), span),
    incidents: incidents.reverse().slice(0, 50),
  };
}

/** Is this probe answer evidence that the service is up? */
export function isUp(status: number, error?: string): boolean {
  if (status > 0) return status < 500;
  const e = error ?? '';
  // Expired, not yet valid or wrong-name certificates stop every TPP: down, even though the host answered.
  if (/CERT_HAS_EXPIRED|CERT_NOT_YET_VALID|ERR_TLS_CERT_ALTNAME|altname/i.test(e)) return false;
  if (/timeout|ECONNREFUSED|ENOTFOUND|EAI_AGAIN/i.test(e)) return false;
  // A TLS refusal for a missing client certificate means the server is alive and enforcing mTLS.
  // A server certificate we cannot verify (e.g. incomplete chain) also proves the server answered: up, flagged elsewhere.
  return /certificate|CERT|SSL|TLS|LEAF_SIGNATURE|handshake|alert|EPROTO/i.test(e);
}

/** Daily CSV for supervisors: one row per target and day. */
export function toCsv(rows: TargetUptime[], names: Record<string, string>, tz: UptimeTz = 'tbilisi'): string {
  // http_samples: samples with an HTTP answer; the others were judged on the TLS handshake only.
  // coverage_pct (last, so earlier columns keep their position): samples taken against samples expected for the day.
  const lines = [`target_id,target_name,date_${tz},samples,up,uptime_pct,http_samples,p50_ms,p95_ms,coverage_pct`];
  for (const r of rows)
    for (const d of r.daily) lines.push([r.targetId, `"${(names[r.targetId] ?? r.targetId).replace(/"/g, '""')}"`, d.period, d.samples, d.up, d.uptimePct ?? '', d.httpSamples, d.p50 ?? '', d.p95 ?? '', d.coveragePct ?? ''].join(','));
  return lines.join('\n') + '\n';
}
