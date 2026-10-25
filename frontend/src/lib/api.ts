import type { Layer } from './utils';

export type Status = 'pass' | 'fail' | 'warn' | 'info' | 'skip';
export type Severity = 'high' | 'medium' | 'low' | 'none';

export interface Finding {
  targetId: string;
  checkId: string;
  layer: Layer;
  status: Status;
  severity: Severity;
  title: string;
  endpoint?: string;
  message: string;
  expected?: string;
  actual?: string;
  fix?: string;
  reference?: string;
  evidence?: unknown;
  ai?: AiTriage;
  source?: 'rules' | 'ai';
  standard?: StandardRef | null;
}

export interface StandardRef {
  refs: string[];
  verified: boolean;
  note?: string;
}

export interface AiTriage {
  model: string;
  impact: string;
  impactConfidence: number;
  owner: string;
  ownerConfidence: number;
  gate: 'auto' | 'review' | 'human';
  aiSeverity: Severity;
  agreesWithRules: boolean;
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

export type TargetAccess = 'mock' | 'full' | 'sandbox' | 'pending' | 'bis' | 'spec' | 'probes';

export interface TargetReport {
  id: string;
  name: string;
  bank: string;
  mode: 'full' | 'passive' | 'bis';
  simulated: boolean;
  /** How far Scio got: organizers' mock, bank sandbox (team-obtained certificates), awaiting certificates, BIS, spec only, public probes. */
  access?: TargetAccess;
  baseUrl: string;
  source?: string;
  note?: string;
  scores: Record<Layer, number | null>;
  /** Rule-based verdicts per layer (older reports lack it). */
  layerChecks?: Record<Layer, number>;
  overall: number | null;
  evaluated: number;
  counts: Record<Status, number>;
  endpointStats: EndpointStats[];
}

export interface Run {
  id: string;
  startedAt: string;
  finishedAt?: string;
  status: 'running' | 'done' | 'failed';
  targets: string[];
  thresholdsSource: string;
  error?: string;
}

export interface Report {
  run: Run;
  ai: { enabled: boolean; note?: string; models: string[]; triaged: number; auto: number; review: number; human: number; disagreements: number };
  local: {
    enabled: boolean;
    note?: string;
    summaries: { targetId: string; model: string; headline: string; summary: string; actions: string[]; verified: boolean; issues: string[] }[];
    clusters: { model: string; threshold: number; clusters: { label: string; size: number; targets: string[]; checks: string[]; cohesion: number; members: { targetId: string; checkId: string; title: string; endpoint?: string }[] }[] } | null;
  };
  standards: { documents: Record<string, { title: string; url: string }> };
  generatedAt: string;
  thresholds: { source: string; availabilityPct: number; errorRatePct: number; latencyP95Ms: number; latencyMinSamples: number; minEvaluatedChecks: number; minLayerChecks?: number };
  /** Like-for-like ranking: only the checks every scored real bank received. */
  common?: { targets: string[]; checkIds: string[]; scores: Record<string, number | null> } | null;
  targets: TargetReport[];
  matrix: { checkId: string; title: string; layer: Layer; standard?: StandardRef | null; cells: Record<string, { status: Status; severity: Severity; count: number; message: string } | null> }[];
  findings: Finding[];
  totals: { findings: number; failures: number; warnings: number; calls: number };
  /** Uptime monitor, attached fresh when the report is served (Tbilisi calendar). */
  uptime?: Uptime;
}

export interface Exchange {
  operation: string;
  method: string;
  url: string;
  status: number;
  durationMs: number;
  serverTimingMs?: number;
  error?: string;
  requestHeaders: Record<string, string>;
  responseHeaders: Record<string, string>;
  bodySnippet: string;
  ts: string;
}

export interface UptimeBucket {
  period: string;
  samples: number;
  up: number;
  uptimePct: number | null;
  p50: number | null;
  p95: number | null;
  /** Samples expected for the whole period (period length / interval). */
  expected?: number;
  /** Samples taken against samples expected, capped at 100. */
  coveragePct?: number | null;
  /** Period not wholly observed (before the window or the first sample, or still running): not judged against the threshold. */
  partial?: boolean;
}

export interface TargetUptime {
  targetId: string;
  name?: string;
  intervalMin: number;
  lastSample?: { ts: string; up: boolean; status: number; error?: string };
  last24h: number | null;
  last7d: number | null;
  last30d: number | null;
  /** Monitor front-door latency over the last 24 h (samples with an HTTP answer); shown, not scored. Older servers omit it. */
  latency24h?: { samples: number; p50: number | null; p95: number | null };
  daily: UptimeBucket[];
  monthly: UptimeBucket[];
  incidents: { start: string; end: string; samples: number; reason: string }[];
}

export type UptimeTz = 'tbilisi' | 'tashkent';

/** One daily audit slot, HH:MM in the schedule's time zone (Tbilisi). */
export interface ScheduleSlot {
  time: string;
  targets: 'all' | 'simulated';
}

/** GET /api/runs/schedule. `time`/`nextAt` are kept for older servers; `slots`/`next` may be missing there. */
export interface Schedule {
  enabled: boolean;
  time: string;
  timezone: string;
  nextAt: string | null;
  manualRuns: boolean;
  slots?: ScheduleSlot[];
  next?: (ScheduleSlot & { at: string }) | null;
}

export interface Uptime {
  generatedAt: string;
  tz: UptimeTz;
  timezone: string;
  availabilityPct: number;
  source: string;
  enabled: boolean;
  /** Sampling intervals from config. */
  intervals?: { simulatedMin: number; realMin: number };
  targets: TargetUptime[];
}

/** One local hour of the hour-of-day latency profile. Latency from samples with an HTTP answer, up% from all samples. */
export interface LatencyHour {
  hour: number;
  samples: number;
  httpSamples: number;
  p50: number | null;
  p95: number | null;
  upPct: number | null;
}

export interface LatencyProfile {
  generatedAt: string;
  tz: UptimeTz;
  timezone: string;
  days: number;
  latencyP95Ms: number;
  source: string;
  /** Below this many HTTP answers an hour is greyed (and has no p95). */
  minSamples: number;
  enabled: boolean;
  intervals: { simulatedMin: number; realMin: number; authenticatedMin: number };
  targets: { targetId: string; name: string; simulated: boolean; intervalMin: number; rows: { operation: string; hours: LatencyHour[] }[] }[];
}

const BASE = import.meta.env.VITE_API_URL ?? '';

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const r = await fetch(`${BASE}${path}`, { headers: { 'Content-Type': 'application/json' }, ...init });
  if (!r.ok) {
    const body = await r.json().catch(() => ({}));
    throw new Error(body?.message ?? `HTTP ${r.status}`);
  }
  return r.json();
}

export const api = {
  report: (id = 'latest') => req<Report>(`/api/reports/${id}`),
  runs: () => req<Run[]>('/api/runs'),
  run: (id: string) => req<Run>(`/api/runs/${id}`),
  schedule: () => req<Schedule>('/api/runs/schedule'),
  quota: () => req<{ limit: number; used: number; remaining: number | null; resetsAt: string; timezone: string }>('/api/runs/quota'),
  start: (targets?: string[]) => req<Run>('/api/runs', { method: 'POST', body: JSON.stringify({ targets }) }),
  htmlUrl: (id = 'latest') => `${BASE}/api/reports/${id}/html`,
  downloadUrl: (id: string, format: 'html' | 'json') => `${BASE}/api/reports/${id}/download/${format}`,
  exchanges: (runId: string, target: string, operations: string[]) =>
    req<Exchange[]>(`/api/reports/${runId}/exchanges?target=${encodeURIComponent(target)}&operation=${encodeURIComponent(operations.join(','))}`),
  uptime: (days = 31, tz: UptimeTz = 'tbilisi') => req<Uptime>(`/api/uptime?days=${days}&tz=${tz}`),
  uptimeCsvUrl: (days = 31, tz: UptimeTz = 'tbilisi') => `${BASE}/api/uptime.csv?days=${days}&tz=${tz}`,
  latencyProfile: (days = 7) => req<LatencyProfile>(`/api/latency-profile?days=${days}`),
};
