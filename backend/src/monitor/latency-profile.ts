import { Exchange } from '../common/types';
import { percentile } from '../checks/performance.checks';
import { FRONT_DOOR_OP, isUp, TBILISI_OFFSET_MS } from './uptime';

/** Monitor operations: the unauthenticated front door (uptime) and the authenticated AIS reads on simulated targets. */
export const MONITOR_OPS = {
  frontDoor: FRONT_DOOR_OP,
  accounts: 'monitor.ais.accounts',
  balances: 'monitor.ais.balances',
  transactions: 'monitor.ais.transactions',
  /** Consent, authorize and token calls: stored for the log, never in latency or uptime statistics. */
  setup: 'monitor.ais.setup',
} as const;

/** Operations shown in the hour-of-day profile, in display order. */
export const PROFILE_OPS: string[] = [MONITOR_OPS.frontDoor, MONITOR_OPS.accounts, MONITOR_OPS.balances, MONITOR_OPS.transactions];

/** Below this many HTTP answers an hour's latency is shown greyed and p95 is not given. */
export const PROFILE_MIN_SAMPLES = 3;

export interface HourCell {
  hour: number;
  /** All samples in this hour (with or without an HTTP answer). */
  samples: number;
  /** Samples with an HTTP answer: the latency figures come from these. */
  httpSamples: number;
  p50: number | null;
  p95: number | null;
  upPct: number | null;
}

export interface ProfileRow {
  operation: string;
  hours: HourCell[];
}

/**
 * Hour-of-day latency profile of one target: per operation and local hour (0-23), samples, p50, p95 and up%.
 * Latency uses samples with an HTTP answer; up% uses every sample (a timeout is down). Setup calls are ignored.
 * The front-door row is always present; authenticated rows only when the target has such samples.
 */
export function profileRows(xs: Exchange[], offsetMs = TBILISI_OFFSET_MS): ProfileRow[] {
  const rows: ProfileRow[] = [];
  for (const op of PROFILE_OPS) {
    const ofOp = xs.filter((x) => x.operation === op);
    if (!ofOp.length && op !== MONITOR_OPS.frontDoor) continue;
    const byHour: Exchange[][] = Array.from({ length: 24 }, () => []);
    for (const x of ofOp) byHour[new Date(Date.parse(x.ts) + offsetMs).getUTCHours()].push(x);
    rows.push({ operation: op, hours: byHour.map((h, hour) => hourCell(hour, h)) });
  }
  return rows;
}

export function hourCell(hour: number, xs: Exchange[]): HourCell {
  const d = xs.filter((x) => x.status > 0).map((x) => x.durationMs);
  const up = xs.filter((x) => isUp(x.status, x.error)).length;
  return {
    hour,
    samples: xs.length,
    httpSamples: d.length,
    p50: d.length ? percentile(d, 50) : null,
    p95: d.length >= PROFILE_MIN_SAMPLES ? percentile(d, 95) : null,
    upPct: xs.length ? Math.round((up / xs.length) * 10000) / 100 : null,
  };
}
