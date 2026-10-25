// Recent alerts from GET /api/alerts (read-only; channel names only, no tokens or addresses).

export interface AlertItem {
  ts: string;
  rule: string;
  targetId?: string;
  bank?: string;
  message: string;
  /** e.g. "telegram:ok,email:failed" */
  channels: string;
  ok: boolean;
}

export interface AlertsResponse {
  enabled: boolean;
  channels: string[];
  alerts: AlertItem[];
}

const BASE = import.meta.env.VITE_API_URL ?? '';

export async function fetchAlerts(): Promise<AlertsResponse> {
  const r = await fetch(`${BASE}/api/alerts`);
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

export const RULE_LABEL: Record<string, string> = {
  down: 'Down',
  recovered: 'Recovered',
  latency: 'Slow',
  'latency-ok': 'Latency normal',
  'new-high-findings': 'New high findings',
  'cert-expiry': 'Certificate',
  'audit-finished': 'Audit finished',
};

/** Alert time in Tbilisi time. */
export function tbilisiTime(iso: string): string {
  return new Date(iso).toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'short', timeZone: 'Asia/Tbilisi' });
}
