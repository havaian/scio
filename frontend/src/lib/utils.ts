import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export const LAYERS = ['conformance', 'reliability', 'latency', 'security', 'data'] as const;
export type Layer = (typeof LAYERS)[number];

export const LAYER_LABEL: Record<Layer, string> = {
  conformance: 'Standard compatibility',
  reliability: 'Performance & reliability',
  latency: 'Latency',
  security: 'Security',
  data: 'Data quality',
};

/** Short layer names for narrow screens. */
export const LAYER_SHORT: Record<string, string> = {
  conformance: 'Standard',
  reliability: 'Reliability',
  latency: 'Latency',
  security: 'Security',
  data: 'Data',
};

export function scoreTone(v: number | null | undefined): string {
  if (v === null || v === undefined) return 'text-muted-foreground';
  return v >= 85 ? 'text-[var(--status-good)]' : v >= 60 ? 'text-[#b7791f] dark:text-[var(--status-warning)]' : 'text-[var(--status-critical)]';
}

/** All times are shown in Georgian time (UTC+4, no daylight saving), whatever the viewer's zone is. */
export const TBILISI_TZ = 'Asia/Tbilisi';
export const TZ_LABEL = 'Tbilisi';

/** "23 Oct 2026, 13:00 Tbilisi". With an explicit time zone: that zone, without the label. */
export function fmtTime(iso?: string, timeZone?: string) {
  if (!iso) return '';
  const s = new Date(iso).toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'short', timeZone: timeZone ?? TBILISI_TZ });
  return timeZone ? s : `${s} ${TZ_LABEL}`;
}

/** Short Tbilisi time without the year, e.g. "23 Oct, 13:00". */
export function fmtShort(iso?: string) {
  if (!iso) return '';
  return new Date(iso).toLocaleString('en-GB', { timeZone: TBILISI_TZ, day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' });
}

/** Short label for how far Scio got with a target. Older reports without "access" fall back to the mode. */
export const ACCESS_LABEL: Record<string, string> = {
  mock: "organizers' mock · full flow",
  full: 'full flow',
  sandbox: 'bank sandbox · mTLS + signed',
  pending: 'sandbox · awaiting certificates',
  bis: 'proprietary API (BIS)',
  spec: 'published spec only',
  probes: 'public probes',
};
export function accessOf(t: { access?: string; mode: string; simulated: boolean }): string {
  return t.access ?? (t.simulated ? 'mock' : t.mode === 'full' ? 'full' : t.mode === 'bis' ? 'bis' : 'probes');
}

/** Journey steps per access level, each tied to the check that records it (first id found wins). */
export const JOURNEY: Record<string, { label: string; checks: string[] }[]> = {
  sandbox: [
    { label: 'Consent created', checks: ['flow.consent'] },
    { label: 'Bank login + token', checks: ['flow.authorize', 'flow.token'] },
    { label: 'Consent valid', checks: ['flow.consent-valid'] },
    { label: 'Accounts read', checks: ['flow.sandbox'] },
  ],
  mock: [
    { label: 'AIS consent + login', checks: ['flow.authorize', 'flow.consent'] },
    { label: 'Payments', checks: ['pis.authorize', 'pis.create'] },
    { label: 'Deposits + loans', checks: ['v2.authorize', 'v2.consent'] },
  ],
  full: [
    { label: 'AIS consent + login', checks: ['flow.authorize', 'flow.consent'] },
    { label: 'Payments', checks: ['pis.authorize'] },
  ],
  bis: [
    { label: 'Token (client credentials)', checks: ['bis.token'] },
    { label: 'Account reads', checks: ['bis.movements', 'bis.balance', 'bis.flow'] },
  ],
};
JOURNEY.pending = JOURNEY.sandbox;
