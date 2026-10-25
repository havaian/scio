import { Injectable, Logger, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import type { Dispatcher } from 'undici';
import { HttpRecorder, newRequestId } from '../common/http';
import { loadCredentials, RequestSigner, targetCaDispatcher } from '../common/credentials';
import { loadTargets, loadThresholds } from '../common/config';
import { TargetConfig } from '../common/types';
import { DbService } from '../storage/db.service';
import { aggregate, isUp, TargetUptime, UPTIME_TZ, UptimeTz, windowStart } from './uptime';
import { AisProbe, authenticatedTarget } from './ais-probe';
import { PROFILE_MIN_SAMPLES, ProfileRow, profileRows } from './latency-profile';

/**
 * Continuous availability monitor (NBG: "periodically monitor availability, provide daily and monthly uptime").
 * One light, unauthenticated, read-only request per target per interval:
 *  - simulated targets (the organizers' mock) every monitor.simulatedIntervalMin (default 5)
 *  - real banks every monitor.realIntervalMin (config/thresholds.json: 5; 30 when unset)
 * Simulated full-mode targets (the mock, never real banks) also get a light authenticated AIS journey every
 * monitor.authenticatedIntervalMin (default 15): accounts, balances, transactions, reusing consent and token until expiry.
 * Those are latency samples for the hour-of-day profile (monitor.ais.*), never counted in uptime.
 * Samples are stored as exchanges with run_id NULL. Disable with MONITOR_ENABLED=false.
 */
@Injectable()
export class MonitorService implements OnModuleInit, OnModuleDestroy {
  private readonly log = new Logger('Monitor');
  private timers: NodeJS.Timeout[] = [];
  /** Per target: the bank's test certificate (mTLS + seal) or its published test CA, loaded once. */
  private clients = new Map<string, { dispatcher?: Dispatcher; signer?: RequestSigner; signBase?: string; mode: string }>();

  private readonly ais = new AisProbe();

  constructor(private readonly db: DbService) {}

  get enabled(): boolean {
    return process.env.MONITOR_ENABLED !== 'false';
  }

  intervalMin(t: TargetConfig): number {
    const i = this.intervals();
    return t.simulated ? i.simulatedMin : i.realMin;
  }

  /** Sampling intervals from config, for reports that describe the monitor. */
  intervals(): { simulatedMin: number; realMin: number; authenticatedMin: number } {
    const m = loadThresholds().monitor ?? {};
    // authenticatedMin 0 turns the authenticated probes off.
    return { simulatedMin: m.simulatedIntervalMin ?? 5, realMin: m.realIntervalMin ?? 30, authenticatedMin: m.authenticatedIntervalMin ?? 15 };
  }

  /** uptime() results for ~60 s per period and calendar: reports and the dashboard ask often, samples change every few minutes. */
  private uptimeCache = new Map<string, { at: number; value: ReturnType<MonitorService['uptime']> }>();
  /** latencyProfile() results, cached the same way. */
  private profileCache = new Map<string, { at: number; value: ReturnType<MonitorService['latencyProfile']> }>();

  /** The URL sampled for a target: the XS2A front door, or the discovery document when endpoint probes are off. */
  probeUrl(t: TargetConfig): string {
    if (t.skipEndpointProbes && t.discoveryUrl) return t.discoveryUrl;
    return `${t.baseUrl.replace(/\/$/, '')}${t.accountsPath ?? '/v1/accounts'}`;
  }

  onModuleInit() {
    if (!this.enabled) return;
    const retentionDays = loadThresholds().monitor?.retentionDays ?? 100;
    this.db.pruneMonitor(new Date(Date.now() - retentionDays * 86400_000).toISOString());
    // Spec-only targets have no API host to sample.
    const sampled = loadTargets().filter((x) => !x.specOnly);
    for (const t of sampled) {
      const every = this.intervalMin(t) * 60_000;
      // Spread the first samples so targets are not hit at the same second.
      const first = setTimeout(() => this.sample(t), 2000 + Math.random() * 20_000);
      const loop = setInterval(() => this.sample(t), every);
      first.unref();
      loop.unref();
      this.timers.push(first, loop);
    }
    const authEvery = this.intervals().authenticatedMin;
    const authed = authEvery > 0 ? sampled.filter(authenticatedTarget) : [];
    for (const t of authed) {
      const first = setTimeout(() => this.sampleAis(t), 30_000 + Math.random() * 30_000);
      const loop = setInterval(() => this.sampleAis(t), authEvery * 60_000);
      first.unref();
      loop.unref();
      this.timers.push(first, loop);
    }
    this.log.log(`monitoring ${sampled.length} targets${authed.length ? `, authenticated AIS probes on ${authed.map((t) => t.id).join(', ')} every ${authEvery} min` : ''}`);
  }

  onModuleDestroy() {
    for (const t of this.timers) clearTimeout(t);
  }

  /**
   * How the monitor reaches a target. With the bank's test certificate it gets a real HTTP answer (401 without a token)
   * instead of a TLS refusal, so up/down and latency describe the API, not only the TLS listener.
   */
  client(t: TargetConfig) {
    let c = this.clients.get(t.id);
    if (!c) {
      const creds = t.credentials ? loadCredentials(t) : undefined;
      if (creds && typeof creds !== 'string') c = { dispatcher: creds.dispatcher, signer: creds.signer, signBase: t.baseUrl, mode: 'mtls' };
      else {
        const ca = targetCaDispatcher(t);
        c = ca ? { dispatcher: ca.dispatcher, mode: 'bank-ca' } : { mode: 'public' };
      }
      this.clients.set(t.id, c);
    }
    return c;
  }

  async sample(t: TargetConfig) {
    try {
      const probe = async () => {
        const c = this.client(t);
        const http = new HttpRecorder(t.id, loadThresholds().requestTimeoutMs, { dispatcher: c.dispatcher, signer: c.signer, signBase: c.signBase });
        await http.request({ operation: 'monitor.front-door', method: 'GET', url: this.probeUrl(t), headers: { 'X-Request-ID': newRequestId() } });
        for (const x of http.exchanges) x.ok = isUp(x.status, x.error);
        return http.exchanges;
      };
      let xs = await probe();
      // Confirm a failure before recording it: one failed request from the probe's own network is not a bank outage.
      // Only the confirming sample is stored, so an outage shorter than confirmDownSec is not counted.
      if (xs.some((x) => !x.ok)) {
        const wait = (loadThresholds().monitor?.confirmDownSec ?? 30) * 1000;
        await new Promise((res) => setTimeout(res, wait));
        xs = await probe();
      }
      this.db.insertExchanges(null, xs);
    } catch (e: any) {
      this.log.warn(`${t.id}: sample failed: ${e?.message ?? e}`);
    }
  }

  /** Authenticated AIS probe (simulated targets only). Never throws: a failed probe is logged and skipped. */
  async sampleAis(t: TargetConfig) {
    try {
      if (!authenticatedTarget(t)) return;
      const c = this.client(t);
      const xs = await this.ais.run(t, { dispatcher: c.dispatcher, signer: c.signer, signBase: c.signBase });
      if (xs.length) this.db.insertExchanges(null, xs);
    } catch (e: any) {
      this.log.warn(`${t.id}: authenticated probe failed: ${e?.message ?? e}`);
    }
  }

  /** Hour-of-day latency per target and monitor operation over the last `days` days (Tbilisi or Tashkent hours). Cached ~60 s. */
  latencyProfile(days = 7, tz: UptimeTz = 'tbilisi'): {
    generatedAt: string;
    tz: UptimeTz;
    timezone: string;
    days: number;
    latencyP95Ms: number;
    source: string;
    minSamples: number;
    enabled: boolean;
    intervals: { simulatedMin: number; realMin: number; authenticatedMin: number };
    targets: { targetId: string; name: string; simulated: boolean; intervalMin: number; rows: ProfileRow[] }[];
  } {
    const key = `${days}:${tz}`;
    const hit = this.profileCache.get(key);
    if (hit && Date.now() - hit.at < 60_000) return hit.value;
    const th = loadThresholds();
    const samples = this.db.monitorSamples(new Date(Date.now() - days * 86400_000).toISOString());
    const targets = loadTargets()
      .filter((t) => !t.specOnly)
      .map((t) => ({ targetId: t.id, name: t.name, simulated: t.simulated, intervalMin: this.intervalMin(t), rows: profileRows(samples.filter((x) => x.targetId === t.id), UPTIME_TZ[tz].offsetMs) }));
    const value = { generatedAt: new Date().toISOString(), tz, timezone: UPTIME_TZ[tz].label, days, latencyP95Ms: th.latencyP95Ms, source: th.source, minSamples: PROFILE_MIN_SAMPLES, enabled: this.enabled, intervals: this.intervals(), targets };
    this.profileCache.set(key, { at: Date.now(), value });
    return value;
  }

  /** Uptime per target over the last `days` days, bucketed by Tbilisi or Tashkent calendar days. */
  uptime(days = 31, tz: UptimeTz = 'tbilisi'): { generatedAt: string; tz: UptimeTz; timezone: string; availabilityPct: number; source: string; enabled: boolean; intervals: { simulatedMin: number; realMin: number }; targets: TargetUptime[] } {
    const key = `${days}:${tz}`;
    const hit = this.uptimeCache.get(key);
    if (hit && Date.now() - hit.at < 60_000) return hit.value;
    const value = this.computeUptime(days, tz);
    this.uptimeCache.set(key, { at: Date.now(), value });
    return value;
  }

  private computeUptime(days: number, tz: UptimeTz): ReturnType<MonitorService['uptime']> {
    const th = loadThresholds();
    // Whole calendar days: the window starts at local midnight, so the first day is not cut in the middle.
    const sinceMs = windowStart(days, Date.now(), UPTIME_TZ[tz].offsetMs);
    const since = new Date(sinceMs).toISOString();
    const samples = this.db.monitorSamples(since);
    const targets = loadTargets()
      .filter((t) => !t.specOnly)
      .map((t) => ({
      ...aggregate(
        t.id,
        this.intervalMin(t),
        samples.filter((x) => x.targetId === t.id),
        Date.now(),
        UPTIME_TZ[tz].offsetMs,
        sinceMs,
      ),
      name: t.name,
      // public = plain HTTPS; bank-ca = the bank's published test CA; mtls = the bank's test certificate (real HTTP answers).
      access: this.client(t).mode,
    }));
    return { generatedAt: new Date().toISOString(), tz, timezone: UPTIME_TZ[tz].label, availabilityPct: th.availabilityPct, source: th.source, enabled: this.enabled, intervals: this.intervals(), targets };
  }
}
