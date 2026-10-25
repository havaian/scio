import { Injectable, OnModuleDestroy } from '@nestjs/common';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
// Built-in SQLite (Node >= 22.13). No native build step needed on Windows or in Docker.
import { DatabaseSync } from 'node:sqlite';
import { Exchange, Finding, RunSummary } from '../common/types';

@Injectable()
export class DbService implements OnModuleDestroy {
  private db: DatabaseSync;

  constructor() {
    const file = process.env.DB_FILE ?? 'data/scio.sqlite';
    mkdirSync(dirname(file), { recursive: true });
    this.db = new DatabaseSync(file);
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      -- The server (monitor) and the CLI may write at the same time: wait for the lock instead of failing.
      PRAGMA busy_timeout = 30000;
      CREATE TABLE IF NOT EXISTS runs (
        id TEXT PRIMARY KEY, started_at TEXT, finished_at TEXT, status TEXT,
        targets TEXT, thresholds_source TEXT, error TEXT
      );
      CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT, target_id TEXT, check_id TEXT,
        layer TEXT, status TEXT, severity TEXT, title TEXT, endpoint TEXT, message TEXT,
        expected TEXT, actual TEXT, fix TEXT, reference TEXT, evidence TEXT, ai TEXT, source TEXT
      );
      CREATE TABLE IF NOT EXISTS run_ai (
        run_id TEXT, kind TEXT, target_id TEXT, data TEXT
      );
      CREATE TABLE IF NOT EXISTS exchanges (
        id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT, target_id TEXT, operation TEXT,
        method TEXT, url TEXT, status INTEGER, ok INTEGER, duration_ms REAL, server_timing_ms REAL,
        error TEXT, request_headers TEXT, response_headers TEXT, body_snippet TEXT, ts TEXT
      );
      CREATE TABLE IF NOT EXISTS endpoint_stats (
        run_id TEXT, target_id TEXT, data TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
      CREATE INDEX IF NOT EXISTS idx_exchanges_run ON exchanges(run_id);
      CREATE INDEX IF NOT EXISTS idx_exchanges_target_ts ON exchanges(target_id, ts);
    `);
    // Databases created before the AI layer lack the ai column.
    for (const col of ['ai', 'source']) {
      try {
        this.db.exec(`ALTER TABLE findings ADD COLUMN ${col} TEXT`);
      } catch {
        /* column exists */
      }
    }
    // Databases created before the daily quota counted API runs only lack runs.source.
    try {
      this.db.exec(`ALTER TABLE runs ADD COLUMN source TEXT`);
    } catch {
      /* column exists */
    }
    // Alerting: per-rule state (survives restarts, so nothing is re-alerted) and the log of alerts sent.
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS alert_state (key TEXT PRIMARY KEY, value TEXT, updated_at TEXT);
      CREATE TABLE IF NOT EXISTS alerts_sent (
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, rule TEXT, target_id TEXT, key TEXT,
        message TEXT, channels TEXT, ok INTEGER
      );
      CREATE INDEX IF NOT EXISTS idx_alerts_sent_key ON alerts_sent(rule, key, ts);
    `);
  }

  /**
   * Runs left 'running' by a stopped server (restart, crash, redeploy) are marked failed. Called by the server at start-up
   * only, not by the CLI, so a CLI start never ends the server's live run. CLI runs may still be alive in their own
   * process, so they are only marked once older than `cliStaleMs`. Returns the number of runs marked.
   */
  failInterruptedRuns(cliStaleMs = 2 * 3600_000): number {
    const r = this.db
      .prepare(`UPDATE runs SET status = 'failed', finished_at = ?, error = 'interrupted (server restart)' WHERE status = 'running' AND (IFNULL(source, '') != 'cli' OR started_at < ?)`)
      .run(new Date().toISOString(), new Date(Date.now() - cliStaleMs).toISOString());
    return Number(r.changes ?? 0);
  }

  onModuleDestroy() {
    this.db.close();
  }

  createRun(run: RunSummary) {
    this.db
      .prepare(
        `INSERT INTO runs (id, started_at, status, targets, thresholds_source, source) VALUES (?, ?, ?, ?, ?, ?)`,
      )
      .run(run.id, run.startedAt, run.status, JSON.stringify(run.targets), run.thresholdsSource, run.source ?? null);
  }

  /**
   * Creates the run unless another one (from any process: server or CLI) is still 'running' and started after
   * `runningSince`. Check and insert share one write transaction. Returns the blocking run, or undefined when created.
   */
  createRunIfIdle(run: RunSummary, runningSince: string): RunSummary | undefined {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const busy = this.db.prepare(`SELECT * FROM runs WHERE status = 'running' AND started_at >= ? ORDER BY started_at DESC LIMIT 1`).get(runningSince) as any;
      if (!busy) this.createRun(run);
      this.db.exec('COMMIT');
      return busy ? toRun(busy) : undefined;
    } catch (e) {
      this.db.exec('ROLLBACK');
      throw e;
    }
  }

  /** The newest run still 'running' that started after a timestamp (any process). */
  runningSince(sinceIso: string): RunSummary | undefined {
    const row = this.db.prepare(`SELECT * FROM runs WHERE status = 'running' AND started_at >= ? ORDER BY started_at DESC LIMIT 1`).get(sinceIso) as any;
    return row ? toRun(row) : undefined;
  }

  /** Runs started since a timestamp, any status, newest first (e.g. for the gap between runs that touch real banks). */
  runsStartedSince(sinceIso: string): RunSummary[] {
    const rows = this.db.prepare(`SELECT * FROM runs WHERE started_at >= ? ORDER BY started_at DESC`).all(sinceIso) as any[];
    return rows.map(toRun);
  }

  finishRun(id: string, status: RunSummary['status'], error?: string) {
    this.db
      .prepare(`UPDATE runs SET finished_at = ?, status = ?, error = ? WHERE id = ?`)
      .run(new Date().toISOString(), status, error ?? null, id);
  }

  listRuns(limit = 50): RunSummary[] {
    const rows = this.db
      .prepare(`SELECT * FROM runs ORDER BY started_at DESC LIMIT ?`)
      .all(limit) as any[];
    return rows.map(toRun);
  }

  getRun(id: string): RunSummary | undefined {
    const row = this.db.prepare(`SELECT * FROM runs WHERE id = ?`).get(id) as any;
    return row ? toRun(row) : undefined;
  }

  /**
   * Runs started since a timestamp, failed ones excluded (a crash should not use up the quota).
   * `source` limits the count to one origin (the quota counts 'api' runs); `includeFailed` counts every status.
   */
  countRunsSince(sinceIso: string, opts: { source?: RunSummary['source']; includeFailed?: boolean } = {}): number {
    const row = this.db
      .prepare(`SELECT COUNT(*) AS n FROM runs WHERE started_at >= ?${opts.includeFailed ? '' : ` AND status != 'failed'`}${opts.source ? ' AND source = ?' : ''}`)
      .get(...(opts.source ? [sinceIso, opts.source] : [sinceIso])) as any;
    return Number(row?.n ?? 0);
  }

  latestDoneRunId(): string | undefined {
    const row = this.db
      .prepare(`SELECT id FROM runs WHERE status = 'done' ORDER BY started_at DESC LIMIT 1`)
      .get() as any;
    return row?.id;
  }

  insertFindings(runId: string, findings: Finding[]) {
    const stmt = this.db.prepare(
      `INSERT INTO findings (run_id, target_id, check_id, layer, status, severity, title, endpoint,
        message, expected, actual, fix, reference, evidence, ai, source)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    );
    for (const f of findings) {
      stmt.run(
        runId, f.targetId, f.checkId, f.layer, f.status, f.severity, f.title, f.endpoint ?? null,
        f.message, f.expected ?? null, f.actual ?? null, f.fix ?? null, f.reference ?? null,
        f.evidence === undefined ? null : JSON.stringify(f.evidence),
        f.ai === undefined ? null : JSON.stringify(f.ai),
        f.source ?? 'rules',
      );
    }
  }

  insertExchanges(runId: string | null, exchanges: Exchange[]) {
    const stmt = this.db.prepare(
      `INSERT INTO exchanges (run_id, target_id, operation, method, url, status, ok, duration_ms,
        server_timing_ms, error, request_headers, response_headers, body_snippet, ts)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    );
    for (const x of exchanges) {
      stmt.run(
        runId, x.targetId, x.operation, x.method, x.url, x.status, x.ok ? 1 : 0, x.durationMs,
        x.serverTimingMs ?? null, x.error ?? null, JSON.stringify(x.requestHeaders),
        JSON.stringify(x.responseHeaders), x.bodySnippet, x.ts,
      );
    }
  }

  insertStats(runId: string, targetId: string, stats: unknown[]) {
    const stmt = this.db.prepare(`INSERT INTO endpoint_stats (run_id, target_id, data) VALUES (?, ?, ?)`);
    for (const s of stats) stmt.run(runId, targetId, JSON.stringify(s));
  }

  stats(runId: string): { targetId: string; data: any }[] {
    const rows = this.db.prepare(`SELECT * FROM endpoint_stats WHERE run_id = ?`).all(runId) as any[];
    return rows.map((r) => ({ targetId: r.target_id, data: JSON.parse(r.data) }));
  }

  putRunAi(runId: string, kind: string, targetId: string | null, data: unknown) {
    this.db.prepare(`INSERT INTO run_ai (run_id, kind, target_id, data) VALUES (?, ?, ?, ?)`).run(runId, kind, targetId, JSON.stringify(data));
  }

  runAi(runId: string): { kind: string; targetId?: string; data: any }[] {
    const rows = this.db.prepare(`SELECT * FROM run_ai WHERE run_id = ?`).all(runId) as any[];
    return rows.map((r) => ({ kind: r.kind, targetId: r.target_id ?? undefined, data: JSON.parse(r.data) }));
  }

  findings(runId: string): Finding[] {
    const rows = this.db.prepare(`SELECT * FROM findings WHERE run_id = ? ORDER BY id`).all(runId) as any[];
    return rows.map((r) => ({
      runId: r.run_id,
      targetId: r.target_id,
      checkId: r.check_id,
      layer: r.layer,
      status: r.status,
      severity: r.severity,
      title: r.title,
      endpoint: r.endpoint ?? undefined,
      message: r.message,
      expected: r.expected ?? undefined,
      actual: r.actual ?? undefined,
      fix: r.fix ?? undefined,
      reference: r.reference ?? undefined,
      evidence: r.evidence ? JSON.parse(r.evidence) : undefined,
      ai: r.ai ? JSON.parse(r.ai) : undefined,
      source: r.source ?? 'rules',
    }));
  }

  countExchanges(runId: string): number {
    const row = this.db.prepare(`SELECT COUNT(*) AS n FROM exchanges WHERE run_id = ?`).get(runId) as any;
    return Number(row?.n ?? 0);
  }

  exchanges(runId: string): Exchange[] {
    const rows = this.db.prepare(`SELECT * FROM exchanges WHERE run_id = ? ORDER BY id`).all(runId) as any[];
    return rows.map(toExchange);
  }

  /** Monitor samples (run_id IS NULL) since a timestamp, for time-series charts. */
  monitorSamples(sinceIso: string): Exchange[] {
    const rows = this.db
      .prepare(`SELECT * FROM exchanges WHERE run_id IS NULL AND ts >= ? ORDER BY ts`)
      .all(sinceIso) as any[];
    return rows.map(toExchange);
  }

  /** Deletes every audit run with its findings, AI results, stats and call log. Monitor samples (run_id NULL) stay. */
  clearRuns(): { runs: number; findings: number; exchanges: number } {
    const count = (sql: string) => Number((this.db.prepare(sql).get() as any)?.n ?? 0);
    const out = {
      runs: count(`SELECT COUNT(*) AS n FROM runs`),
      findings: count(`SELECT COUNT(*) AS n FROM findings`),
      exchanges: count(`SELECT COUNT(*) AS n FROM exchanges WHERE run_id IS NOT NULL`),
    };
    this.db.exec(`
      BEGIN;
      DELETE FROM findings;
      DELETE FROM run_ai;
      DELETE FROM endpoint_stats;
      DELETE FROM exchanges WHERE run_id IS NOT NULL;
      DELETE FROM runs;
      COMMIT;
    `);
    return out;
  }

  /** Drops monitor samples older than the retention window. */
  pruneMonitor(beforeIso: string) {
    this.db.prepare(`DELETE FROM exchanges WHERE run_id IS NULL AND ts < ?`).run(beforeIso);
  }

  /** Alerting state value (JSON), or undefined when never set. */
  alertState<T = any>(key: string): T | undefined {
    const row = this.db.prepare(`SELECT value FROM alert_state WHERE key = ?`).get(key) as any;
    return row ? JSON.parse(row.value) : undefined;
  }

  setAlertState(key: string, value: unknown) {
    this.db
      .prepare(`INSERT INTO alert_state (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`)
      .run(key, JSON.stringify(value), new Date().toISOString());
  }

  insertAlert(a: { ts: string; rule: string; targetId?: string; key: string; message: string; channels: string; ok: boolean }) {
    this.db
      .prepare(`INSERT INTO alerts_sent (ts, rule, target_id, key, message, channels, ok) VALUES (?, ?, ?, ?, ?, ?, ?)`)
      .run(a.ts, a.rule, a.targetId ?? null, a.key, a.message, a.channels, a.ok ? 1 : 0);
  }

  /** Time of the last alert for a rule and key (sent or attempted), for repeat limits. */
  lastAlertAt(rule: string, key: string): string | undefined {
    const row = this.db.prepare(`SELECT ts FROM alerts_sent WHERE rule = ? AND key = ? ORDER BY ts DESC LIMIT 1`).get(rule, key) as any;
    return row?.ts;
  }

  recentAlerts(limit = 50): { ts: string; rule: string; targetId?: string; key: string; message: string; channels: string; ok: boolean }[] {
    const rows = this.db.prepare(`SELECT * FROM alerts_sent ORDER BY ts DESC, id DESC LIMIT ?`).all(limit) as any[];
    return rows.map((r) => ({ ts: r.ts, rule: r.rule, targetId: r.target_id ?? undefined, key: r.key, message: r.message, channels: r.channels, ok: !!r.ok }));
  }

  /** Monitor samples (run_id IS NULL) of one target and operation since a timestamp, oldest first. */
  monitorSamplesFor(targetId: string, operation: string, sinceIso: string): Exchange[] {
    const rows = this.db
      .prepare(`SELECT * FROM exchanges WHERE run_id IS NULL AND target_id = ? AND operation = ? AND ts >= ? ORDER BY ts`)
      .all(targetId, operation, sinceIso) as any[];
    return rows.map(toExchange);
  }

  /** The newest monitor sample of one target and operation. */
  latestMonitorSample(targetId: string, operation: string): Exchange | undefined {
    const row = this.db
      .prepare(`SELECT * FROM exchanges WHERE run_id IS NULL AND target_id = ? AND operation = ? ORDER BY ts DESC LIMIT 1`)
      .get(targetId, operation) as any;
    return row ? toExchange(row) : undefined;
  }

  /** Finished ('done') runs, oldest first. */
  doneRuns(): RunSummary[] {
    const rows = this.db.prepare(`SELECT * FROM runs WHERE status = 'done' ORDER BY started_at, id`).all() as any[];
    return rows.map(toRun);
  }
}

function toRun(r: any): RunSummary {
  return {
    id: r.id,
    startedAt: r.started_at,
    finishedAt: r.finished_at ?? undefined,
    status: r.status,
    targets: JSON.parse(r.targets ?? '[]'),
    thresholdsSource: r.thresholds_source,
    error: r.error ?? undefined,
    source: r.source ?? undefined,
  };
}

function toExchange(r: any): Exchange {
  return {
    runId: r.run_id ?? undefined,
    targetId: r.target_id,
    operation: r.operation,
    method: r.method,
    url: r.url,
    status: r.status,
    ok: !!r.ok,
    durationMs: r.duration_ms,
    serverTimingMs: r.server_timing_ms ?? undefined,
    error: r.error ?? undefined,
    requestHeaders: JSON.parse(r.request_headers ?? '{}'),
    responseHeaders: JSON.parse(r.response_headers ?? '{}'),
    bodySnippet: r.body_snippet,
    ts: r.ts,
  };
}
