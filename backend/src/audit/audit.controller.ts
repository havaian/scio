import { Body, Controller, Get, Header, NotFoundException, Param, Post, Query, Res } from '@nestjs/common';
import type { Response } from 'express';
import { AuditService } from './audit.service';
import { ReportService } from '../reports/report.service';
import { renderHtml } from '../reports/report.html';
import { DbService } from '../storage/db.service';
import { qvac } from '../ai/qvac.engine';
import { MonitorService } from '../monitor/monitor.service';
import { AuditScheduler } from './audit.scheduler';
import { parseTz, toCsv } from '../monitor/uptime';

const AI_STATUS_TTL_MS = 10 * 60_000;
/** Module-level: one status check per 10 minutes for all callers (the promise is shared, so parallel hits wait for one check). */
let aiStatusCache: { at: number; value: Promise<unknown> } | undefined;

@Controller('api')
export class AuditController {
  constructor(
    private readonly audit: AuditService,
    private readonly reports: ReportService,
    private readonly db: DbService,
    private readonly monitor: MonitorService,
    private readonly scheduler: AuditScheduler,
  ) {}

  @Get('health')
  health() {
    return { ok: true, running: this.audit.isRunning() };
  }

  /** Checks the Jev connection with one tiny question. Cached for 10 minutes: each check is a paid Jev call plus local inference. */
  @Get('ai/status')
  aiStatus() {
    if (!aiStatusCache || Date.now() - aiStatusCache.at > AI_STATUS_TTL_MS) aiStatusCache = { at: Date.now(), value: this.checkAi() };
    return aiStatusCache.value;
  }

  private async checkAi() {
    const jev = this.audit.jev;
    let jevStatus: any = { enabled: false, message: 'TYPESAFE_API_KEY is not set' };
    if (jev.enabled) {
      try {
        const r = await jev.ask('HTTP 400 FORMAT_ERROR: X-Request-ID must be a valid UUID', {
          isError: { type: 'noul', instructions: 'This text describes an error.' },
        });
        jevStatus = { enabled: true, ok: true, model: r.model, answer: r.answers.isError, usage: r.usage };
      } catch (e: any) {
        jevStatus = { enabled: true, ok: false, message: e.message };
      }
    }
    let qvacStatus: any = { enabled: false, message: 'QVAC_ENABLED is not true' };
    if (qvac.enabled) {
      try {
        const v = await qvac.embed(['health check']);
        qvacStatus = { enabled: true, ok: true, embeddingDims: v[0].length };
      } catch (e: any) {
        qvacStatus = { enabled: true, ok: false, message: e.message };
      }
    }
    return { jev: jevStatus, qvac: qvacStatus, checkedAt: new Date().toISOString() };
  }

  @Get('runs')
  runs() {
    return this.db.listRuns();
  }

  @Post('runs')
  start(@Body() body: { targets?: string[] }) {
    return this.audit.start(body?.targets);
  }

  /** Automated audit schedule: slots (Tbilisi time), next run, whether manual runs are allowed. */
  @Get('runs/schedule')
  schedule() {
    return this.scheduler.info();
  }

  /** Daily audit quota: limit, used today, remaining, reset time. */
  @Get('runs/quota')
  quota() {
    return this.audit.quota();
  }

  @Get('runs/:id')
  run(@Param('id') id: string) {
    const run = this.db.getRun(id);
    if (!run) throw new NotFoundException();
    return run;
  }

  /** Full report for a run; "latest" picks the most recent completed run. */
  @Get('reports/:id')
  report(@Param('id') id: string) {
    return this.reports.build(id === 'latest' ? undefined : id);
  }

  /** Report as a file download: format "html" (printable) or "json" (full report data). */
  @Get('reports/:id/download/:format')
  download(@Param('id') id: string, @Param('format') format: string, @Res({ passthrough: true }) res: Response) {
    if (format !== 'html' && format !== 'json') throw new NotFoundException('Format must be html or json');
    const report = this.reports.build(id === 'latest' ? undefined : id);
    res.setHeader('Content-Type', format === 'html' ? 'text/html; charset=utf-8' : 'application/json; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="scio-report-${report.run.id}.${format}"`);
    return format === 'html' ? renderHtml(report) : JSON.stringify(report, null, 2);
  }

  @Get('reports/:id/html')
  @Header('Content-Type', 'text/html; charset=utf-8')
  reportHtml(@Param('id') id: string) {
    return renderHtml(this.reports.build(id === 'latest' ? undefined : id));
  }

  /** Continuous availability: daily and monthly uptime per target (?tz=tbilisi|tashkent calendar days, default Tbilisi). */
  @Get('uptime')
  uptime(@Query('days') days?: string, @Query('tz') tz?: string) {
    return this.monitor.uptime(clampDays(days), parseTz(tz));
  }

  /** Same data as CSV, one row per target and day, for supervisors' spreadsheets. */
  @Get('uptime.csv')
  @Header('Content-Type', 'text/csv; charset=utf-8')
  uptimeCsv(@Query('days') days: string | undefined, @Query('tz') tz: string | undefined, @Res({ passthrough: true }) res: Response) {
    const u = this.monitor.uptime(clampDays(days), parseTz(tz));
    res.setHeader('Content-Disposition', `attachment; filename="scio-uptime-${u.tz}.csv"`);
    return toCsv(u.targets, Object.fromEntries(this.audit.targets().map((t) => [t.id, t.name])), u.tz);
  }

  /** Hour-of-day latency (p50, p95, up%) per target and monitor operation over the last ?days= days (default 7), Tbilisi hours by default. */
  @Get('latency-profile')
  latencyProfile(@Query('days') days?: string, @Query('tz') tz?: string) {
    const n = Number(days ?? 7);
    return this.monitor.latencyProfile(Number.isFinite(n) ? Math.min(100, Math.max(1, Math.round(n))) : 7, parseTz(tz));
  }

  @Get('reports/:id/exchanges')
  exchanges(@Param('id') id: string, @Query('target') target?: string, @Query('operation') operation?: string) {
    const runId = id === 'latest' ? this.db.latestDoneRunId() : id;
    if (!runId) throw new NotFoundException();
    // operation: comma-separated names; "neg.x" also matches "neg.x.token" etc.
    const ops = operation?.split(',').filter(Boolean);
    const all = this.reports.exchanges(runId, target);
    return ops?.length ? all.filter((x) => ops.some((o) => x.operation === o || x.operation.startsWith(`${o}.`))) : all;
  }
}

function clampDays(v?: string): number {
  const n = Number(v ?? 31);
  return Number.isFinite(n) ? Math.min(100, Math.max(1, Math.round(n))) : 31;
}
