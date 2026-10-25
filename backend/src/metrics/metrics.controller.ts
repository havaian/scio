import { Controller, Get, Res } from '@nestjs/common';
import type { Response } from 'express';
import { FRONT_DOOR_OP } from '../monitor/uptime';
import { MonitorService } from '../monitor/monitor.service';
import { ReportService } from '../reports/report.service';
import { DbService } from '../storage/db.service';
import { renderMetrics } from './metrics';

/** GET /api/metrics: Prometheus text format for Grafana or any scraper. Read-only, same data as the dashboard. */
@Controller('api/metrics')
export class MetricsController {
  constructor(
    private readonly reports: ReportService,
    private readonly monitor: MonitorService,
    private readonly db: DbService,
  ) {}

  @Get()
  get(@Res() res: Response) {
    let report;
    try {
      report = this.reports.build();
    } catch {
      // no completed audit yet: monitor metrics only
    }
    const body = renderMetrics({
      report,
      uptime: this.monitor.uptime(31, 'tbilisi'),
      latest: (id) => this.db.latestMonitorSample(id, FRONT_DOOR_OP),
    });
    res.status(200).type('text/plain; version=0.0.4; charset=utf-8').send(body);
  }
}
