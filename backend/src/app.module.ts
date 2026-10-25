import { Module } from '@nestjs/common';
import { AuditController } from './audit/audit.controller';
import { AuditService } from './audit/audit.service';
import { ReportService } from './reports/report.service';
import { DbService } from './storage/db.service';
import { MonitorService } from './monitor/monitor.service';
import { AuditScheduler } from './audit/audit.scheduler';
import { AlertsService } from './alerts/alerts.service';
import { AlertsController } from './alerts/alerts.controller';
import { McpController } from './mcp/mcp.controller';
import { MetricsController } from './metrics/metrics.controller';

@Module({
  controllers: [AuditController, AlertsController, McpController, MetricsController],
  providers: [DbService, AuditService, ReportService, MonitorService, AuditScheduler, AlertsService],
})
export class AppModule {}
