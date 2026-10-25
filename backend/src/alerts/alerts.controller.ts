import { Controller, Get } from '@nestjs/common';
import { loadTargets } from '../common/config';
import { DbService } from '../storage/db.service';
import { AlertsService } from './alerts.service';

/** Read-only: whether alerting is on, which channels (names only, never tokens or addresses), and the last 50 alerts. */
@Controller('api/alerts')
export class AlertsController {
  constructor(
    private readonly db: DbService,
    private readonly alerts: AlertsService,
  ) {}

  @Get()
  list() {
    const names = new Map(loadTargets().map((t) => [t.id, t.name]));
    return {
      enabled: this.alerts.enabled,
      channels: this.alerts.channelNames(),
      alerts: this.db.recentAlerts(50).map((a) => ({
        ts: a.ts,
        rule: a.rule,
        targetId: a.targetId,
        bank: a.targetId ? names.get(a.targetId) ?? a.targetId : undefined,
        message: a.message,
        channels: a.channels,
        ok: a.ok,
      })),
    };
  }
}
