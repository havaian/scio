import 'reflect-metadata';
// The CLI runs one audit and exits: no background uptime monitor, no scheduler.
// Forced off (not defaulted): inside the container MONITOR_ENABLED / AUDIT_SCHEDULE_ENABLED are true for the server,
// and a second monitor and scheduler in the CLI process would duplicate samples and could start a second audit.
process.env.MONITOR_ENABLED = 'false';
process.env.AUDIT_SCHEDULE_ENABLED = 'false';
// Alerts are sent by the server only; a CLI run next to it must not poll and send them twice.
process.env.ALERTS_ENABLED = 'false';
// Log timestamps in Georgian time (UTC+4) on any machine; stored times stay ISO UTC.
process.env.TZ = 'Asia/Tbilisi';
import { NestFactory } from '@nestjs/core';
import { mkdirSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { AppModule } from './app.module';
import { AuditService } from './audit/audit.service';
import { ReportService } from './reports/report.service';
import { fmtTbilisi, renderHtml } from './reports/report.html';

/**
 * Headless audit: npm run audit -- [--targets tbc-mock,paysera-ge] [--out reports]
 * Writes report.json and report.html, prints the scorecard, exits non-zero on high-severity failures.
 * Refused with exit code 2 while another audit is running (server or another CLI; checked in the database).
 */
async function main() {
  const args = process.argv.slice(2);
  const arg = (name: string) => {
    const i = args.indexOf(`--${name}`);
    return i >= 0 ? args[i + 1] : undefined;
  };
  const targets = arg('targets')?.split(',').filter(Boolean);
  const outDir = resolve(arg('out') ?? 'reports');

  const app = await NestFactory.createApplicationContext(AppModule, { logger: ['error', 'warn', 'log'] });
  const run = await app.get(AuditService).runToCompletion(targets);
  const report = app.get(ReportService).build(run.id);

  const dir = resolve(outDir, run.id);
  mkdirSync(dir, { recursive: true });
  writeFileSync(resolve(dir, 'report.json'), JSON.stringify(report, null, 2));
  writeFileSync(resolve(dir, 'report.html'), renderHtml(report));

  console.log(`\nRun ${run.id}: ${run.status} (started ${fmtTbilisi(run.startedAt)}${run.finishedAt ? `, finished ${fmtTbilisi(run.finishedAt)}` : ''})`);
  console.table(
    report.targets.map((t) => ({ target: t.id, ...t.scores, overall: t.overall, fail: t.counts.fail, warn: t.counts.warn })),
  );
  console.log(`Reports: ${dir}`);
  const high = report.findings.filter((f) => f.status === 'fail' && f.severity === 'high').length;
  await app.close();
  process.exit(run.status !== 'done' ? 2 : high ? 1 : 0);
}

main().catch((e) => {
  // Guardrail refusals (already running, too soon after a real-bank run) are plain messages, not crashes.
  console.error(typeof e?.getStatus === 'function' ? `Not started: ${e.message}` : e);
  process.exit(2);
});
