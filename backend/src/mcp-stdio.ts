import 'reflect-metadata';
// Local MCP server over stdio for Claude Desktop/Code or Cursor: reads the same database as the server, never samples or audits.
// Forced off before Nest loads: no second monitor, scheduler or alert sender next to the server.
process.env.MONITOR_ENABLED = 'false';
process.env.AUDIT_SCHEDULE_ENABLED = 'false';
process.env.ALERTS_ENABLED = 'false';
import { NestFactory } from '@nestjs/core';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { AppModule } from './app.module';
import { ReportService } from './reports/report.service';
import { MonitorService } from './monitor/monitor.service';
import { createScioMcpServer } from './mcp/scio-mcp';

async function main() {
  // stdout is the protocol channel: Nest logging stays off.
  const app = await NestFactory.createApplicationContext(AppModule, { logger: false });
  const reports = app.get(ReportService);
  const monitor = app.get(MonitorService) as MonitorService & { latencyProfile?: (days: number, tz: 'tbilisi' | 'tashkent') => any };
  const server = createScioMcpServer({
    report: () => reports.build(),
    uptime: (days) => monitor.uptime(days, 'tbilisi'),
    latencyProfile: typeof monitor.latencyProfile === 'function' ? (days) => monitor.latencyProfile!(days, 'tbilisi') : undefined,
  });
  await server.connect(new StdioServerTransport());
  const stop = async () => {
    await server.close();
    await app.close();
    process.exit(0);
  };
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
}

main().catch((e) => {
  process.stderr.write(`scio mcp: ${e?.stack ?? e}\n`);
  process.exit(1);
});
