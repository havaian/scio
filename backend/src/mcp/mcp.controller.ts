import { Controller, Delete, Get, Logger, Post, Req, Res } from '@nestjs/common';
import type { Request, Response } from 'express';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { ReportService } from '../reports/report.service';
import { MonitorService } from '../monitor/monitor.service';
import { createScioMcpServer } from './scio-mcp';

/** Requests per IP per minute. */
const RATE_LIMIT = 60;

/**
 * MCP over Streamable HTTP at /api/mcp, stateless: a new server and transport per request (no sessions).
 * Read-only: tools read the latest report and the uptime monitor; nothing here starts an audit or calls a bank.
 */
@Controller('api/mcp')
export class McpController {
  private readonly log = new Logger('MCP');
  private hits = new Map<string, { windowStart: number; count: number }>();

  constructor(
    private readonly reports: ReportService,
    private readonly monitor: MonitorService,
  ) {}

  /** Fixed one-minute window per IP, in memory. */
  private limited(ip: string): boolean {
    const now = Date.now();
    const h = this.hits.get(ip);
    if (!h || now - h.windowStart >= 60_000) {
      if (this.hits.size > 10_000) this.hits.clear();
      this.hits.set(ip, { windowStart: now, count: 1 });
      return false;
    }
    h.count++;
    return h.count > RATE_LIMIT;
  }

  @Post()
  async handle(@Req() req: Request, @Res() res: Response) {
    const ip = String(req.headers['x-real-ip'] ?? req.ip ?? 'unknown');
    if (this.limited(ip)) {
      res.status(429).setHeader('Retry-After', '60').json({ jsonrpc: '2.0', error: { code: -32000, message: 'Too many requests (60 per minute)' }, id: null });
      return;
    }
    const monitor = this.monitor as MonitorService & { latencyProfile?: (days: number, tz: 'tbilisi' | 'tashkent') => any };
    const server = createScioMcpServer({
      report: () => this.reports.build(),
      uptime: (days) => this.monitor.uptime(days, 'tbilisi'),
      latencyProfile: typeof monitor.latencyProfile === 'function' ? (days) => monitor.latencyProfile!(days, 'tbilisi') : undefined,
    });
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    res.on('close', () => {
      transport.close();
      server.close();
    });
    try {
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (e: any) {
      this.log.warn(`request failed: ${e?.message ?? e}`);
      if (!res.headersSent) res.status(500).json({ jsonrpc: '2.0', error: { code: -32603, message: 'Internal server error' }, id: null });
    }
  }

  @Get()
  get(@Res() res: Response) {
    this.notAllowed(res);
  }

  @Delete()
  remove(@Res() res: Response) {
    this.notAllowed(res);
  }

  /** Stateless server: no SSE stream to open, no session to end. */
  private notAllowed(res: Response) {
    res.status(405).setHeader('Allow', 'POST').json({ jsonrpc: '2.0', error: { code: -32000, message: 'Method not allowed' }, id: null });
  }
}
