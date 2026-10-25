import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createScioMcpServer } from '../src/mcp/scio-mcp';
import type { Report, TargetReport } from '../src/reports/report.service';
import type { Finding } from '../src/common/types';

// Test fixture: a small Report-shaped object (two banks, three checks).
const layers = { conformance: null, reliability: null, latency: null, security: null, data: null };
const target = (id: string, name: string, bank: string, access: TargetReport['access'], overall: number | null): TargetReport => ({
  id,
  name,
  bank,
  mode: 'passive',
  simulated: false,
  access,
  baseUrl: `https://example.invalid/${id}`,
  note: `${name} fixture note`,
  scores: { ...layers, conformance: overall },
  layerChecks: { conformance: 3, reliability: 0, latency: 0, security: 0, data: 0 },
  overall,
  evaluated: 3,
  counts: { pass: 1, fail: 1, warn: 1, info: 0, skip: 0 },
  endpointStats: [],
});
const std = { refs: ['GE-XS2A §5.1', 'BG-IG §6.3'], verified: true, note: 'Consent object' };
const finding = (targetId: string, checkId: string, status: Finding['status'], severity: Finding['severity']) => ({
  targetId,
  checkId,
  layer: 'conformance' as const,
  status,
  severity,
  title: `${checkId} title`,
  message: `${checkId} on ${targetId}: ${status}`,
  expected: 'expected value',
  actual: 'actual value',
  fix: 'do the fix',
  standard: std,
});
const findings = [
  finding('bog-sandbox', 'consent.create', 'pass', 'none'),
  finding('bog-sandbox', 'consent.status', 'fail', 'high'),
  finding('bog-sandbox', 'spec.version', 'warn', 'low'),
  finding('silk-sandbox', 'consent.create', 'fail', 'medium'),
  finding('silk-sandbox', 'consent.status', 'fail', 'high'),
  finding('silk-sandbox', 'spec.version', 'pass', 'none'),
];
const cells = (checkId: string) =>
  Object.fromEntries(['bog-sandbox', 'silk-sandbox'].map((t) => {
    const f = findings.find((x) => x.targetId === t && x.checkId === checkId)!;
    return [t, { status: f.status, severity: f.severity, count: 1, message: f.message }];
  }));
const report = {
  run: { id: 'run-fixture-1', startedAt: '2026-10-22T02:00:00Z', finishedAt: '2026-10-22T02:10:00Z', status: 'done', targets: ['bog-sandbox', 'silk-sandbox'], thresholdsSource: 'assumed' },
  ai: { enabled: false, models: [], triaged: 0, auto: 0, review: 0, human: 0, disagreements: 0 },
  local: { enabled: false, summaries: [], clusters: null },
  standards: { documents: { 'GE-XS2A': { title: 'GE XS2A Implementation Guide', url: 'https://example.invalid/xs2a' } } },
  generatedAt: '2026-10-22T03:00:00Z',
  thresholds: { source: 'assumed', availabilityPct: 99.5, errorRatePct: 1, latencyP95Ms: 1000, latencyMinSamples: 20, minEvaluatedChecks: 3, minLayerChecks: 3 },
  common: null,
  targets: [target('bog-sandbox', 'Bank of Georgia (sandbox)', 'Bank of Georgia', 'sandbox', 50), target('silk-sandbox', 'Silk Bank (sandbox)', 'Silk Bank', 'pending', 40)],
  matrix: ['consent.create', 'consent.status', 'spec.version'].map((id) => ({ checkId: id, title: `${id} title`, layer: 'conformance' as const, standard: std, cells: cells(id) })),
  findings,
  totals: { findings: 6, failures: 3, warnings: 1, calls: 0 },
} as unknown as Report;

async function connect() {
  const server = createScioMcpServer({
    report: () => report,
    uptime: () => ({ generatedAt: '', tz: 'tbilisi', timezone: 'Asia/Tbilisi (UTC+4)', availabilityPct: 99.5, source: 'assumed', enabled: false, intervals: { simulatedMin: 5, realMin: 5 }, targets: [] }),
  });
  const [a, b] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'test', version: '0' });
  await Promise.all([server.connect(a), client.connect(b)]);
  return client;
}

const json = (r: any) => JSON.parse(r.content[1].text);

test('MCP: lists the read-only tools', async () => {
  const client = await connect();
  const { tools } = await client.listTools();
  assert.deepEqual(tools.map((t) => t.name).sort(), ['compare_banks', 'explain_check', 'get_bank_report', 'get_findings', 'get_uptime', 'list_banks']);
  assert.ok(tools.every((t) => t.annotations?.readOnlyHint === true));
  assert.match(client.getInstructions() ?? '', /mock/);
});

test('MCP: list_banks states the run id and assumed thresholds', async () => {
  const client = await connect();
  const r: any = await client.callTool({ name: 'list_banks', arguments: {} });
  assert.match(r.content[0].text, /run-fixture-1/);
  assert.match(r.content[0].text, /assumptions/);
  assert.equal(r.structuredContent.targets.length, 2);
  assert.equal(r.structuredContent.targets[0].access, 'sandbox');
});

test('MCP: get_bank_report resolves a fuzzy bank name, worst problem first with clauses', async () => {
  const client = await connect();
  const r: any = await client.callTool({ name: 'get_bank_report', arguments: { bank: 'bank of georgia' } });
  const d = json(r);
  assert.equal(d.target.id, 'bog-sandbox');
  assert.equal(d.topProblems[0].checkId, 'consent.status');
  assert.deepEqual(d.topProblems[0].standard.refs, std.refs);
  assert.equal(d.topProblems[0].fix, 'do the fix');
  assert.equal((await client.callTool({ name: 'get_bank_report', arguments: { bank: 'Silk' } }) as any).structuredContent.target.id, 'silk-sandbox');
});

test('MCP: compare_banks returns only rows where verdicts differ', async () => {
  const client = await connect();
  const r: any = await client.callTool({ name: 'compare_banks', arguments: { banks: ['bog', 'silk'] } });
  const ids = r.structuredContent.rows.map((x: any) => x.checkId).sort();
  assert.deepEqual(ids, ['consent.create', 'spec.version']);
  assert.match(r.content[0].text, /different access levels/);
});

test('MCP: unknown bank is a tool error listing target ids', async () => {
  const client = await connect();
  const r: any = await client.callTool({ name: 'get_bank_report', arguments: { bank: 'Nonexistent Bank' } });
  assert.equal(r.isError, true);
  assert.match(r.content[0].text, /bog-sandbox/);
  assert.match(r.content[0].text, /silk-sandbox/);
});
