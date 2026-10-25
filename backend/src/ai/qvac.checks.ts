import { Finding, Severity } from '../common/types';
import { AuditContext, REF } from '../checks/context';
import { api } from '../flows/full.flow';
import { layerScore } from '../reports/report.service';
import { LAYERS } from '../common/types';
import { cosine, MODELS, qvac } from './qvac.engine';
import { gateFor } from './ai.checks';

/**
 * QVAC (local) features. Same rules as the Jev layer:
 * the model proposes or phrases, code decides; nothing here changes a score.
 */

// ---------------------------------------------------------------- 1. AI-generated negative tests

const MUTATIONS: Record<string, string> = {
  omit: 'Leave the parameter out (only meaningful for required parameters)',
  empty: 'Send an empty value',
  wrong_type: 'Send a value of the wrong type (text for a date or boolean, etc.)',
  invalid_format: 'Send a value with the right type but an invalid format (impossible date, bad enum value)',
  too_long: 'Send a 5000-character value',
  unknown_value: 'Send a syntactically valid but unknown value',
  special_chars: "Send markup and quote characters (<>'\")",
  reversed_range: 'For date ranges: dateTo earlier than dateFrom',
};

/** Covered by the rule-based negative tests, so not offered to the model. */
const COVERED = new Set(['x-request-id', 'authorization', 'consent-id', 'x-jws-signature', 'digest', 'signature', 'tpp-signature-certificate',
  // GE XS2A IG §7.5: no restrictions on Accept-Language beyond HTTP itself, so any value is acceptable input.
  'accept-language']);

interface Param {
  name: string;
  in: 'header' | 'query';
  required: boolean;
  type?: string;
  format?: string;
  enum?: string[];
}

function paramsOf(ctx: AuditContext, method: string, path: string): Param[] {
  const spec = ctx.spec!;
  const op = spec.operations.find((o) => o.method === method && o.path === path);
  if (!op) return [];
  return [...(spec.doc.paths[path].parameters ?? []), ...(op.op.parameters ?? [])]
    .map((p: any) => (p.$ref ? spec.resolve(p.$ref) : p))
    .filter((p: any) => p && (p.in === 'header' || p.in === 'query') && !COVERED.has(String(p.name).toLowerCase()))
    .map((p: any) => {
      const s = p.schema?.$ref ? spec.resolve(p.schema.$ref) : p.schema ?? {};
      return { name: p.name, in: p.in, required: !!p.required, type: s.type, format: s.format, enum: s.enum };
    });
}

function mutate(p: Param, mutation: string): string | undefined {
  switch (mutation) {
    case 'omit':
      return undefined;
    case 'empty':
      return p.in === 'header' ? ' ' : '';
    case 'wrong_type':
      return p.type === 'boolean' ? 'maybe' : p.format === 'date' || /date/i.test(p.name) ? 'yesterday' : p.type === 'integer' ? 'many' : '12345';
    case 'invalid_format':
      return p.format === 'date' || /date/i.test(p.name) ? '2026-02-30' : p.enum ? 'bogusValue' : p.format === 'uuid' ? 'zzz-not-uuid' : '%%%';
    case 'too_long':
      return 'a'.repeat(5000);
    case 'unknown_value':
      return p.enum ? 'unknownEnumValue' : 'UNKNOWN_VALUE';
    case 'special_chars':
      return `<script>'"`;
    default:
      return undefined;
  }
}

interface GenTest {
  parameter: string;
  mutation: string;
  expected_status: '400' | '401' | '403' | '404' | '200';
  why: string;
}

export async function generateTests(ctx: AuditContext) {
  if (!ctx.spec || !ctx.state.token) return;
  const acc = ctx.state.accountReads?.[0]?.id;
  const { from, to } = ctx.state.txWindow ?? {};
  const ops = [
    { path: '/v1/accounts', url: '/v1/accounts', query: {} as Record<string, string> },
    ...(acc
      ? [
          { path: '/v1/accounts/{account-id}/balances', url: `/v1/accounts/${encodeURIComponent(acc)}/balances`, query: {} },
          { path: '/v1/accounts/{account-id}/transactions', url: `/v1/accounts/${encodeURIComponent(acc)}/transactions`, query: { bookingStatus: 'booked', dateFrom: from, dateTo: to } },
        ]
      : []),
  ];

  const results: any[] = [];
  for (const o of ops) {
    const params = paramsOf(ctx, 'GET', o.path);
    if (!params.length) continue;
    const menu = params.map((p) => `- ${p.name} (${p.in}${p.required ? ', required' : ', optional'}${p.type ? `, ${p.type}` : ''}${p.format ? `/${p.format}` : ''}${p.enum ? `, one of ${p.enum.slice(0, 6).join('|')}` : ''})`).join('\n');
    let proposal: { tests: GenTest[] };
    try {
      proposal = await qvac.json<{ tests: GenTest[] }>(
        'You design negative tests for a Berlin Group open banking API. Pick inputs a sloppy implementation would wrongly accept. Use only the parameters listed.',
        `Endpoint: GET ${o.path}\nParameters:\n${menu}\nReturn up to 4 distinct tests. For each: the parameter, the mutation, the HTTP status a correct API returns, and one short reason.`,
        'negative_tests',
        {
          type: 'object',
          properties: {
            tests: {
              type: 'array',
              maxItems: 4,
              items: {
                type: 'object',
                properties: {
                  parameter: { type: 'string', enum: params.map((p) => p.name) },
                  mutation: { type: 'string', enum: Object.keys(MUTATIONS) },
                  expected_status: { type: 'string', enum: ['400', '401', '403', '404', '200'] },
                  why: { type: 'string' },
                },
                required: ['parameter', 'mutation', 'expected_status', 'why'],
                additionalProperties: false,
              },
            },
          },
          required: ['tests'],
          additionalProperties: false,
        },
      );
    } catch (e: any) {
      results.push({ endpoint: o.path, error: String(e?.message ?? e) });
      continue;
    }

    // Code validates every proposal before anything is sent.
    const seen = new Set<string>();
    for (const t of proposal.tests ?? []) {
      const p = params.find((x) => x.name === t.parameter);
      const key = `${t.parameter}|${t.mutation}`;
      const reject = (reason: string) => results.push({ endpoint: o.path, ...t, verdict: 'rejected', reason });
      if (!p) { reject('parameter not in spec'); continue; }
      if (seen.has(key)) { reject('duplicate'); continue; }
      seen.add(key);
      if (t.mutation === 'omit' && !p.required) { reject('omitting an optional parameter is valid input'); continue; }
      if (t.mutation === 'reversed_range' && !/^date(From|To)$/.test(p.name)) { reject('reversed_range only applies to dateFrom/dateTo'); continue; }

      const query: Record<string, string> = { ...o.query };
      const headers: Record<string, string> = {};
      if (t.mutation === 'reversed_range') {
        query.dateFrom = to;
        query.dateTo = from;
      } else {
        const v = mutate(p, t.mutation);
        if (p.in === 'query') {
          if (v === undefined) delete query[p.name];
          else query[p.name] = v;
        } else if (v === undefined) headers[p.name] = '';
        else headers[p.name] = v;
      }
      const qs = new URLSearchParams(Object.entries(query).filter(([, v]) => v !== undefined) as [string, string][]).toString();
      const path = `${o.url}${qs ? `?${qs}` : ''}`;
      let r = await api(ctx, 'ai.generated-test', 'GET', path, { headers, validate: false, retry: false });
      // The mock injects random outages: a 5xx only counts when it reproduces with the same input.
      if (r.status === 0 || r.status >= 500) {
        await new Promise((res) => setTimeout(res, 1000));
        const again = await api(ctx, 'ai.generated-test', 'GET', path, { headers, validate: false, retry: false });
        if (!(again.status === 0 || again.status >= 500)) r = again;
      }
      // A correct API rejects invalid input with 4xx. Code judges, not the model's expected_status.
      const outcome = r.status === 0 ? 'no-response' : r.status >= 500 ? 'server-error' : r.status >= 400 ? 'rejected' : 'accepted';
      results.push({ endpoint: o.path, ...t, verdict: 'executed', status: r.status, code: r.json?.tppMessages?.[0]?.code, outcome });

      if (outcome === 'accepted' || outcome === 'server-error') {
        ctx.add({
          source: 'ai',
          checkId: 'ai.generated-test',
          layer: 'conformance',
          status: outcome === 'server-error' ? 'fail' : 'warn',
          severity: outcome === 'server-error' ? 'medium' : 'low',
          title: outcome === 'server-error' ? 'AI-generated test: invalid input crashes the endpoint' : 'AI-generated test: invalid input accepted',
          endpoint: `GET ${o.path} · ${p.name} · ${t.mutation}`,
          message: `${MUTATIONS[t.mutation]} for ${p.name} was answered ${ctx.short(r)}. Test proposed by ${MODELS.llm.name}, executed and judged by code.`,
          evidence: { proposal: t },
          expected: '4xx FORMAT_ERROR',
          actual: ctx.short(r),
          fix: outcome === 'server-error' ? `Validate ${p.name} before processing; invalid input must never produce 5xx.` : `Validate ${p.name} against its schema and reject invalid values with 400 FORMAT_ERROR.`,
          reference: `${REF.BG}. AI-generated test: reported, not scored.`,
        });
      }
    }
  }

  const executed = results.filter((r) => r.verdict === 'executed');
  ctx.add({
    source: 'ai',
    checkId: 'ai.generated-tests',
    layer: 'conformance',
    status: 'info',
    severity: 'none',
    title: 'AI-generated tests (QVAC, local)',
    message: `${MODELS.llm.name} proposed ${results.filter((r) => r.parameter).length} tests from the OpenAPI spec; code rejected ${results.filter((r) => r.verdict === 'rejected').length} and ran ${executed.length}: ${executed.filter((r) => r.outcome === 'rejected').length} correctly rejected, ${executed.filter((r) => r.outcome === 'accepted').length} accepted invalid input, ${executed.filter((r) => r.outcome === 'server-error').length} server errors.`,
    reference: 'Proposals constrained to parameters and mutations from the spec; executed only against test environments.',
    evidence: results,
  });
}

// ---------------------------------------------------------------- 2. Local triage (fallback for Jev)

const IMPACT_SEVERITY: Record<string, Severity> = { security_exposure: 'high', blocks_integration: 'medium', breaks_some_flows: 'medium', degrades_quality: 'low', cosmetic: 'low' };
const IMPACT_TEXT: Record<string, string> = {
  security_exposure: 'an unauthorised party could read account data or act on an account',
  blocks_integration: 'a TPP following the standard cannot integrate without bank-specific workarounds',
  breaks_some_flows: 'some requests or edge cases fail, the main flow still works',
  degrades_quality: 'works, but slower, less reliable, or harder to debug',
  cosmetic: 'documentation or naming issue with no runtime effect',
};
const OWNER_TEXT: Record<string, string> = {
  spec_documentation: 'the published OpenAPI document or developer docs',
  api_implementation: 'API code: validation, responses, data',
  authorization_server: 'OAuth, consent and token handling',
  infrastructure: 'gateway, TLS, certificates, CORS, availability, performance',
  test_data: 'sandbox or mock test data',
};
const OWNERS = Object.keys(OWNER_TEXT);

export async function triageLocal(ctx: AuditContext) {
  for (const f of ctx.findings.filter((x) => (x.status === 'fail' || x.status === 'warn') && x.source !== 'ai')) {
    const a = await qvac.json<{ impact: string; owner: string }>(
      'You triage deviations found in a bank open banking API for third-party providers. Most deviations are not security issues; pick security_exposure only when unauthorised access to data or accounts becomes possible.',
      `Check: ${f.title} (${f.layer})\nObservation: ${f.message}\nExpected: ${f.expected ?? '-'}\nActual: ${f.actual ?? '-'}\n\nImpact options:\n${Object.entries(IMPACT_TEXT).map(([k, v]) => `- ${k}: ${v}`).join('\n')}\n\nOwner options:\n${Object.entries(OWNER_TEXT).map(([k, v]) => `- ${k}: ${v}`).join('\n')}\n\nPick the main impact and the owner.`,
      'triage',
      {
        type: 'object',
        properties: { impact: { type: 'string', enum: Object.keys(IMPACT_SEVERITY) }, owner: { type: 'string', enum: OWNERS } },
        required: ['impact', 'owner'],
        additionalProperties: false,
      },
    );
    const aiSeverity = IMPACT_SEVERITY[a.impact] ?? 'low';
    // A generative model gives no calibrated confidence, so every local answer goes to review.
    f.ai = { model: MODELS.llm.name, impact: a.impact, impactConfidence: 0, owner: a.owner, ownerConfidence: 0, gate: 'review', aiSeverity, agreesWithRules: aiSeverity === f.severity };
  }
}

// ---------------------------------------------------------------- 3. Plain-language summary with number check

/** Words that indicate a claim about a layer, used to catch unsupported claims in summaries. */
const CLAIMS: Record<string, RegExp> = {
  latency: /\b(latency|slow|response times?)\b/i,
  reliability: /\b(availability|outages?|downtime|uptime|unreliab\w*)\b/i,
  data: /\b(iban|data quality|checksum)\b/i,
};

export interface AiSummary {
  targetId: string;
  model: string;
  headline: string;
  summary: string;
  actions: string[];
  verified: boolean;
  issues: string[];
}

export async function summarize(ctx: AuditContext): Promise<AiSummary | undefined> {
  const scored = ctx.findings.filter((f) => f.source !== 'ai');
  const scores = Object.fromEntries(LAYERS.map((l) => [l, layerScore(scored.filter((f) => f.layer === l))]));
  const sevRank: Record<string, number> = { high: 0, medium: 1, low: 2, none: 3 };
  const facts = {
    bank: ctx.target.name,
    environment: ctx.target.simulated ? 'organizers mock (simulated data)' : ctx.target.mode === 'full' ? 'test environment' : ctx.target.mode === 'bis' ? 'TBC proprietary business API (test), read-only' : ctx.target.credentials ? 'bank sandbox with test certificates (mTLS, signed requests, bank login) plus public read-only probes' : ctx.target.specOnly ? 'published spec only (no reachable sandbox)' : 'public endpoints, unauthenticated probes only',
    layerScores: scores,
    failures: scored.filter((f) => f.status === 'fail').length,
    warnings: scored.filter((f) => f.status === 'warn').length,
    topProblems: scored
      .filter((f) => f.status === 'fail' || f.status === 'warn')
      .sort((a, b) => sevRank[a.severity] - sevRank[b.severity])
      .slice(0, 6)
      .map((f) => ({ problem: f.title, severity: f.severity, detail: f.message, fix: f.fix })),
    latency: (ctx.state.endpointStats ?? []).map((s: any) => ({ endpoint: s.operation, p95ms: s.p95, availabilityPct: s.availabilityPct })),
  };
  if (!facts.topProblems.length && !facts.latency.length) return undefined;

  const factText = JSON.stringify(facts);
  const healthy = LAYERS.filter((l) => scores[l] !== null && (scores[l] as number) >= 85);
  const allowed = new Set((factText.match(/\d+(\.\d+)?/g) ?? []).map(Number));
  const schema = {
    type: 'object',
    properties: { headline: { type: 'string' }, summary: { type: 'string' }, actions: { type: 'array', minItems: 1, maxItems: 3, items: { type: 'string' } } },
    required: ['headline', 'summary', 'actions'],
    additionalProperties: false,
  };
  let out: { headline: string; summary: string; actions: string[] } | undefined;
  let bad: string[] = [];
  for (let attempt = 0; attempt < 2; attempt++) {
    out = await qvac.json(
      'You write short audit summaries for a central bank supervisor and for fintech developers. Use only the facts given. Do not calculate or invent numbers; copy numbers exactly as given.',
      `Facts (JSON): ${factText}\n${healthy.length ? `Layers without problems (do not describe them as problems): ${healthy.join(', ')}.\n` : ''}Write a one-line headline (max 12 words), a summary of at most 70 words that does not repeat the headline, and up to 3 concrete actions for the bank.${attempt ? ` Your previous answer had these errors: ${bad.join('; ')}. Fix them.` : ''}`,
      'audit_summary',
      schema,
    );
    // Guardrail 1: every number in the text must appear in the facts (only 1-3, e.g. "3 actions", are free).
    const text = `${out!.headline} ${out!.summary} ${out!.actions.join(' ')}`;
    bad = (text.match(/\d+(\.\d+)?/g) ?? []).filter((n) => Number(n) > 3 && !allowed.has(Number(n))).map((n) => `number ${n} is not in the facts`);
    // Guardrail 2: no problem claims about a layer that scored well (or was not tested).
    for (const [layer, words] of Object.entries(CLAIMS)) {
      const sc = (scores as any)[layer];
      if ((sc === null || sc >= 85) && words.test(text)) bad.push(`claims a ${layer} problem, but ${layer} ${sc === null ? 'was not tested' : `scored ${sc}`}`);
    }
    if (!bad.length) break;
  }
  return { targetId: ctx.target.id, model: MODELS.llm.name, headline: out!.headline, summary: out!.summary, actions: out!.actions, verified: !bad.length, issues: [...new Set(bad)] };
}

// ---------------------------------------------------------------- 4. Grouping similar findings (run level)

export interface FindingCluster {
  label: string;
  size: number;
  targets: string[];
  checks: string[];
  members: { targetId: string; checkId: string; title: string; endpoint?: string }[];
  cohesion: number;
}

/** Greedy single-pass clustering on embedding similarity. Threshold from QVAC_CLUSTER_SIM (default 0.76, tuned on audit findings). */
export async function clusterFindings(findings: Finding[]): Promise<{ model: string; threshold: number; clusters: FindingCluster[] }> {
  const items = findings.filter((f) => (f.status === 'fail' || f.status === 'warn') && f.checkId !== 'ai.generated-tests');
  const threshold = Number(process.env.QVAC_CLUSTER_SIM ?? 0.76);
  if (items.length < 2) return { model: MODELS.embed.name, threshold, clusters: [] };
  // Title + fix captures the root cause; messages carry run-specific numbers that add noise.
  const vecs = await qvac.embed(items.map((f) => `${f.title}. ${f.fix ?? ''}`.slice(0, 1000)));

  const groups: number[][] = [];
  const centroids: number[][] = [];
  vecs.forEach((v, i) => {
    let best = -1, bestSim = threshold;
    centroids.forEach((c, g) => {
      const s = cosine(v, c);
      if (s >= bestSim) { best = g; bestSim = s; }
    });
    if (best < 0) {
      groups.push([i]);
      centroids.push([...v]);
    } else {
      groups[best].push(i);
      const n = groups[best].length;
      centroids[best] = centroids[best].map((x, k) => x + (v[k] - x) / n);
    }
  });

  const clusters = groups
    .filter((g) => g.length >= 2 && new Set(g.map((i) => items[i].checkId)).size + new Set(g.map((i) => items[i].targetId)).size > 2)
    .map((g, idx) => {
      const c = centroids[groups.indexOf(g)];
      const sims = g.map((i) => cosine(vecs[i], c));
      const central = g[sims.indexOf(Math.max(...sims))];
      return {
        label: items[central].title,
        size: g.length,
        targets: [...new Set(g.map((i) => items[i].targetId))],
        checks: [...new Set(g.map((i) => items[i].checkId))],
        members: g.map((i) => ({ targetId: items[i].targetId, checkId: items[i].checkId, title: items[i].title, endpoint: items[i].endpoint })),
        cohesion: Math.round((sims.reduce((a, b) => a + b, 0) / sims.length) * 100) / 100,
      };
    })
    .sort((a, b) => b.size - a.size);
  return { model: MODELS.embed.name, threshold, clusters };
}

export { gateFor };
