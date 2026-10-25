import { Exchange, Finding, Severity } from '../common/types';
import { AuditContext, REF } from '../checks/context';
import { JevClient, pool } from './jev.client';
import { qvac } from './qvac.engine';
import { triageLocal } from './qvac.checks';

/**
 * AI layer (Jev by TypeSafe). Design rules, in line with NBG model-risk expectations:
 *  - Deterministic checks decide pass/fail and the score. AI never changes either.
 *  - AI answers typed questions only (no free text), each with a calibrated confidence.
 *  - Confidence gates what happens: auto-label, flag for review, or hand to a human.
 *  - Rules are the baseline, AI the challenger: disagreements are surfaced, not resolved silently.
 *  - Only finding metadata and error bodies are sent; IBAN-like strings are masked first.
 */

export interface AiTriage {
  model: string;
  impact: string;
  impactConfidence: number;
  owner: string;
  ownerConfidence: number;
  gate: 'auto' | 'review' | 'human';
  aiSeverity: Severity;
  agreesWithRules: boolean;
}

const IMPACT: Record<string, string> = {
  security_exposure: 'Could let an unauthorised party read account data or act on an account',
  blocks_integration: 'A TPP that follows the standard cannot integrate without bank-specific workarounds',
  breaks_some_flows: 'Some requests or edge cases fail or are mishandled, the main flow still works',
  degrades_quality: 'Works, but slower, less reliable, or harder to debug and monitor',
  cosmetic: 'Documentation or naming issue with no effect on running integrations',
};
const IMPACT_SEVERITY: Record<string, Severity> = {
  security_exposure: 'high',
  // Medium: integration still possible with bank-specific workarounds; only security exposure is high.
  blocks_integration: 'medium',
  breaks_some_flows: 'medium',
  degrades_quality: 'low',
  cosmetic: 'low',
};
const OWNER: Record<string, string> = {
  spec_documentation: 'The published OpenAPI document or developer documentation',
  api_implementation: 'The API application code (request validation, responses, data)',
  authorization_server: 'OAuth / consent / token handling',
  infrastructure: 'Gateway, TLS, certificates, CORS, availability, performance',
  test_data: 'Sandbox or mock test data rather than production behaviour',
};

/** IBAN-like strings, upper or lower case, compact or printed in groups of four ("GE29 NB00 ..."); at least 10 digits, so words are left alone. */
export const mask = (s: string) =>
  s.replace(/\b[A-Za-z]{2}\d{2}(?: ?[A-Za-z0-9]{4}){2,7}(?: ?[A-Za-z0-9]{1,4})?\b/g, (m) => ((m.match(/\d/g)?.length ?? 0) >= 10 ? '[IBAN]' : m));

export function gateFor(conf: number, t: { auto: number; review: number }): AiTriage['gate'] {
  return conf >= t.auto ? 'auto' : conf >= t.review ? 'review' : 'human';
}

/** Adds an AI triage to every failure and warning. */
async function triage(ctx: AuditContext, jev: JevClient, gate: { auto: number; review: number }) {
  const targets = ctx.findings.filter((f) => f.status === 'fail' || f.status === 'warn');
  await pool(targets, 4, async (f: Finding) => {
    const state = mask(
      JSON.stringify({
        bank: ctx.target.simulated ? 'simulated bank (mock)' : 'bank',
        check: f.title,
        layer: f.layer,
        endpoint: f.endpoint,
        observation: f.message,
        expected: f.expected,
        actual: f.actual,
        standard: f.reference,
      }),
    );
    const res = await jev.ask(state, {
      impact: { type: 'choice', instructions: 'What is the main impact of this open banking API deviation on third-party providers and their customers?', criteria: IMPACT },
      owner: { type: 'choice', instructions: 'Which part of the bank most likely has to change to fix this deviation?', criteria: OWNER },
    });
    const impact = res.answers.impact as any;
    const owner = res.answers.owner as any;
    const aiSeverity = IMPACT_SEVERITY[impact.choice] ?? 'low';
    (f as any).ai = {
      model: res.model,
      impact: impact.choice,
      impactConfidence: round(impact.confidence),
      owner: owner.choice,
      ownerConfidence: round(owner.confidence),
      gate: gateFor(Math.min(impact.confidence, owner.confidence), gate),
      aiSeverity,
      agreesWithRules: aiSeverity === f.severity,
    } satisfies AiTriage;
  });
}

/** Describes what each negative request deliberately did wrong, so the AI can judge whether the error explains it. */
const INTENT: Record<string, string> = {
  'neg.missing-request-id': 'The request omitted the mandatory X-Request-ID header.',
  'neg.invalid-request-id': 'The request sent X-Request-ID = "not-a-uuid" (not a UUID).',
  'passive.invalid-request-id': 'The request sent X-Request-ID = "not-a-uuid" (not a UUID) and no client certificate.',
  'neg.no-token': 'The request had no Authorization header.',
  'neg.bad-token': 'The request used an invalid bearer token.',
  'neg.missing-consent-id': 'The request omitted the Consent-ID header but had a valid token.',
  'neg.unknown-consent': 'The request used a Consent-ID that does not exist.',
  'neg.unknown-account': 'The request asked for an account id that does not exist.',
  'neg.bad-consent-body': 'The consent request body was missing required fields (access, validUntil, ...).',
  'neg.bad-date': 'The request used an invalid dateFrom value "2026-13-45".',
  'passive.accounts': 'The request carried no client certificate and no token.',
};

/** Grades how useful each distinct error response is to a developer, per bank. */
async function errorQuality(ctx: AuditContext, jev: JevClient, gate: { auto: number; review: number }) {
  const seen = new Map<string, Exchange>();
  for (const x of ctx.http.exchanges) {
    if (x.status < 400 || x.status >= 500 || !INTENT[x.operation]) continue;
    const key = `${x.operation}|${x.status}|${x.bodySnippet}`;
    if (!seen.has(key)) seen.set(key, x);
  }
  const xs = [...seen.values()];
  if (!xs.length) return;

  const graded = await pool(xs, 4, async (x) => {
    const state = mask(JSON.stringify({ whatTheClientDidWrong: INTENT[x.operation], httpStatus: x.status, responseBody: x.bodySnippet.slice(0, 1200) }));
    const res = await jev.ask(state, {
      actionability: {
        type: 'score',
        instructions: 'How well does this error response tell a developer what to fix?',
        criteria: [
          'Gives no usable cause',
          'Names only a generic error class',
          'Names the specific field or header at fault',
          'Names the field or header and how to correct it',
        ],
      },
      explainsCause: {
        type: 'noul',
        instructions: 'The error response correctly describes what the client actually did wrong (whatTheClientDidWrong).',
      },
    });
    const a = res.answers.actionability as any;
    const n = res.answers.explainsCause as any;
    return { operation: x.operation, status: x.status, body: x.bodySnippet.slice(0, 300), actionability: round(a.score), actionabilityConfidence: round(a.confidence), explainsCause: round(n.noul), gate: gateFor(a.confidence, gate), model: res.model };
  });

  // Low-confidence grades (gate 'human') state no conclusion: they are left out of the average and the cause counts,
  // and only listed as sent to human review.
  const confident = graded.filter((g) => g.gate !== 'human');
  const human = graded.filter((g) => g.gate === 'human');
  const avg = confident.length ? round(confident.reduce((s, g) => s + g.actionability, 0) / confident.length) : null;
  const misleading = confident.filter((g) => g.explainsCause < 0.3);
  const unsure = confident.filter((g) => g.explainsCause >= 0.3 && g.explainsCause <= 0.7);
  ctx.add({
    checkId: 'ai.error-quality',
    layer: 'conformance',
    status: 'info',
    severity: 'none',
    title: 'AI: error message quality',
    message:
      `${graded.length} distinct error responses graded by ${graded[0].model}. ` +
      (avg !== null ? `Average actionability ${avg} of 3. ` : 'Confidence too low to grade. ') +
      (misleading.length ? `${misleading.length} ${misleading.length === 1 ? 'does' : 'do'} not describe the real cause (e.g. ${misleading[0].operation} → HTTP ${misleading[0].status}). ` : confident.length ? `All ${confident.length === graded.length ? '' : 'confidently graded ones '}describe the real cause. ` : '') +
      (unsure.length ? `${unsure.length} uncertain, sent to human review. ` : '') +
      (human.length ? `${human.length} graded with low confidence, sent to human review.` : ''),
    fix: misleading.length || (avg !== null && avg < 2) ? 'Return a code that matches the real cause and name the offending field in tppMessages[].path and text, e.g. "X-Request-ID must be a UUID".' : undefined,
    reference: `${REF.BG}. Advisory only: not part of the score.`,
    evidence: graded,
  });
}

export async function runAi(ctx: AuditContext, jev: JevClient) {
  if (!jev.enabled) {
    if (qvac.enabled) {
      // No Jev key: answer the same triage questions with the local model (uncalibrated, so all go to review).
      try {
        await triageLocal(ctx);
        ctx.add({ checkId: 'ai.status', layer: 'conformance', status: 'info', severity: 'none', title: 'AI layer', message: 'TYPESAFE_API_KEY not set: triage answered locally by QVAC. Local answers have no calibrated confidence and all go to review.' });
      } catch (e: any) {
        ctx.add({ checkId: 'ai.status', layer: 'conformance', status: 'skip', severity: 'none', title: 'AI layer', message: `Local triage failed: ${e?.message ?? e}` });
      }
      return;
    }
    ctx.add({ checkId: 'ai.status', layer: 'conformance', status: 'skip', severity: 'none', title: 'AI layer', message: 'TYPESAFE_API_KEY is not set, AI triage and error grading skipped.' });
    return;
  }
  const gate = { auto: ctx.thresholds.aiAutoConfidence ?? 0.8, review: ctx.thresholds.aiReviewConfidence ?? 0.5 };
  try {
    await triage(ctx, jev, gate);
    await errorQuality(ctx, jev, gate);
  } catch (e: any) {
    ctx.add({ checkId: 'ai.status', layer: 'conformance', status: 'skip', severity: 'none', title: 'AI layer', message: `AI calls failed, deterministic results unaffected: ${e?.message ?? e}` });
  }
}

const round = (v: number) => Math.round(v * 100) / 100;
