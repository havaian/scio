import { fetch, EnvHttpProxyAgent, Agent, Dispatcher } from 'undici';

/**
 * Minimal client for TypeSafe's System One API (Jev).
 * Jev does not generate text: it answers typed questions (choice / score / noul) about a state,
 * with calibrated probabilities. Docs: https://docs.typesafe.ai/api
 */
const dispatcher: Dispatcher = process.env.HTTPS_PROXY || process.env.HTTP_PROXY ? new EnvHttpProxyAgent() : new Agent();

export type JevQuestion =
  | { type: 'noul'; instructions: string; criteria?: { true?: string; false?: string } }
  | { type: 'choice'; instructions: string; criteria: Record<string, string> }
  | { type: 'score'; instructions: string; criteria: string[] };

export type JevAnswer =
  | { type: 'noul'; noul: number }
  | { type: 'choice'; choice: string; confidence: number; probabilities: Record<string, number> }
  | { type: 'score'; score: number; confidence: number; probabilities: Record<string, number>; legend: Record<string, string> };

export interface JevResult {
  model: string;
  answers: Record<string, JevAnswer>;
  usage: { input_tokens: number; output_tokens: number };
}

export class JevClient {
  readonly model = process.env.JEV_MODEL ?? 'jev-latest';
  private readonly key = process.env.TYPESAFE_API_KEY;
  private readonly url = (process.env.TYPESAFE_BASE_URL ?? 'https://api.typesafe.ai') + '/v1/systemone';

  get enabled(): boolean {
    return !!this.key;
  }

  async ask(state: unknown, questions: Record<string, JevQuestion>, attempt = 0): Promise<JevResult> {
    const r = await fetch(this.url, {
      method: 'POST',
      dispatcher,
      signal: AbortSignal.timeout(20000),
      headers: { Authorization: `Bearer ${this.key}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ model: this.model, state, questions }),
    });
    if ((r.status === 429 || r.status >= 500) && attempt < 2) {
      await new Promise((res) => setTimeout(res, 1000 * (attempt + 1)));
      return this.ask(state, questions, attempt + 1);
    }
    const body: any = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(`Jev HTTP ${r.status}: ${body?.detail?.message ?? JSON.stringify(body?.detail ?? body).slice(0, 200)}`);
    return body as JevResult;
  }
}

/** Runs tasks with bounded concurrency. */
export async function pool<T, R>(items: T[], size: number, fn: (t: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(size, items.length) }, async () => {
      while (next < items.length) {
        const i = next++;
        out[i] = await fn(items[i]);
      }
    }),
  );
  return out;
}
