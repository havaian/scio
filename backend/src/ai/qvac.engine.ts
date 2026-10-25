import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { Logger } from '@nestjs/common';

/**
 * Local models through QVAC (Tether): everything runs on this machine, nothing is sent out.
 *  - EmbeddingGemma 300M: embeddings for grouping similar findings
 *  - Qwen3 1.7B: JSON-constrained generation (test ideas, summaries, local triage fallback)
 * Optional: enabled with QVAC_ENABLED=true and the optional dependency @qvac/sdk installed.
 * Model files: run `npm run qvac:setup` once, or point QVAC_LLM_MODEL / QVAC_EMBED_MODEL to a path or URL.
 */

// Models live in the repo's models/ folder (git-ignored), run from backend/; Docker sets QVAC_MODEL_DIR=/app/models.
export const MODEL_DIR = process.env.QVAC_MODEL_DIR ?? resolve(process.cwd(), '..', 'models');
export const MODELS = {
  embed: {
    file: 'embeddinggemma-300m-Q4_0.gguf',
    url: 'https://huggingface.co/unsloth/embeddinggemma-300m-GGUF/resolve/main/embeddinggemma-300m-Q4_0.gguf',
    env: 'QVAC_EMBED_MODEL',
    type: 'llamacpp-embedding',
    name: 'EmbeddingGemma 300M (local)',
  },
  llm: {
    file: 'Qwen3-1.7B-Q4_0.gguf',
    url: 'https://huggingface.co/unsloth/Qwen3-1.7B-GGUF/resolve/main/Qwen3-1.7B-Q4_0.gguf',
    env: 'QVAC_LLM_MODEL',
    type: 'llamacpp-completion',
    name: 'Qwen3 1.7B (local)',
  },
} as const;

// @qvac/sdk is ESM-only; load it without TypeScript turning import() into require().
const importEsm = new Function('m', 'return import(m)') as (m: string) => Promise<any>;

function source(m: (typeof MODELS)[keyof typeof MODELS]): string {
  const fromEnv = process.env[m.env];
  if (fromEnv) return fromEnv;
  const local = resolve(MODEL_DIR, m.file);
  return existsSync(local) ? local : m.url;
}

class QvacEngine {
  private readonly log = new Logger('QVAC');
  private sdk: any;
  private ids: { embed?: string; llm?: string } = {};
  private loading?: Promise<void>;
  private queue: Promise<unknown> = Promise.resolve();
  lastError?: string;

  get enabled(): boolean {
    return process.env.QVAC_ENABLED === 'true';
  }

  private async ensure() {
    if (this.ids.embed && this.ids.llm) return;
    this.loading ??= (async () => {
      const t0 = Date.now();
      this.sdk = await importEsm('@qvac/sdk');
      this.ids.embed = await this.sdk.loadModel({ modelSrc: source(MODELS.embed), modelType: MODELS.embed.type });
      this.ids.llm = await this.sdk.loadModel({ modelSrc: source(MODELS.llm), modelType: MODELS.llm.type, modelConfig: { ctx_size: 8192 } });
      this.log.log(`models ready in ${((Date.now() - t0) / 1000).toFixed(1)}s`);
    })().catch((e) => {
      this.loading = undefined;
      this.lastError = String(e?.message ?? e);
      throw e;
    });
    await this.loading;
  }

  /** One model, one job at a time. */
  private serial<T>(fn: () => Promise<T>): Promise<T> {
    const next = this.queue.then(fn, fn);
    this.queue = next.catch(() => undefined);
    return next;
  }

  async embed(texts: string[]): Promise<number[][]> {
    await this.ensure();
    return this.serial(async () => (await this.sdk.embed({ modelId: this.ids.embed, text: texts })).embedding);
  }

  /** JSON-schema constrained completion. Returns the parsed object. */
  async json<T>(system: string, user: string, name: string, schema: object): Promise<T> {
    await this.ensure();
    return this.serial(async () => {
      const run = this.sdk.completion({
        modelId: this.ids.llm,
        history: [
          { role: 'system', content: `${system} /no_think` },
          { role: 'user', content: user },
        ],
        stream: true,
        responseFormat: { type: 'json_schema', json_schema: { name, schema } },
      });
      for await (const _ of run.events);
      const final = await run.final;
      return JSON.parse(String(final.contentText).trim()) as T;
    });
  }
}

export const qvac = new QvacEngine();

export function cosine(a: number[], b: number[]): number {
  let dot = 0, na = 0, nb = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    na += a[i] * a[i];
    nb += b[i] * b[i];
  }
  return dot / Math.sqrt(na * nb || 1);
}
