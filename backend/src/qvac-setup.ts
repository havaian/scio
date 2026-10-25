import { createWriteStream, existsSync, mkdirSync, renameSync, statSync } from 'node:fs';
import { resolve } from 'node:path';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { fetch, EnvHttpProxyAgent, Agent } from 'undici';
import { MODEL_DIR, MODELS } from './ai/qvac.engine';

/**
 * Downloads the QVAC model files once over plain HTTPS (about 1.33 GB).
 * Avoids the QVAC peer-to-peer registry, which times out on some networks.
 * Usage: npm run qvac:setup
 */
async function main() {
  const dispatcher = process.env.HTTPS_PROXY || process.env.HTTP_PROXY ? new EnvHttpProxyAgent() : new Agent();
  mkdirSync(MODEL_DIR, { recursive: true });
  for (const m of Object.values(MODELS)) {
    const target = resolve(MODEL_DIR, m.file);
    if (existsSync(target) && statSync(target).size > 1_000_000) {
      console.log(`${m.file}: already present`);
      continue;
    }
    console.log(`${m.file}: downloading from Hugging Face...`);
    const r = await fetch(m.url, { dispatcher });
    if (!r.ok || !r.body) throw new Error(`${m.file}: HTTP ${r.status}`);
    const total = Number(r.headers.get('content-length') ?? 0);
    let done = 0;
    const body = Readable.fromWeb(r.body as any);
    body.on('data', (c: Buffer) => {
      done += c.length;
      if (total) process.stdout.write(`\r  ${((done / total) * 100).toFixed(0)}% of ${(total / 1e6).toFixed(0)} MB`);
    });
    // Write to a temp file first so an interrupted download is never mistaken for a complete one.
    await pipeline(body, createWriteStream(`${target}.part`));
    renameSync(`${target}.part`, target);
    console.log(`\n${m.file}: saved to ${target}`);
  }
  console.log('Done. Start the backend with QVAC_ENABLED=true.');
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
