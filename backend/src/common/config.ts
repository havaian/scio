import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { TargetConfig, Thresholds } from './types';

const CONFIG_DIR = process.env.CONFIG_DIR ?? resolve(process.cwd(), 'config');

export function loadTargets(): TargetConfig[] {
  const raw = JSON.parse(readFileSync(resolve(CONFIG_DIR, 'targets.json'), 'utf8'));
  const targets = raw.targets as TargetConfig[];
  // Test-user passwords issued privately by a bank stay out of the repo: credentials.psu.passwordEnv names the variable.
  for (const t of targets) {
    const psu = t.credentials?.psu;
    if (psu?.passwordEnv) psu.password = process.env[psu.passwordEnv] ?? '';
  }
  return targets;
}

export function loadThresholds(): Thresholds {
  return JSON.parse(readFileSync(resolve(CONFIG_DIR, 'thresholds.json'), 'utf8')) as Thresholds;
}

export function configPath(rel: string): string {
  return resolve(CONFIG_DIR, '..', rel);
}
