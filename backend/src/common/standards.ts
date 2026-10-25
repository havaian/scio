import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const CONFIG_DIR = process.env.CONFIG_DIR ?? resolve(process.cwd(), 'config');

export interface StandardRef {
  refs: string[];
  verified: boolean;
  note?: string;
}

export interface StandardMap {
  documents: Record<string, { title: string; url: string }>;
  checks: Record<string, StandardRef>;
}

/** Clause-level mapping of every check to the Georgian guides and Berlin Group guidelines (config/standard-map.json). */
export function loadStandardMap(): StandardMap {
  try {
    return JSON.parse(readFileSync(resolve(CONFIG_DIR, 'standard-map.json'), 'utf8'));
  } catch {
    return { documents: {}, checks: {} };
  }
}
