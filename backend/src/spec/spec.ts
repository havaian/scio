import { readFileSync, existsSync } from 'node:fs';
import Ajv, { ValidateFunction } from 'ajv';
import addFormats from 'ajv-formats';
import { HttpRecorder } from '../common/http';
import { configPath } from '../common/config';
import { TargetConfig } from '../common/types';

export interface SpecOperation {
  method: string;
  path: string;
  operationId?: string;
  op: any;
  regex: RegExp;
  paramCount: number;
}

export interface SchemaCheck {
  operation?: SpecOperation;
  valid: boolean;
  skipped?: string;
  errors?: string[];
}

const METHODS = ['get', 'post', 'put', 'delete', 'patch'];

/** Loaded OpenAPI document plus helpers to match live calls and validate responses against it. */
export class Spec {
  readonly operations: SpecOperation[] = [];
  readonly basePath: string;
  private ajv: Ajv;
  private cache = new Map<string, ValidateFunction | null>();

  constructor(
    readonly doc: any,
    readonly source: string,
    /** Path prefix of the target's base URL, stripped too when the spec's servers do not match the real host (e.g. Credo's placeholder servers). */
    readonly targetBase = '',
  ) {
    const server = doc.servers?.[0]?.url ?? '';
    try {
      this.basePath = new URL(server).pathname.replace(/\/$/, '');
    } catch {
      this.basePath = '';
    }
    for (const [path, item] of Object.entries<any>(doc.paths ?? {})) {
      for (const m of METHODS) {
        if (!item?.[m]) continue;
        const names = path.match(/\{[^}]+\}/g) ?? [];
        const pattern = path
          .split(/(\{[^}]+\})/)
          .map((part) => (part.startsWith('{') ? '[^/]+' : part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')))
          .join('');
        this.operations.push({
          method: m.toUpperCase(),
          path,
          operationId: item[m].operationId,
          op: item[m],
          regex: new RegExp(`^${pattern}$`),
          paramCount: names.length,
        });
      }
    }
    // Literal paths win over templated ones (/v1/consents before /v1/{payment-service}).
    this.operations.sort((a, b) => a.paramCount - b.paramCount);

    this.ajv = new Ajv({ strict: false, allErrors: true, validateFormats: true, logger: false });
    addFormats(this.ajv);
    // Validate against a sanitized copy; the defects found while sanitizing are reported as spec findings.
    const copy = structuredClone(doc);
    sanitize(copy, '#', this.schemaDefects);
    this.ajv.addSchema(copy, 'openapi');
  }

  /** Places where the document's schemas are invalid for a validator (e.g. "nullable" without "type"). */
  readonly schemaDefects: string[] = [];

  static async load(target: TargetConfig, http: HttpRecorder): Promise<Spec | undefined> {
    if (target.specUrl) {
      const r = await http.request({ operation: 'spec.fetch', method: 'GET', url: target.specUrl, silent: true });
      if (r.status === 200 && r.json?.paths) return new Spec(r.json, target.specUrl, basePathOf(target.baseUrl));
    }
    if (target.specFile) {
      const file = configPath(target.specFile);
      if (existsSync(file)) return new Spec(JSON.parse(readFileSync(file, 'utf8')), `${target.specFile} (vendored copy)`, basePathOf(target.baseUrl));
    }
    return undefined;
  }

  match(method: string, url: string): SpecOperation | undefined {
    let p = new URL(url).pathname;
    const candidates = [p];
    for (const base of [this.basePath, this.targetBase]) if (base && p.startsWith(base)) candidates.push(p.slice(base.length) || '/');
    for (const c of candidates) {
      const op = this.operations.find((o) => o.method === method.toUpperCase() && o.regex.test(c));
      if (op) return op;
    }
    return undefined;
  }

  responseSchemaPointer(op: SpecOperation, status: number): { pointer?: string; declared: boolean } {
    const responses = op.op.responses ?? {};
    const key = responses[String(status)] ? String(status) : responses[`${String(status)[0]}XX`] ? `${String(status)[0]}XX` : responses.default ? 'default' : undefined;
    if (!key) return { declared: false };
    let resp = responses[key];
    let base = `#/paths/${esc(op.path)}/${op.method.toLowerCase()}/responses/${esc(key)}`;
    if (resp.$ref) {
      base = resp.$ref;
      resp = this.resolve(resp.$ref);
    }
    const content = resp?.content ?? {};
    const ct = Object.keys(content).find((c) => c.includes('json'));
    if (!ct || !content[ct]?.schema) return { declared: true };
    return { declared: true, pointer: `${base}/content/${esc(ct)}/schema` };
  }

  validate(method: string, url: string, status: number, body: unknown): SchemaCheck {
    const op = this.match(method, url);
    if (!op) return { valid: false, skipped: 'no matching operation in spec' };
    const { pointer, declared } = this.responseSchemaPointer(op, status);
    if (!declared) return { operation: op, valid: false, errors: [`status ${status} is not documented for ${op.method} ${op.path}`] };
    if (!pointer) return { operation: op, valid: true, skipped: 'no JSON schema documented for this response' };
    let fn = this.cache.get(pointer);
    if (fn === undefined) {
      try {
        fn = this.ajv.compile({ $ref: `openapi${pointer}` });
      } catch (e: any) {
        fn = null;
      }
      this.cache.set(pointer, fn);
    }
    if (!fn) return { operation: op, valid: false, skipped: 'response schema could not be compiled' };
    const ok = fn(body);
    return {
      operation: op,
      valid: !!ok,
      errors: ok ? undefined : (fn.errors ?? []).slice(0, 8).map((e) => `${e.instancePath || '(root)'} ${e.message}${e.params && (e.params as any).additionalProperty ? ` '${(e.params as any).additionalProperty}'` : ''}`),
    };
  }

  resolve(ref: string): any {
    if (!ref.startsWith('#/')) return undefined;
    return ref
      .slice(2)
      .split('/')
      .map((s) => s.replace(/~1/g, '/').replace(/~0/g, '~'))
      .reduce((acc: any, k) => acc?.[k], this.doc);
  }

  /** Compile a schema by JSON pointer (cached); a schema the validator cannot compile returns its error instead. */
  compilePointer(pointer: string): { fn?: ValidateFunction; error?: string } {
    const key = `ptr:${pointer}`;
    const hit = this.cache.get(key);
    if (hit) return { fn: hit };
    try {
      const fn = this.ajv.compile({ $ref: `openapi${pointer}` });
      this.cache.set(key, fn);
      return { fn };
    } catch (e: any) {
      return { error: e.message };
    }
  }

  /** Validate an arbitrary schema (by JSON pointer) against a value. */
  validatePointer(pointer: string, value: unknown): string[] | null {
    const { fn, error } = this.compilePointer(pointer);
    if (!fn) return [`schema not compilable: ${error}`];
    return fn(value) ? null : (fn.errors ?? []).slice(0, 5).map((e) => `${e.instancePath || '(root)'} ${e.message}`);
  }
}

function sanitize(node: any, pointer: string, defects: string[]) {
  if (Array.isArray(node)) {
    node.forEach((n, i) => sanitize(n, `${pointer}/${i}`, defects));
    return;
  }
  if (!node || typeof node !== 'object') return;
  if (node.nullable !== undefined && node.type === undefined) {
    defects.push(`${pointer}: "nullable" without "type"`);
    delete node.nullable;
  }
  // OAS 3.0 boolean exclusiveMinimum/exclusiveMaximum (valid there) make a draft-07 validator throw: convert to the numeric form.
  for (const [ex, lim] of [['exclusiveMinimum', 'minimum'], ['exclusiveMaximum', 'maximum']] as const) {
    if (typeof node[ex] !== 'boolean') continue;
    if (node[ex] && typeof node[lim] === 'number') {
      node[ex] = node[lim];
      delete node[lim];
    } else delete node[ex];
  }
  // BG's own "oneOf: [{}, ...]" (empty body or one of the forms): {} matches everything, so oneOf would reject every
  // body that also matches a form. anyOf keeps the intent.
  if (Array.isArray(node.oneOf) && node.anyOf === undefined && node.oneOf.some((x: any) => x && typeof x === 'object' && !Array.isArray(x) && !Object.keys(x).length)) {
    node.anyOf = node.oneOf;
    delete node.oneOf;
  }
  // Unknown formats (e.g. "ipv4 or ipv6") would make the validator throw.
  if (typeof node.format === 'string' && /\s/.test(node.format)) {
    defects.push(`${pointer}: invalid format "${node.format}"`);
    delete node.format;
  }
  for (const [k, v] of Object.entries(node)) sanitize(v, `${pointer}/${k.replace(/~/g, '~0').replace(/\//g, '~1')}`, defects);
}

function esc(s: string): string {
  return s.replace(/~/g, '~0').replace(/\//g, '~1');
}

function basePathOf(url: string): string {
  try {
    return new URL(url).pathname.replace(/\/$/, '');
  } catch {
    return '';
  }
}
