import { AuditContext, REF } from './context';
import { ibanValid } from './data.checks';

/**
 * Layer 1 (standard compatibility), static part: checks the bank's published OpenAPI document itself.
 * A TPP builds against this document, so defects here become integration bugs.
 */
export function runStaticSpecChecks(ctx: AuditContext) {
  const spec = ctx.spec;
  if (!spec) {
    ctx.add({
      checkId: 'spec.available',
      layer: 'conformance',
      status: 'fail',
      severity: 'high',
      title: 'Published OpenAPI specification',
      message: 'No machine-readable OpenAPI document could be retrieved for this target.',
      fix: 'Publish the OpenAPI document for every API version at a stable URL so TPPs can generate clients and run conformance tests.',
      reference: REF.GE,
    });
    return;
  }
  ctx.pass({
    checkId: 'spec.available',
    layer: 'conformance',
    title: 'Published OpenAPI specification',
    message: `Loaded ${spec.operations.length} operations from ${spec.source} (OpenAPI ${spec.doc.openapi ?? '?'}).`,
  });

  // 0. The published file must parse as-is. Vendored copies record what had to be repaired to load them.
  const repairs: string[] = spec.doc['x-scio-repairs'] ?? [];
  if (repairs.length)
    ctx.add({ checkId: 'spec.parse', layer: 'conformance', status: 'fail', severity: 'medium', title: 'Published spec parses as-is', message: `The published file is not valid YAML: ${repairs.length} line(s) had to be removed before any tool could read it. Code generators and validators fail on the original.`, actual: repairs.slice(0, 3).join(' | '), fix: 'Remove the commented-out lines from inside the multi-line descriptions (a "#" at column 0 ends the YAML block), or indent them as text.', reference: REF.OAS, evidence: repairs });
  else ctx.pass({ checkId: 'spec.parse', layer: 'conformance', title: 'Published spec parses as-is', message: 'The published file loads without repairs.' });

  // 1. Malformed path templates, e.g. "/v2/loans{resourceId}/balances" (missing "/").
  const malformed = spec.operations.filter((o) => /[^/]\{/.test(o.path) || /\}[^/]/.test(o.path));
  if (malformed.length) {
    for (const o of malformed) {
      const fixed = o.path.replace(/([^/])\{/g, '$1/{').replace(/\}([^/])/g, '}/$1');
      ctx.add({
        checkId: 'spec.path-template',
        layer: 'conformance',
        status: 'fail',
        severity: 'medium',
        title: 'Malformed path template',
        endpoint: `${o.method} ${o.path}`,
        message: 'A path parameter is not a full path segment. Generated clients will build wrong URLs.',
        expected: fixed,
        actual: o.path,
        fix: `Change the path to "${fixed}" in the published specification, and check that the implementation serves that route.`,
        reference: REF.OAS,
      });
    }
  } else {
    ctx.pass({ checkId: 'spec.path-template', layer: 'conformance', title: 'Path templates well-formed', message: 'Every path parameter is a full path segment.' });
  }

  // 2. Path parameters declared in "parameters".
  let undeclared = 0;
  for (const o of spec.operations) {
    const names = (o.path.match(/\{([^}]+)\}/g) ?? []).map((n) => n.slice(1, -1));
    const params = [...(spec.doc.paths[o.path].parameters ?? []), ...(o.op.parameters ?? [])].map((p: any) =>
      p.$ref ? spec.resolve(p.$ref) : p,
    );
    for (const n of names) {
      if (!params.some((p: any) => p?.in === 'path' && p?.name === n)) {
        undeclared++;
        ctx.add({
          checkId: 'spec.path-params',
          layer: 'conformance',
          status: 'fail',
          severity: 'low',
          title: 'Path parameter not declared',
          endpoint: `${o.method} ${o.path}`,
          message: `Path parameter "{${n}}" has no matching "in: path" parameter definition.`,
          fix: `Add a parameter object { name: "${n}", in: "path", required: true } to the operation.`,
          reference: REF.OAS,
        });
      }
    }
  }
  if (!undeclared) ctx.pass({ checkId: 'spec.path-params', layer: 'conformance', title: 'Path parameters declared', message: 'All path parameters have definitions.' });

  // 3. X-Request-ID must be mandatory on every XS2A request (XS2A service paths only; path-item parameters count too).
  const relaxed: string[] = [];
  const seen = new Set<string>();
  let xs2aOps = 0;
  for (const o of spec.operations) {
    if (o.path.includes('oauth') || o.path.includes('.well-known')) continue;
    if (![o.path, spec.basePath + o.path, spec.targetBase + o.path].some((p) => XS2A_PATH.test(p))) continue;
    xs2aOps++;
    const params = [...(o.op.parameters ?? []), ...(spec.doc.paths[o.path].parameters ?? [])].map((p: any) => (p.$ref ? spec.resolve(p.$ref) : p));
    const rid = params.find((p: any) => p?.in === 'header' && /^x-request-id$/i.test(p?.name));
    if (!rid || rid.required !== true) {
      relaxed.push(`${o.method} ${o.path}`);
      seen.add(rid ? `required: ${rid.required ?? 'not set (false)'}` : 'not declared');
    }
  }
  if (relaxed.length) {
    ctx.add({
      checkId: 'spec.x-request-id-required',
      layer: 'conformance',
      status: 'fail',
      severity: 'medium',
      title: 'X-Request-ID documented as optional',
      message: `${relaxed.length} of ${xs2aOps} XS2A operations declare X-Request-ID as optional or omit it. The standard makes it mandatory on every request for traceability.`,
      expected: 'X-Request-ID: required, format uuid',
      actual: [...seen].join('; '),
      fix: 'Mark X-Request-ID as required on all XS2A operations and reject requests without a valid UUID with 400 FORMAT_ERROR.',
      reference: REF.BG,
      evidence: relaxed.slice(0, 20),
    });
  } else if (xs2aOps) {
    ctx.pass({ checkId: 'spec.x-request-id-required', layer: 'conformance', title: 'X-Request-ID mandatory', message: `All ${xs2aOps} XS2A operations require X-Request-ID.` });
  } else {
    ctx.add({ checkId: 'spec.x-request-id-required', layer: 'conformance', status: 'info', severity: 'none', title: 'X-Request-ID mandatory', message: 'No XS2A service operation found in the spec, nothing to check.' });
  }

  // 4. Security schemes: defined vs used.
  const defined = Object.keys(spec.doc.components?.securitySchemes ?? {});
  const used = new Set<string>();
  for (const o of spec.operations) for (const s of o.op.security ?? spec.doc.security ?? []) Object.keys(s).forEach((k) => used.add(k));
  const unused = defined.filter((d) => !used.has(d));
  if (unused.length) {
    ctx.add({
      checkId: 'spec.security-schemes-unused',
      layer: 'conformance',
      status: 'warn',
      severity: 'low',
      title: 'Security schemes defined but never applied',
      message: `${unused.length} of ${defined.length} security schemes are declared but no operation uses them. The documented security model does not match the operations.`,
      fix: 'Remove unused schemes, or reference them from the operations they protect.',
      reference: REF.OAS,
      evidence: unused.slice(0, 20),
    });
  }
  const types = new Set(defined.map((k) => spec.doc.components.securitySchemes[k]?.type));
  if (!types.has('mutualTLS') && !defined.some((k) => /mtls|certificate/i.test(k))) {
    ctx.add({
      checkId: 'spec.mtls-documented',
      layer: 'security',
      status: 'warn',
      severity: 'low',
      title: 'Client-certificate authentication not documented',
      message: 'The specification does not describe mutual TLS (QWAC) client authentication, although the Georgian standard requires TPP identification by certificate.',
      fix: 'Document the certificate requirement (OpenAPI 3.1 "mutualTLS" scheme, or a description on every operation).',
      reference: REF.MTLS,
    });
  }

  // 5. Examples must validate against their own schemas (one finding per spec, every failing example in evidence).
  // A requestBody given as $ref is followed; schemas the validator cannot compile are counted apart, not as example failures.
  let exampleFailures = 0;
  let exampleCount = 0;
  const badExamples: { endpoint: string; example: string; errors: string }[] = [];
  const uncompilable: { endpoint: string; example: string; error: string }[] = [];
  for (const o of spec.operations) {
    const { body, pointer: bodyPointer } = requestBodyOf(spec, o);
    const content = body?.content ?? {};
    for (const [ct, media] of Object.entries<any>(content)) {
      if (!ct.includes('json') || !media?.schema) continue;
      for (const [name, exRef] of Object.entries<any>(media.examples ?? {})) {
        const ex = exRef?.$ref ? spec.resolve(exRef.$ref) : exRef;
        if (ex?.value === undefined) continue;
        const pointer = `${bodyPointer}/content/${ct.replace(/~/g, '~0').replace(/\//g, '~1')}/schema`;
        const { fn, error } = spec.compilePointer(pointer);
        if (!fn) {
          uncompilable.push({ endpoint: `${o.method} ${o.path}`, example: name, error: String(error).slice(0, 200) });
          continue;
        }
        exampleCount++;
        if (!fn(ex.value)) {
          exampleFailures++;
          badExamples.push({ endpoint: `${o.method} ${o.path}`, example: name, errors: (fn.errors ?? []).slice(0, 5).map((e) => `${e.instancePath || '(root)'} ${e.message}`).join('; ') });
        }
      }
    }
  }
  const notChecked = uncompilable.length ? ` ${uncompilable.length} more could not be checked: their schema does not compile in a standard validator.` : '';
  if (exampleFailures)
    ctx.add({
      checkId: 'spec.examples-valid',
      layer: 'conformance',
      status: 'fail',
      severity: 'low',
      title: 'Documented example violates its own schema',
      endpoint: badExamples.length === 1 ? badExamples[0].endpoint : `${new Set(badExamples.map((b) => b.endpoint)).size} operations`,
      message: `${exampleFailures} of ${exampleCount} request examples do not validate against their own request schema. TPPs copying them will get errors.${notChecked}`,
      actual: badExamples.slice(0, 3).map((b) => `${b.endpoint} "${b.example}": ${b.errors.slice(0, 160)}`).join(' | '),
      fix: 'Correct the examples, or the schemas if the examples show the real format (field names are case-sensitive in the standard, e.g. "accounts", not "Accounts").',
      reference: REF.BG,
      evidence: { failing: badExamples.slice(0, 50), notCompilable: uncompilable.slice(0, 20) },
    });
  else if (exampleCount) ctx.pass({ checkId: 'spec.examples-valid', layer: 'conformance', title: 'Request examples valid', message: `All ${exampleCount} JSON request examples validate against their schemas.${notChecked}`, evidence: uncompilable.length ? { notCompilable: uncompilable.slice(0, 20) } : undefined });
  else ctx.add({ checkId: 'spec.examples-valid', layer: 'conformance', status: 'info', severity: 'none', title: 'Request examples valid', message: `No JSON request example could be checked.${notChecked}`, evidence: uncompilable.length ? { notCompilable: uncompilable.slice(0, 20) } : undefined });

  // 5b. Schemas that a standard JSON Schema validator cannot compile.
  if (spec.schemaDefects.length) {
    ctx.add({
      checkId: 'spec.schema-valid',
      layer: 'conformance',
      status: 'warn',
      severity: 'low',
      title: 'Schemas not machine-validatable',
      message: `${spec.schemaDefects.length} schema locations are invalid for standard validators and code generators.`,
      actual: spec.schemaDefects.slice(0, 4).join('; '),
      fix: 'Give every "nullable" schema an explicit "type", and use registered "format" values (e.g. "ipv4", not "ipv4 or ipv6").',
      reference: REF.OAS,
      evidence: spec.schemaDefects.slice(0, 30),
    });
  } else {
    ctx.pass({ checkId: 'spec.schema-valid', layer: 'conformance', title: 'Schemas machine-validatable', message: 'All schemas compile in a standard validator.' });
  }

  // 6. Error responses documented.
  const missingErrors = spec.operations.filter((o) => !Object.keys(o.op.responses ?? {}).some((k) => /^4/.test(k) || k === 'default'));
  if (missingErrors.length) {
    ctx.add({
      checkId: 'spec.error-responses',
      layer: 'conformance',
      status: 'warn',
      severity: 'low',
      title: 'Error responses not documented',
      message: `${missingErrors.length} operations document no 4xx or default response.`,
      fix: 'Document 400/401/403/404/405/409/429 responses with the tppMessages error structure.',
      reference: REF.BG,
      evidence: missingErrors.slice(0, 20).map((o) => `${o.method} ${o.path}`),
    });
  } else {
    ctx.pass({ checkId: 'spec.error-responses', layer: 'conformance', title: 'Error responses documented', message: 'Every operation documents error responses.' });
  }

  // 6b. Operations that document no success response (a TPP cannot know what success looks like).
  const noSuccess = spec.operations.filter((o) => !o.path.includes('oauth') && !Object.keys(o.op.responses ?? {}).some((k) => /^2/.test(k) || /^3/.test(k)));
  if (noSuccess.length)
    ctx.add({ checkId: 'spec.success-responses', layer: 'conformance', status: 'fail', severity: 'low', title: 'Success response not documented', message: `${noSuccess.length} operations document no 2xx response.`, fix: 'Document the success status and body (e.g. 204 or 202 for cancellations) for every operation.', reference: REF.OAS, evidence: noSuccess.map((o) => `${o.method} ${o.path}`) });
  else ctx.pass({ checkId: 'spec.success-responses', layer: 'conformance', title: 'Success responses documented', message: 'Every operation documents a 2xx response.' });

  // 6c. Error examples whose own "status" contradicts the response code they document.
  const contradictions: string[] = [];
  for (const o of spec.operations)
    for (const [code, resp0] of Object.entries<any>(o.op.responses ?? {})) {
      if (!/^[45]\d\d$/.test(code)) continue;
      const resp = resp0?.$ref ? spec.resolve(resp0.$ref) : resp0;
      for (const media of Object.values<any>(resp?.content ?? {})) {
        const exs = [media?.example, ...Object.values<any>(media?.examples ?? {}).map((e) => (e?.$ref ? spec.resolve(e.$ref) : e)?.value)].filter((e) => e && typeof e === 'object');
        for (const ex of exs) if (typeof ex.status === 'number' && String(ex.status) !== code) contradictions.push(`${o.method} ${o.path} ${code}: example says status ${ex.status}`);
      }
    }
  if (contradictions.length)
    ctx.add({ checkId: 'spec.error-examples', layer: 'conformance', status: 'warn', severity: 'low', title: 'Error examples contradict their status code', message: `${contradictions.length} documented error examples carry a different "status" than the response they illustrate (e.g. a 401 example with status 400). TPPs cannot learn real error handling from them.`, actual: contradictions.slice(0, 3).join('; '), fix: 'Give each status code its own realistic example with the matching status and message code.', reference: REF.BG, evidence: contradictions.slice(0, 40) });

  // 6d. Example IBANs that fail their own checksum.
  const badIbans = new Set<string>();
  const scan = (v: any) => {
    if (Array.isArray(v)) v.forEach(scan);
    else if (v && typeof v === 'object') for (const [k, x] of Object.entries(v)) (k === 'iban' && typeof x === 'string' ? (!ibanValid(x.trim()) && badIbans.add(x.trim())) : scan(x));
  };
  for (const o of spec.operations) for (const media of Object.values<any>(requestBodyOf(spec, o).body?.content ?? {})) for (const e of Object.values<any>(media?.examples ?? {})) scan((e?.$ref ? spec.resolve(e.$ref) : e)?.value);
  if (badIbans.size)
    ctx.add({ checkId: 'spec.example-ibans', layer: 'conformance', status: 'warn', severity: 'low', title: 'Example IBANs fail the checksum', message: `${badIbans.size} IBANs in request examples fail the ISO 13616 mod-97 check. A TPP testing with them gets errors from any bank that validates IBANs.`, actual: [...badIbans].slice(0, 5).join(', '), fix: 'Use checksum-valid IBANs in every example.', reference: REF.IBAN });

  // 6e. The same header under two names (e.g. "consentId" and "Consent-ID") on one operation.
  const dupHeaders: string[] = [];
  for (const o of spec.operations) {
    const names = [...(spec.doc.paths[o.path].parameters ?? []), ...(o.op.parameters ?? [])].map((p: any) => (p.$ref ? spec.resolve(p.$ref) : p)).filter((p: any) => p?.in === 'header').map((p: any) => String(p.name));
    const seen = new Map<string, string>();
    for (const n of names) {
      const k = n.toLowerCase().replace(/[-_]/g, '');
      if (seen.has(k) && seen.get(k) !== n) dupHeaders.push(`${o.method} ${o.path}: "${seen.get(k)}" and "${n}"`);
      seen.set(k, n);
    }
  }
  if (dupHeaders.length)
    ctx.add({ checkId: 'spec.duplicate-headers', layer: 'conformance', status: 'fail', severity: 'low', title: 'Same header documented under two names', message: `${dupHeaders.length} operations declare one header twice with different spellings. Generated clients send both or the wrong one.`, actual: dupHeaders.slice(0, 3).join('; '), fix: 'Keep the standard name only (e.g. "Consent-ID").', reference: REF.GE, evidence: dupHeaders });

  // 7. Version in base path (in the server URL, the target's base URL, or as a prefix of every path).
  const allPathsVersioned = spec.operations.length > 0 && spec.operations.every((o) => /^\/0\.8\//.test(o.path));
  if (!/\/0\.8(\/|$)/.test(spec.basePath) && !/\/0\.8(\/|$)/.test(new URL(ctx.target.baseUrl).pathname) && !allPathsVersioned) {
    ctx.add({
      checkId: 'spec.version-path',
      layer: 'conformance',
      status: 'warn',
      severity: 'low',
      title: 'Standard version not visible in base path',
      message: `Base path "${spec.basePath}" does not carry the standard version 0.8.`,
      fix: 'Expose the standard version in the base path (e.g. /0.8/v1/...).',
      reference: REF.GE,
    });
  }

  runCrossBankSpecChecks(ctx);
}

/** XS2A service paths (GE-XS2A §7.1: /{version}/v1/{service}), with an optional version prefix such as /0.8. */
const XS2A_PATH = /^(\/[^/]+)*?\/v[12]\/(consents|accounts|card-accounts|cards|payments|bulk-payments|periodic-payments|recurring-payments|deferred-payments|secured-payments|savings|loans|funds-confirmations|signing-baskets|\{[^}]*service[^}]*\})(\/|$)/;

/** Last two host labels (bank domain); Georgian second-level domains (com.ge, org.ge, ...) keep three. */
function registrable(host: string): string {
  const parts = host.toLowerCase().split('.');
  const n = parts.length >= 3 && /^(com|org|net|gov|edu)$/.test(parts[parts.length - 2]) ? 3 : 2;
  return parts.slice(-n).join('.');
}

/** The operation's request body, following a $ref to components/requestBodies, and the JSON pointer of the body object. */
function requestBodyOf(spec: NonNullable<AuditContext['spec']>, o: { method: string; path: string; op: any }): { body?: any; pointer: string } {
  const rb = o.op.requestBody;
  if (rb?.$ref) return { body: spec.resolve(rb.$ref), pointer: rb.$ref };
  return { body: rb, pointer: `#/paths/${o.path.replace(/~/g, '~0').replace(/\//g, '~1')}/${o.method.toLowerCase()}/requestBody` };
}

/** Georgian 0.8 core operations as concrete calls (relative to the /0.8 base); any spec template that serves them counts. */
const CORE_AIS = ['POST /v1/consents', 'GET /v1/consents/x', 'GET /v1/consents/x/status', 'DELETE /v1/consents/x', 'GET /v1/accounts', 'GET /v1/accounts/x', 'GET /v1/accounts/x/balances', 'GET /v1/accounts/x/transactions'];
const CORE_PIS = ['POST /v1/payments/domestic', 'GET /v1/payments/domestic/x', 'GET /v1/payments/domestic/x/status'];

/**
 * Checks that only make sense side by side across banks: where the spec points, which version it declares,
 * whether the core endpoints sit where the standard puts them, how authentication is documented,
 * and how amounts are typed. They feed the incompatibility matrix with one row per question.
 */
export function runCrossBankSpecChecks(ctx: AuditContext) {
  const spec = ctx.spec;
  if (!spec) return;
  const doc = spec.doc;

  // a. servers: https URL on the bank's own host (relative URLs resolve against the target base URL); one match is enough.
  const servers: string[] = (doc.servers ?? []).map((x: any) => String(x?.url ?? ''));
  const bankHost = new URL(ctx.target.baseUrl).hostname.toLowerCase();
  const matching = servers.filter((u) => {
    try {
      // Only a path ("/0.8/v1", "./v1") is relative; a bare host without scheme is read by generators as a path, so it does not count.
      if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(u) && !/^\.{0,2}\//.test(u)) return false;
      const h = new URL(u, ctx.target.baseUrl);
      return h.protocol === 'https:' && (h.hostname.toLowerCase() === bankHost || registrable(h.hostname) === registrable(bankHost));
    } catch {
      return false;
    }
  });
  const badServers = servers.filter((u) => !matching.includes(u));
  if (!matching.length)
    ctx.add({ checkId: 'spec.servers', layer: 'conformance', status: 'warn', severity: 'low', title: 'Spec servers point to the bank API', message: servers.length ? `The published spec lists ${badServers.map((u) => `"${u}"`).join(', ')} as servers instead of the bank's own https host (${bankHost}). Generated clients call the wrong host.` : 'The published spec lists no servers; generated clients have no base URL.', expected: `https://${bankHost}/...`, actual: servers.join(', ') || 'none', fix: 'List the bank\'s sandbox and production base URLs (https, full path) under servers.', reference: REF.OAS });
  else ctx.pass({ checkId: 'spec.servers', layer: 'conformance', title: 'Spec servers point to the bank API', message: `${matching.join(', ')}${badServers.length ? ` (also listed: ${badServers.join(', ')})` : ''}` });

  // b. declared version vs the Georgian standard 0.8. No clause governs info.version (the standard version is carried in the
  // URL, GE-XS2A §7.1, judged by spec.version-path), so this is informational only.
  const declared = String(doc.info?.version ?? '').trim();
  const isV08 = /^v?0\.8(\b|$)/i.test(declared);
  ctx.add({ checkId: 'spec.standard-version', layer: 'conformance', status: 'info', severity: 'none', title: 'Declared version matches the Georgian standard', message: isV08 ? `Declares ${declared}.` : `Declares version "${declared || 'none'}" in info.version; the Georgian standard in force is 0.8 (GE-XS2A §2.1.1: 0.8.RC1 or newer). info.version is the document's own version and no clause governs it; the standard version belongs in the URL (GE-XS2A §7.1, see spec.version-path).`, expected: '0.8', actual: declared || 'none' });

  // c. core endpoints where the standard puts them (path parameters and a leading /0.8 are normalised away).
  // Each spec path becomes a pattern ({param} = one segment, a leading /0.8 dropped); a core call is present if one matches.
  // Paths relative to a server URL (e.g. servers .../0.8/v1 + "/consents") are read with that prefix, from the spec's servers or the target's base URL.
  const prefixes = [...new Set(['', spec.basePath, spec.targetBase])];
  const patterns = spec.operations.flatMap((o) =>
    prefixes.map((pre) => ({
      method: o.method,
      re: new RegExp(`^${(pre + o.path).replace(/^.*?\/0\.8(?=\/)/, '').split(/(\{[^}]+\})/).map((x) => (x.startsWith('{') ? '[^/]+' : x.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))).join('')}$`),
    })),
  );
  const served = (call: string) => {
    const [m, path] = call.split(' ');
    return patterns.some((x) => x.method === m && x.re.test(path));
  };
  const norm = (m: string, p: string) => `${m} ${p.replace(/^\/0\.8(?=\/)/, '')}`;
  const missingAis = CORE_AIS.filter((k) => !served(k));
  const missingPis = CORE_PIS.filter((k) => !served(k));
  const v2 = spec.operations.filter((o) => /^\/(openfinance\/)?v2\//.test(o.path)).length;
  const missing = [...missingAis, ...missingPis];
  ctx.add({
    checkId: 'spec.core-paths',
    layer: 'conformance',
    status: missing.length ? 'fail' : 'pass',
    severity: missingAis.length ? 'high' : missing.length ? 'medium' : 'none',
    title: 'Core AIS/PIS endpoints at the standard paths',
    message: missing.length
      ? `${missing.length} of ${CORE_AIS.length + CORE_PIS.length} core 0.8 operations are not at the standard path${v2 ? ` (the spec has ${v2} operations under /v2 instead)` : ''}. A TPP integrating against the standard cannot call them without bank-specific routing.`
      : `All ${CORE_AIS.length + CORE_PIS.length} core AIS and PIS operations are at the standard paths.`,
    expected: 'e.g. POST /v1/consents, GET /v1/accounts/{account-id}/balances, POST /v1/payments/{payment-product}',
    actual: missing.length ? `missing: ${missing.slice(0, 6).join('; ')}${missing.length > 6 ? ' ...' : ''}` : undefined,
    fix: missing.length ? 'Serve and document the 0.8 paths (/0.8/v1/...); keep extensions (v2, open finance) as additions, not replacements.' : undefined,
    reference: REF.GE,
    evidence: { missing, v2Operations: v2 },
  });

  // d. authentication documented as OAuth2 / bearer on protected operations.
  const schemes = doc.components?.securitySchemes ?? {};
  const kinds = Object.values<any>(schemes).map((x) => `${x?.type}${x?.scheme ? `/${x.scheme}` : ''}`);
  const oauthLike = Object.values<any>(schemes).some((x) => x?.type === 'oauth2' || x?.type === 'openIdConnect' || (x?.type === 'http' && /bearer/i.test(x?.scheme ?? '')));
  const accountsOp = spec.operations.find((o) => norm(o.method, o.path) === 'GET /v1/accounts') ?? spec.operations.find((o) => o.method === 'GET' && /\/v\d\/accounts$/.test(o.path));
  const protectedDocumented = !!(accountsOp && (accountsOp.op.security ?? doc.security)?.length);
  const authOk = oauthLike && protectedDocumented;
  ctx.add({ checkId: 'spec.auth-documented', layer: 'security', status: authOk ? 'pass' : 'warn', severity: authOk ? 'none' : 'medium', title: 'OAuth2 access documented', message: authOk ? `Bearer/OAuth2 scheme applied to the account list (${kinds.join(', ')}).` : `${oauthLike ? 'A bearer/OAuth2 scheme exists' : `Security schemes are ${kinds.join(', ') || 'missing'} (no OAuth2 or HTTP bearer)`}${protectedDocumented ? '' : ', and GET accounts declares no security requirement'}. The spec does not say how a TPP gets and sends its access token.`, expected: 'OAuth2 (or HTTP bearer) scheme, required on AIS/PIS operations, with authorize/token URLs documented', actual: kinds.join(', ') || 'none', fix: authOk ? undefined : 'Document the OAuth2 flow (authorize and token URLs, scopes) as an oauth2 security scheme and require it on every protected operation.', reference: `${REF.OAUTH}; ${REF.FAPI}` });

  // f. string types (IBAN, currency, text) exported as objects with only a "length" property: a code-generator artefact.
  const wrapped = Object.entries<any>(doc.components?.schemas ?? {})
    .filter(([, sch]) => sch?.type === 'object' && sch.properties && Object.keys(sch.properties).length === 1 && sch.properties.length?.type === 'integer')
    .map(([name]) => name);
  if (wrapped.length)
    ctx.add({ checkId: 'spec.string-types', layer: 'conformance', status: 'fail', severity: 'high', title: 'String types documented as strings', message: `${wrapped.length} schemas that the standard defines as strings (e.g. ${wrapped.slice(0, 3).join(', ')}) are documented as objects with a single "length" property. A client generated from this spec sends {"length": 22} instead of an IBAN.`, expected: 'iban: string (pattern [A-Z]{2}[0-9]{2}[A-Z0-9]{1,30}), currency: string (ISO 4217)', actual: `type: object, properties: { length: integer } (${wrapped.slice(0, 6).join(', ')}${wrapped.length > 6 ? ', ...' : ''})`, fix: 'Export these types as "type: string" with their pattern; the object form comes from the API framework\'s serializer, not the data on the wire.', reference: REF.BG, evidence: wrapped });
  else ctx.pass({ checkId: 'spec.string-types', layer: 'conformance', title: 'String types documented as strings', message: 'No string type is exported as an object.' });

  // e. amounts typed as decimal strings (Berlin Group Amount.amount is a string).
  const numeric: string[] = [];
  for (const [name, sch] of Object.entries<any>(doc.components?.schemas ?? {})) {
    const a = sch?.properties?.amount;
    if (a && (a.type === 'number' || a.type === 'integer')) numeric.push(name);
  }
  if (numeric.length)
    ctx.add({ checkId: 'spec.amount-type', layer: 'data', status: 'fail', severity: 'medium', title: 'Amounts typed as decimal strings', message: `${numeric.length} schemas type "amount" as a number. JSON numbers lose precision in many clients; the standard uses decimal strings.`, actual: numeric.slice(0, 5).join(', '), expected: 'amount: string, pattern -?[0-9]{1,14}(.[0-9]{1,3})?', fix: 'Type every amount as a string with the standard pattern.', reference: REF.BG });
  else ctx.pass({ checkId: 'spec.amount-type', layer: 'data', title: 'Amounts typed as decimal strings', message: 'No schema types "amount" as a number.' });

  // g. Variable recurring payments (VRP) for sweeping: NBG lists the service as "available, but not yet in practical use".
  // GE-XS2A 0.8.RC3 predates it and no published Georgian or Berlin Group clause fixes its path, so this is informational
  // (unscored): it shows which banks publish the service at all, next to the fixed-amount recurring services.
  const VRP = /\bvrps?\b|variable[\s_-]*recurring|sweep/i;
  const RECURRING = /recurring|periodic|standing[\s_-]*order/i;
  const opText = (o: (typeof spec.operations)[number]) => [o.path, o.op?.operationId, o.op?.summary, ...(o.op?.tags ?? []), String(o.op?.description ?? '').slice(0, 300)].filter(Boolean).join(' ');
  const vrpOps = spec.operations.filter((o) => VRP.test(opText(o))).map((o) => `${o.method} ${o.path}`);
  const vrpSchemas = Object.keys(doc.components?.schemas ?? {}).filter((n) => VRP.test(n));
  const recurringOps = spec.operations.filter((o) => !VRP.test(opText(o)) && RECURRING.test(o.path)).map((o) => `${o.method} ${o.path}`);
  ctx.add({
    checkId: 'spec.vrp',
    layer: 'conformance',
    status: 'info',
    severity: 'none',
    title: 'Variable recurring payments (sweeping) published',
    message: vrpOps.length
      ? `${vrpOps.length} VRP operation(s) published: ${vrpOps.slice(0, 4).join('; ')}${vrpOps.length > 4 ? ' ...' : ''}.`
      : `No VRP / sweeping operation in the published spec${vrpSchemas.length ? ` (VRP schemas exist: ${vrpSchemas.slice(0, 3).join(', ')}, but no operation uses them)` : ''}. ${recurringOps.length ? `Fixed-amount recurring payments are published (${recurringOps.length} operations, e.g. ${recurringOps[0]}), which do not cover variable amounts.` : 'No recurring payment service is published either.'} NBG lists VRPs for sweeping as available; a TPP cannot build sweeping on this spec.`,
    expected: 'Operations for variable recurring payments (sweeping between the PSU\'s own accounts), as listed by NBG',
    actual: vrpOps.length ? vrpOps.slice(0, 6).join('; ') : 'none',
    fix: vrpOps.length ? undefined : 'Publish the VRP (sweeping) service in the OpenAPI document once offered, with its consent (mandate) and payment operations.',
    evidence: { vrpOperations: vrpOps, vrpSchemas, recurringOperations: recurringOps.length },
  });
}
