import { HttpResponse } from '../common/http';
import { AuditContext, REF } from '../checks/context';
import { ibanValid } from '../checks/data.checks';
import { runProbes } from '../checks/performance.checks';
import { checkTls, checkTransportHeaders } from '../checks/security.checks';
import { api } from './full.flow';

/** TBC's own documentation for BIS - Accounts (proprietary, not NextGenPSD2). */
const DOC = 'TBC BIS - Accounts API documentation (developers.tbcbank.ge, proprietary, not XS2A)';
const RFC_PROBLEM = 'RFC 9457 (Problem Details for HTTP APIs)';

/**
 * TBC Business Integration Services - Accounts: machine-to-machine account data for business clients.
 * Read-only: client-credentials token, movements, statement summary, balance, documented error cases.
 * Judged against TBC's own documentation and general HTTP/OAuth rules; transfers are never called.
 */
export async function runBisFlow(ctx: AuditContext) {
  const t = ctx.target;
  const b = t.bis!;
  const base = t.baseUrl.replace(/\/$/, '');
  await checkTls(ctx, base);

  const clientId = process.env[b.clientIdEnv] ?? '';
  const clientSecret = process.env[b.clientSecretEnv] ?? '';

  // Unauthenticated call first: documented 401 and the error format, observable without credentials.
  const noToken = await api(ctx, 'bis.neg.no-token', 'GET', `${base}/bab/v1/accounts/movements?PageIndex=0&PageSize=1`, { absolute: true, auth: false, consent: false, validate: false });
  checkTransportHeaders(ctx, noToken, 'GET /bab/v1/accounts/movements');
  if (noToken.status > 0)
    ctx.add({ checkId: 'bis.neg.no-token', layer: 'security', status: noToken.status === 401 ? 'pass' : 'fail', severity: noToken.status === 401 ? 'none' : 'high', title: 'Request without token is rejected', endpoint: 'GET /bab/v1/accounts/movements', message: noToken.status === 401 ? 'Rejected with 401.' : `Answered ${ctx.short(noToken)} without a token.`, expected: '401', actual: ctx.short(noToken), reference: REF.OAUTH });

  if (!clientId || !clientSecret) {
    ctx.add({ checkId: 'bis.flow', layer: 'conformance', status: 'skip', severity: 'none', title: 'BIS - Accounts flow', message: `Not run: ${b.clientIdEnv} and ${b.clientSecretEnv} are not set (app credentials from myapps.tbcbank.ge).` });
    return checkErrors(ctx);
  }

  // 1. Token: client credentials, HTTP Basic, form body (documented).
  const tokenUrl = b.tokenUrl ?? `${base}/oauth/token`;
  let tok = await ctx.http.request({ operation: 'bis.token', method: 'POST', url: tokenUrl, headers: { Authorization: `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString('base64')}` }, form: { grant_type: 'client_credentials', scope: b.scope } });
  if (tok.status === 0 || tok.status >= 500) {
    await new Promise((r) => setTimeout(r, 1500));
    tok = await ctx.http.request({ operation: 'bis.token', method: 'POST', url: tokenUrl, headers: { Authorization: `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString('base64')}` }, form: { grant_type: 'client_credentials', scope: b.scope } });
  }
  const token: string | undefined = tok.json?.access_token;
  if (!token) {
    const ours = tok.status === 401 || tok.status === 400;
    ctx.add({ checkId: 'bis.token', layer: 'conformance', status: ours ? 'skip' : 'fail', severity: ours ? 'none' : 'high', title: 'Client-credentials token', endpoint: `POST ${new URL(tokenUrl).pathname}`, message: ours ? `Token refused (${ctx.short(tok)}): check the app's client ID/secret and that "${b.scope}" is approved for it.` : `Token endpoint failed (${ctx.short(tok)}).`, actual: tok.text.slice(0, 300), reference: REF.OAUTH });
    return checkErrors(ctx);
  }
  const tokProblems: string[] = [];
  if (!/^bearer$/i.test(tok.json?.token_type ?? '')) tokProblems.push(`token_type "${tok.json?.token_type}"`);
  if (!(Number(tok.json?.expires_in) > 0)) tokProblems.push('expires_in missing');
  if (!/no-store/i.test(tok.headers['cache-control'] ?? '')) tokProblems.push('no Cache-Control: no-store');
  ctx.add({ checkId: 'bis.token', layer: 'security', status: tokProblems.length ? 'warn' : 'pass', severity: tokProblems.length ? 'low' : 'none', title: 'Client-credentials token', endpoint: `POST ${new URL(tokenUrl).pathname}`, message: tokProblems.length ? `Token issued; ${tokProblems.join('; ')}.` : `Bearer token issued, valid ${tok.json.expires_in} s.`, expected: 'token_type Bearer, expires_in, Cache-Control: no-store (RFC 6749 §5.1)', reference: REF.OAUTH });

  // 2. Movements (last 30 days, one small page).
  const to = new Date().toISOString().slice(0, 10);
  const from = new Date(Date.now() - 30 * 86400_000).toISOString().slice(0, 10);
  const mv = await api(ctx, 'bis.movements', 'GET', `${base}/bab/v1/accounts/movements?PeriodFrom=${from}&PeriodTo=${to}&PageIndex=0&PageSize=50`, { absolute: true, token, validate: false });
  const rows = listOf(mv.json);
  ctx.add({ checkId: 'bis.movements', layer: 'conformance', status: mv.status === 200 && rows ? 'pass' : 'fail', severity: mv.status === 200 && rows ? 'none' : 'high', title: 'Account movements', endpoint: 'GET /bab/v1/accounts/movements', message: mv.status === 200 && rows ? `${rows.length} movement(s) for ${from}..${to}.` : `Failed (${ctx.short(mv)}).`, actual: mv.status === 200 ? undefined : mv.text.slice(0, 300), reference: DOC });

  // Account and currency to use: from a movement, or from configuration.
  const acc = b.accountNumber ?? pick(rows?.[0], /^(account(number|iban)?|iban)$/i);
  const ccy = b.currency ?? pick(rows?.[0], /^(account)?currency(code)?$/i);

  // 3. Statement summary and balance.
  let bal: HttpResponse | undefined;
  if (acc && ccy) {
    const st = await api(ctx, 'bis.statement', 'GET', `${base}/bab/v1/accounts/statements?AccountNumber=${encodeURIComponent(acc)}&AccountCurrencyCode=${ccy}&PeriodFrom=${from}&PeriodTo=${to}`, { absolute: true, token, validate: false });
    ctx.add({ checkId: 'bis.statement', layer: 'conformance', status: st.status === 200 ? 'pass' : 'fail', severity: st.status === 200 ? 'none' : 'medium', title: 'Statement summary', endpoint: 'GET /bab/v1/accounts/statements', message: st.status === 200 ? 'Statement summary returned.' : `Failed (${ctx.short(st)}).`, reference: DOC });
    bal = await api(ctx, 'bis.balance', 'GET', `${base}/bab/v1/accounts/${encodeURIComponent(acc)}/balances/${ccy}`, { absolute: true, token, validate: false });
    ctx.add({ checkId: 'bis.balance', layer: 'conformance', status: bal.status === 200 ? 'pass' : 'fail', severity: bal.status === 200 ? 'none' : 'medium', title: 'Account balance', endpoint: 'GET /bab/v1/accounts/{iban}/balances/{currency}', message: bal.status === 200 ? 'Balance returned.' : `Failed (${ctx.short(bal)}).`, reference: DOC });
  } else {
    ctx.add({ checkId: 'bis.balance', layer: 'conformance', status: 'skip', severity: 'none', title: 'Statement and balance', message: 'No movement in the last 30 days to take an account from; set bis.accountNumber and bis.currency in targets.json.' });
  }

  // 4. Documented error cases.
  const half = await api(ctx, 'bis.neg.account-without-currency', 'GET', `${base}/bab/v1/accounts/movements?AccountNumber=${encodeURIComponent(acc ?? 'GE29TB0000000000000000')}&PeriodFrom=${from}&PeriodTo=${to}`, { absolute: true, token, validate: false });
  negative(ctx, half, 'bis.neg.filter-combination', 'AccountNumber without AccountCurrencyCode is rejected', 'GET /bab/v1/accounts/movements', /INCORRECT_INPUT_DATA|ValidationError/i);
  const unknown = await api(ctx, 'bis.neg.unknown-account', 'GET', `${base}/bab/v1/accounts/GE29NB0000000101904917/balances/GEL`, { absolute: true, token, validate: false });
  negative(ctx, unknown, 'bis.neg.unknown-account', 'Account not available to the client is rejected', 'GET /bab/v1/accounts/{iban}/balances/{currency}', /INVALID_ACCOUNT/i);
  const badDate = await api(ctx, 'bis.neg.bad-date', 'GET', `${base}/bab/v1/accounts/movements?PeriodFrom=not-a-date&PeriodTo=${to}`, { absolute: true, token, validate: false });
  negative(ctx, badDate, 'bis.neg.bad-date', 'Invalid date is rejected', 'GET /bab/v1/accounts/movements', /INCORRECT_INPUT_DATA|ValidationError/i);

  // 5. Data quality on what came back.
  const ibans = [...new Set((rows ?? []).flatMap((r) => Object.entries(r).filter(([k, v]) => /account|iban/i.test(k) && typeof v === 'string' && /^GE\d{2}/.test(v)).map(([, v]) => v as string)))];
  if (ibans.length) {
    const bad = ibans.filter((i) => !ibanValid(i));
    ctx.add({ checkId: 'data.iban', layer: 'data', status: bad.length ? 'fail' : 'pass', severity: bad.length ? 'medium' : 'none', title: 'IBAN check digits', message: bad.length ? `${bad.length} of ${ibans.length} IBANs fail ISO 13616.` : `${ibans.length} IBANs valid.`, evidence: bad.slice(0, 5), reference: REF.IBAN });
  }
  const dates = (rows ?? []).flatMap((r) => Object.entries(r).filter(([k, v]) => /date/i.test(k) && typeof v === 'string').map(([, v]) => v as string));
  if (dates.length) {
    const bad = dates.filter((d) => Number.isNaN(Date.parse(d)) || !/^\d{4}-\d{2}-\d{2}/.test(d));
    ctx.add({ checkId: 'data.date-format', layer: 'data', status: bad.length ? 'fail' : 'pass', severity: bad.length ? 'low' : 'none', title: 'ISO 8601 dates', message: bad.length ? `${bad.length} of ${dates.length} dates are not ISO 8601.` : `${dates.length} dates in ISO 8601, as documented.`, evidence: bad.slice(0, 5), reference: DOC });
  }

  // 6. Reliability and latency with the token (read-only endpoints).
  await runProbes(ctx, [
    { operation: 'movements', path: `${base}/bab/v1/accounts/movements?PeriodFrom=${from}&PeriodTo=${to}&PageIndex=0&PageSize=10`, absolute: true, token, consent: false },
    ...(acc && ccy && bal?.status === 200 ? [{ operation: 'balance', path: `${base}/bab/v1/accounts/${encodeURIComponent(acc)}/balances/${ccy}`, absolute: true, token, consent: false }] : []),
  ]);
  checkErrors(ctx);
}

function negative(ctx: AuditContext, r: HttpResponse, checkId: string, title: string, endpoint: string, code: RegExp) {
  if (r.status === 0) return;
  const ok = r.status === 400 && code.test(r.text);
  ctx.add({ checkId, layer: 'conformance', status: ok ? 'pass' : r.status >= 500 ? 'fail' : 'warn', severity: ok ? 'none' : r.status >= 500 ? 'medium' : 'low', title, endpoint, message: ok ? `Rejected with ${ctx.short(r)} as documented.` : `Answered ${ctx.short(r)}; the documentation lists 400 with ${code.source.replace(/\|/g, ' or ')}.`, expected: `400 ${code.source.replace(/\|/g, ' / ')}`, actual: r.text.slice(0, 200) || ctx.short(r), reference: DOC });
}

/** Errors are documented as application/problem+json: check content type and the RFC 9457 members. */
function checkErrors(ctx: AuditContext) {
  const errs = ctx.http.exchanges.filter((x) => x.status >= 400 && x.status < 500 && !x.operation.startsWith('probe.') && x.operation !== 'bis.token');
  if (!errs.length) return;
  const bad = errs.filter((x) => {
    let j: any;
    try {
      j = JSON.parse(x.bodySnippet);
    } catch {
      return true;
    }
    return !/problem\+json/i.test(x.responseHeaders['content-type'] ?? '') || !j?.title || (j.status !== undefined && j.status !== x.status);
  });
  ctx.add({ checkId: 'bis.error-format', layer: 'conformance', status: bad.length ? 'warn' : 'pass', severity: bad.length ? 'low' : 'none', title: 'Errors as problem+json', message: bad.length ? `${bad.length} of ${errs.length} error responses are not application/problem+json with a title (and a matching status).` : `All ${errs.length} error responses are problem+json.`, expected: 'Content-Type: application/problem+json; { type, title, status, detail }', evidence: bad.slice(0, 5).map((x) => `${x.status} ${x.method} ${new URL(x.url).pathname} (${x.responseHeaders['content-type'] ?? 'no content type'})`), reference: RFC_PROBLEM });
}

/** The movement list, wherever the page object keeps it. */
function listOf(j: any): any[] | undefined {
  if (Array.isArray(j)) return j;
  if (!j || typeof j !== 'object') return undefined;
  for (const k of ['movements', 'items', 'data', 'records', 'results', 'content']) if (Array.isArray(j[k])) return j[k];
  return Object.values(j).find(Array.isArray) as any[] | undefined;
}

function pick(o: any, key: RegExp): string | undefined {
  if (!o || typeof o !== 'object') return undefined;
  for (const [k, v] of Object.entries(o)) {
    if (key.test(k) && typeof v === 'string') return v;
    if (v && typeof v === 'object' && !Array.isArray(v)) {
      const inner = pick(v, key);
      if (inner) return inner;
    }
  }
  return undefined;
}
