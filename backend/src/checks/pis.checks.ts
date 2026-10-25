import { randomInt } from 'node:crypto';
import { HttpResponse } from '../common/http';
import { api, authorizeScopes, unavailable } from '../flows/full.flow';
import { newRequestId } from '../common/http';
import { AuditContext, REF } from './context';
import { errCode, is } from './live-conformance.checks';

/**
 * Payment initiation (PIS) on targets provided for testing: single, recurring and future-dated (deferred) payments.
 * NBG lists recurring, future-dated and VRP payments as "available, not yet in practical use": exactly where a
 * TPP needs proof that the API behaves before building on it. Only runs when the bank's spec documents the endpoints.
 */

// ISO 20022 ExternalPaymentTransactionStatus1Code, as used by the Berlin Group guidelines (§14.13).
export const TX_STATUS = new Set(['ACCC', 'ACCP', 'ACSC', 'ACSP', 'ACTC', 'ACWC', 'ACWP', 'RCVD', 'PDNG', 'RJCT', 'CANC', 'ACFC', 'PATC', 'PART']);

/** Builds a checksum-valid Georgian IBAN (GE + 2 check digits + 2-letter bank code + 16 digits). */
export function makeGeIban(bank = 'TB'): string {
  const bban = bank + Array.from({ length: 16 }, () => randomInt(10)).join('');
  const digits = (bban + 'GE00').replace(/[A-Z]/g, (c) => String(c.charCodeAt(0) - 55));
  let rem = 0;
  for (const ch of digits) rem = (rem * 10 + Number(ch)) % 97;
  return `GE${String(98 - rem).padStart(2, '0')}${bban}`;
}

/** Same IBAN with a wrong check digit. */
export function breakIban(iban: string): string {
  const d = (Number(iban.slice(2, 4)) + 1) % 100;
  return iban.slice(0, 2) + String(d === 0 || d === 1 ? 2 : d).padStart(2, '0') + iban.slice(4);
}

const isoDate = (d: Date) => d.toISOString().slice(0, 10);
const days = (n: number) => new Date(Date.now() + n * 86400_000);

function has(ctx: AuditContext, method: string, path: string) {
  return !!ctx.spec?.operations.some((o) => o.method === method && o.path === path);
}

type Neg = { id: string; title: string; run: () => Promise<HttpResponse>; expect: (r: HttpResponse) => boolean; expected: string; severity: 'high' | 'medium' | 'low'; fix: string; layer?: 'conformance' | 'security'; endpoint: string };

/** Runs negative tests with the same verdict rules as the AIS ones: outage = skip, other 4xx = interoperability warning. */
export async function runNegatives(ctx: AuditContext, negs: Neg[], reference = REF.BG) {
  for (const n of negs) {
    let r = await n.run();
    if (unavailable(r)) {
      await new Promise((res) => setTimeout(res, 1000));
      r = await n.run();
    }
    if (unavailable(r)) {
      ctx.add({ checkId: n.id, layer: n.layer ?? 'conformance', status: 'skip', severity: 'none', title: n.title, endpoint: n.endpoint, message: `Could not be tested: service unavailable (${ctx.short(r)}). Rerun the audit.`, expected: n.expected, actual: ctx.short(r) });
      continue;
    }
    const ok = n.expect(r);
    const rejectedOtherwise = !ok && r.status >= 400 && r.status < 500;
    ctx.add({
      checkId: n.id,
      layer: rejectedOtherwise ? 'conformance' : (n.layer ?? 'conformance'),
      status: ok ? 'pass' : rejectedOtherwise ? 'warn' : 'fail',
      severity: ok ? 'none' : rejectedOtherwise ? 'low' : n.severity,
      title: n.title,
      endpoint: n.endpoint,
      message: ok
        ? `Rejected as expected (${ctx.short(r)}).`
        : rejectedOtherwise
          ? `Rejected, but with ${ctx.short(r)} instead of ${n.expected}. TPPs that branch on status codes will mis-handle it.`
          : `Not rejected: the request was served (${ctx.short(r)}).`,
      expected: n.expected,
      actual: ctx.short(r),
      fix: ok ? undefined : n.fix,
      reference,
    });
  }
}

/** Checks a payment initiation 201 response: id, status code, SCA links, headers. */
function checkCreated(ctx: AuditContext, checkId: string, endpoint: string, r: HttpResponse) {
  const problems: string[] = [];
  if (!r.json?.paymentId) problems.push('no paymentId');
  if (!TX_STATUS.has(r.json?.transactionStatus)) problems.push(`transactionStatus "${r.json?.transactionStatus}" is not an ISO 20022 code`);
  if (!r.headers['location']) problems.push('missing Location header');
  if (!r.headers['aspsp-sca-approach']) problems.push('missing ASPSP-SCA-Approach header');
  const links = r.json?._links ?? {};
  if (!links.scaOAuth && !links.scaRedirect && !links.startAuthorisation) problems.push('no SCA link in _links');
  if (!links.self) problems.push('no self link');
  ctx.add({
    checkId,
    layer: 'conformance',
    status: problems.length ? 'warn' : 'pass',
    severity: problems.length ? 'low' : 'none',
    title: 'Payment initiation response',
    endpoint,
    message: problems.length ? problems.join('; ') : `paymentId, transactionStatus ${r.json.transactionStatus}, Location, ASPSP-SCA-Approach and SCA links present.`,
    expected: '201 with paymentId, ISO 20022 transactionStatus, Location, ASPSP-SCA-Approach, _links (SCA + self)',
    fix: problems.length ? 'Return the full payment initiation response: paymentId, transactionStatus, Location, ASPSP-SCA-Approach and the SCA link for the chosen approach.' : undefined,
    reference: REF.BG,
  });
}

function baseBody(ctx: AuditContext) {
  const debtor = ctx.state.accountReads?.[0]?.details?.json?.account?.iban ?? ctx.state.accounts?.json?.accounts?.[0]?.iban;
  return {
    ...(debtor ? { debtorAccount: { iban: debtor, currency: 'GEL' } } : {}),
    instructedAmount: { currency: 'GEL', amount: '1.50' },
    creditorAccount: { iban: makeGeIban(), currency: 'GEL' },
    creditorName: 'Scio Test Creditor',
    remittanceInformationUnstructured: 'Scio conformance test',
  };
}

export async function runPis(ctx: AuditContext) {
  if (!has(ctx, 'POST', '/v1/payments/{payment-product}')) return;
  const product = 'domestic';
  const redirect = { 'TPP-Redirect-URI': ctx.target.redirectUri ?? 'https://example.org/cb' };
  const create = (body: unknown, op = 'pis.create', prod = product) =>
    api(ctx, op, 'POST', `/v1/payments/${prod}`, { auth: false, consent: false, headers: redirect, json: body, retries: op === 'pis.create' ? 3 : 1, validate: !op.startsWith('pis.neg.') });

  // 1. Single payment: create -> authorise -> status -> details (echo of what was sent).
  const body = baseBody(ctx);
  const created = await create(body);
  if (unavailable(created)) {
    ctx.add({ checkId: 'pis.create', layer: 'conformance', status: 'skip', severity: 'none', title: 'Create payment initiation', endpoint: `POST /v1/payments/${product}`, message: `Could not be tested: service unavailable after retries (${ctx.short(created)}). Payment checks skipped.` });
    return;
  }
  if (created.status !== 201 || !created.json?.paymentId) {
    ctx.add({ checkId: 'pis.create', layer: 'conformance', status: 'fail', severity: 'high', title: 'Create payment initiation', endpoint: `POST /v1/payments/${product}`, message: `A valid domestic payment was not accepted (${ctx.short(created)}).`, expected: '201 Created with paymentId', actual: ctx.short(created), fix: 'Accept standard payment initiation bodies (instructedAmount, creditorAccount, creditorName) and return 201 with paymentId.', reference: REF.BG, evidence: { request: body } });
    return;
  }
  ctx.pass({ checkId: 'pis.create', title: 'Create payment initiation', layer: 'conformance', endpoint: `POST /v1/payments/${product}`, message: `Payment ${created.json.paymentId} created (${created.json.transactionStatus}).` });
  checkCreated(ctx, 'pis.create-response', `POST /v1/payments/${product} -> 201`, created);
  const paymentId: string = created.json.paymentId;
  ctx.state.pis = { paymentId, product };

  const auth = await authorizeScopes(ctx, [`PIS:${paymentId}`, 'PIS'], 'pis.oauth');
  if (!auth) {
    ctx.add({ checkId: 'pis.authorize', layer: 'conformance', status: 'fail', severity: 'high', title: 'Payment authorisation (OAuth SCA)', endpoint: 'authorize + token', message: 'No access token could be obtained for the payment with scope PIS:<paymentId> or PIS.', fix: 'Support OAuth2 SCA for payment initiation with a payment-bound scope, as for AIS consents.', reference: REF.OAUTH });
  } else {
    ctx.state.pis.token = auth.token;
    ctx.pass({ checkId: 'pis.authorize', layer: 'conformance', title: 'Payment authorisation (OAuth SCA)', endpoint: 'authorize + token', message: `Authorised with PKCE, scope "${auth.scope}".` });

    const status = await api(ctx, 'pis.status', 'GET', `/v1/payments/${product}/${paymentId}/status`, { token: auth.token, consent: false });
    const stOk = status.status === 200 && TX_STATUS.has(status.json?.transactionStatus);
    if (!unavailable(status))
      ctx.add({ checkId: 'pis.status', layer: 'conformance', status: stOk ? 'pass' : 'fail', severity: stOk ? 'none' : 'medium', title: 'Payment status', endpoint: 'GET /v1/payments/{product}/{paymentId}/status', message: stOk ? `transactionStatus ${status.json.transactionStatus}.` : `Status could not be read as an ISO 20022 code (${ctx.short(status)}, transactionStatus "${status.json?.transactionStatus}").`, expected: '200 with ISO 20022 transactionStatus', actual: ctx.short(status), fix: stOk ? undefined : 'Return 200 with transactionStatus from the ISO 20022 code list (RCVD, ACTC, ACSC, RJCT, ...).', reference: REF.BG });

    const details = await api(ctx, 'pis.details', 'GET', `/v1/payments/${product}/${paymentId}`, { token: auth.token, consent: false });
    if (details.status === 200) {
      const diffs: string[] = [];
      const got = details.json ?? {};
      if (got.instructedAmount?.amount !== undefined && Number(got.instructedAmount.amount) !== Number(body.instructedAmount.amount)) diffs.push(`amount ${got.instructedAmount.amount} vs sent ${body.instructedAmount.amount}`);
      if (got.instructedAmount?.currency && got.instructedAmount.currency !== body.instructedAmount.currency) diffs.push(`currency ${got.instructedAmount.currency} vs sent ${body.instructedAmount.currency}`);
      if (got.creditorAccount?.iban && got.creditorAccount.iban !== body.creditorAccount.iban) diffs.push(`creditor IBAN ${got.creditorAccount.iban} vs sent ${body.creditorAccount.iban}`);
      if (!got.instructedAmount || !got.creditorAccount) diffs.push('instructedAmount or creditorAccount missing from the payment resource');
      ctx.add({ checkId: 'pis.echo', layer: 'data', status: diffs.length ? 'fail' : 'pass', severity: diffs.length ? 'high' : 'none', title: 'Payment resource matches the initiation', endpoint: 'GET /v1/payments/{product}/{paymentId}', message: diffs.length ? diffs.join('; ') : 'Amount, currency and creditor account are returned exactly as initiated.', fix: diffs.length ? 'Store and return the payment exactly as initiated; any difference means the PSU may authorise something other than what the TPP sent.' : undefined, reference: REF.BG });
    } else if (!unavailable(details)) {
      ctx.add({ checkId: 'pis.echo', layer: 'conformance', status: 'fail', severity: 'medium', title: 'Payment resource readable', endpoint: 'GET /v1/payments/{product}/{paymentId}', message: `The payment just created could not be read (${ctx.short(details)}).`, fix: 'Serve GET on the payment resource for the TPP that created it.', reference: REF.BG });
    }
  }

  // 1b. Idempotency (GE-XS2A §7.7): X-Request-ID exists so the bank can tell a repeated request from a new one.
  // The same initiation sent twice with the same X-Request-ID (a TPP retrying after a timeout) must not create a second payment.
  {
    const rid = newRequestId();
    const once = baseBody(ctx);
    const first = await api(ctx, 'pis.idempotency', 'POST', `/v1/payments/${product}`, { auth: false, consent: false, headers: { ...redirect, 'X-Request-ID': rid }, json: once, retry: false, validate: false });
    const again = await api(ctx, 'pis.idempotency', 'POST', `/v1/payments/${product}`, { auth: false, consent: false, headers: { ...redirect, 'X-Request-ID': rid }, json: once, retry: false, validate: false });
    if (unavailable(first) || unavailable(again))
      ctx.add({ checkId: 'pis.idempotency', layer: 'conformance', status: 'skip', severity: 'none', title: 'Repeated X-Request-ID does not duplicate a payment', endpoint: `POST /v1/payments/${product}`, message: `Could not be tested: service unavailable (${ctx.short(unavailable(first) ? first : again)}).` });
    else if (first.status === 201 && first.json?.paymentId) {
      const duplicate = again.status === 201 && again.json?.paymentId && again.json.paymentId !== first.json.paymentId;
      const replayed = again.status >= 200 && again.status < 300 && again.json?.paymentId === first.json.paymentId;
      ctx.add({
        checkId: 'pis.idempotency',
        layer: 'conformance',
        status: duplicate ? 'fail' : 'pass',
        severity: duplicate ? 'high' : 'none',
        title: 'Repeated X-Request-ID does not duplicate a payment',
        endpoint: `POST /v1/payments/${product}`,
        message: duplicate
          ? `The same initiation with the same X-Request-ID created a second payment (${first.json.paymentId}, then ${again.json.paymentId}). A TPP retrying after a timeout would initiate the payment twice.`
          : replayed
            ? `The repeat returned the original payment ${first.json.paymentId} (${ctx.short(again)}).`
            : `The repeat was refused (${ctx.short(again)}); no second payment was created.`,
        expected: 'same paymentId, or a 4xx naming the duplicate X-Request-ID (GE-XS2A §7.7)',
        actual: `${ctx.short(first)} then ${ctx.short(again)}`,
        fix: duplicate ? 'Keep X-Request-ID per TPP for a retention window; answer a repeat with the original response (or a 4xx), never a new resource.' : undefined,
        reference: 'GE-XS2A §7.7',
      });
    }
  }

  // 2. Negative tests on initiation (no token needed: creation precedes SCA).
  const goodIban = makeGeIban();
  const negs: Neg[] = [
    { id: 'pis.neg.missing-creditor', title: 'Payment without creditorAccount is rejected', endpoint: `POST /v1/payments/${product}`, run: () => create({ instructedAmount: { currency: 'GEL', amount: '1.00' }, creditorName: 'X' }, 'pis.neg.missing-creditor'), expect: is(400, 'FORMAT_ERROR'), expected: '400 FORMAT_ERROR', severity: 'medium', fix: 'Validate mandatory fields (creditorAccount, instructedAmount) and return 400 FORMAT_ERROR naming the field.' },
    { id: 'pis.neg.bad-iban', title: 'Creditor IBAN with a wrong check digit is rejected', endpoint: `POST /v1/payments/${product}`, run: () => create({ ...baseBody(ctx), creditorAccount: { iban: breakIban(goodIban), currency: 'GEL' } }, 'pis.neg.bad-iban'), expect: (r) => r.status === 400, expected: '400 FORMAT_ERROR', severity: 'medium', fix: 'Validate IBAN check digits (ISO 13616 mod-97) at initiation, before SCA, so the PSU never authorises an unpayable transfer.' },
    { id: 'pis.neg.bad-amount', title: 'Amount with 4 decimals is rejected', endpoint: `POST /v1/payments/${product}`, run: () => create({ ...baseBody(ctx), instructedAmount: { currency: 'GEL', amount: '1.2345' } }, 'pis.neg.bad-amount'), expect: is(400, 'FORMAT_ERROR'), expected: '400 FORMAT_ERROR', severity: 'medium', fix: 'Validate amount against -?[0-9]{1,14}(.[0-9]{1,3})? and the currency\'s minor units.' },
    { id: 'pis.neg.negative-amount', title: 'Negative amount is rejected', endpoint: `POST /v1/payments/${product}`, run: () => create({ ...baseBody(ctx), instructedAmount: { currency: 'GEL', amount: '-5.00' } }, 'pis.neg.negative-amount'), expect: (r) => r.status === 400, expected: '400 FORMAT_ERROR', severity: 'high', layer: 'security', fix: 'Reject zero or negative instructed amounts.' },
    { id: 'pis.neg.bad-currency', title: 'Unknown currency is rejected', endpoint: `POST /v1/payments/${product}`, run: () => create({ ...baseBody(ctx), instructedAmount: { currency: 'XYZ', amount: '1.00' } }, 'pis.neg.bad-currency'), expect: is(400, 'FORMAT_ERROR'), expected: '400 FORMAT_ERROR', severity: 'low', fix: 'Validate currency against ISO 4217.' },
    { id: 'pis.neg.unknown-product', title: 'Unknown payment product is rejected', endpoint: 'POST /v1/payments/{unknown-product}', run: () => create(baseBody(ctx), 'pis.neg.unknown-product', 'sepa-credit-transfers'), expect: is(404, 'PRODUCT_UNKNOWN'), expected: '404 PRODUCT_UNKNOWN', severity: 'low', fix: 'Answer unsupported payment products with 404 PRODUCT_UNKNOWN (BG IG §14.11).' },
  ];
  if (auth) {
    negs.push(
      { id: 'pis.neg.unknown-payment', title: 'Unknown paymentId is rejected', endpoint: 'GET /v1/payments/{product}/{paymentId}/status', run: () => api(ctx, 'pis.neg.unknown-payment', 'GET', `/v1/payments/${product}/00000000-0000-4000-8000-000000000000/status`, { token: auth.token, consent: false, validate: false }), expect: (r) => [403, 404].includes(r.status) && errCode(r) === 'RESOURCE_UNKNOWN', expected: '403 RESOURCE_UNKNOWN (resource in path)', severity: 'low', fix: 'Return 403 RESOURCE_UNKNOWN for payment ids unknown to this TPP.' },
      { id: 'pis.neg.no-token', title: 'Payment status without access token is rejected', endpoint: 'GET /v1/payments/{product}/{paymentId}/status', run: () => api(ctx, 'pis.neg.no-token', 'GET', `/v1/payments/${product}/${paymentId}/status`, { auth: false, consent: false, validate: false }), expect: (r) => r.status === 401, expected: '401 TOKEN_UNKNOWN / TOKEN_INVALID', severity: 'high', layer: 'security', fix: 'Require the payment-bound access token on every payment resource.' },
    );
    if (ctx.state.token?.access_token)
      negs.push({ id: 'pis.neg.ais-token', title: 'AIS token cannot read a payment', endpoint: 'GET /v1/payments/{product}/{paymentId}/status', run: () => api(ctx, 'pis.neg.ais-token', 'GET', `/v1/payments/${product}/${paymentId}/status`, { consent: false, validate: false }), expect: (r) => r.status === 401 || r.status === 403, expected: '401 TOKEN_INVALID or 403', severity: 'high', layer: 'security', fix: 'Bind tokens to their scope: a token issued for an AIS consent must not grant access to payment resources.' });
  }
  await runNegatives(ctx, negs);

  // 3. Cancellation of a fresh payment.
  if (has(ctx, 'DELETE', '/v1/{payment-service}/{payment-product}/{paymentId}')) {
    const second = await create(baseBody(ctx), 'pis.cancel.create');
    if (second.status === 201 && second.json?.paymentId) {
      const id = second.json.paymentId;
      const tok = (await authorizeScopes(ctx, [`PIS:${id}`, 'PIS'], 'pis.cancel.oauth'))?.token;
      const del = await api(ctx, 'pis.cancel', 'DELETE', `/v1/payments/${product}/${id}`, { token: tok, auth: !!tok, consent: false });
      if (!unavailable(del)) {
        const ok = del.status === 204 || del.status === 202 || (del.status === 405 && errCode(del) === 'CANCELLATION_INVALID');
        ctx.add({ checkId: 'pis.cancel', layer: 'conformance', status: ok ? 'pass' : 'fail', severity: ok ? 'none' : 'low', title: 'Payment cancellation', endpoint: 'DELETE /v1/payments/{product}/{paymentId}', message: ok ? `Answered ${ctx.short(del)}.` : `Cancelling a payment just created answered ${ctx.short(del)}. A payment that cannot be cancelled should answer 405 CANCELLATION_INVALID; SERVICE_INVALID says the endpoint itself is not offered.`, expected: '204 (cancelled), 202 (cancellation needs authorisation) or 405 CANCELLATION_INVALID', actual: ctx.short(del), fix: ok ? undefined : 'Return 204 or 202 for cancellable payments and 405 CANCELLATION_INVALID otherwise; document the 2xx response in the spec.', reference: REF.BG });
      }
    }
  }

  // 4. Recurring and future-dated (deferred) payments, v2 services added by the Georgian standard.
  // Berlin Group defines dayOfExecution as Max2Text ("01".."31"); send the type the bank documents, and report a difference.
  const recurringOp = ctx.spec!.operations.find((o) => o.method === 'POST' && o.path === '/v2/recurring-payments/{payment-product}');
  const recSchema = recurringOp?.op.requestBody?.content?.['application/json']?.schema;
  const recBody = recSchema?.$ref ? ctx.spec!.resolve(recSchema.$ref) : recSchema;
  const dayProp = recBody?.properties?.dayOfExecution?.$ref ? ctx.spec!.resolve(recBody.properties.dayOfExecution.$ref) : recBody?.properties?.dayOfExecution;
  const dayAsInteger = dayProp?.type === 'integer' || dayProp?.type === 'number';
  const day: string | number = dayAsInteger ? 15 : '15';
  if (dayAsInteger)
    ctx.add({ checkId: 'pis.recurring-day-type', layer: 'conformance', status: 'warn', severity: 'low', title: 'dayOfExecution type differs from the standard', endpoint: 'POST /v2/recurring-payments/{payment-product}', message: `The bank documents dayOfExecution as ${dayProp.type}; Berlin Group defines it as Max2Text ("01"-"31"). A TPP that follows the standard sends a string and gets 400.`, expected: 'string, e.g. "15"', actual: dayProp.type, fix: 'Accept dayOfExecution as a string per the standard (optionally also an integer), and document it as string.', reference: REF.BG });
  const v2: { id: string; title: string; path: string; specPath: string; body: () => any; bad: () => any; badTitle: string; badExpected: string; badExpect: (r: HttpResponse) => boolean; badFix: string }[] = [
    {
      id: 'pis.recurring',
      title: 'Recurring payment initiation',
      path: `/v2/recurring-payments/${product}`,
      specPath: '/v2/recurring-payments/{payment-product}',
      body: () => ({ ...baseBody(ctx), startDate: isoDate(days(2)), endDate: isoDate(days(180)), frequency: 'Monthly', dayOfExecution: day }),
      bad: () => ({ ...baseBody(ctx), startDate: isoDate(days(180)), endDate: isoDate(days(2)), frequency: 'Monthly', dayOfExecution: day }),
      badTitle: 'Recurring payment with endDate before startDate is rejected',
      badExpected: '400 FORMAT_ERROR or PERIOD_INVALID',
      badExpect: (r) => r.status === 400,
      badFix: 'Validate the execution window: endDate must not precede startDate.',
    },
    {
      id: 'pis.deferred',
      title: 'Future-dated payment initiation',
      path: `/v2/deferred-payments/${product}`,
      specPath: '/v2/{deferred-payment-service}/{payment-product}',
      body: () => ({ ...baseBody(ctx), requestedExecutionDate: isoDate(days(7)) }),
      bad: () => ({ ...baseBody(ctx), requestedExecutionDate: isoDate(days(-3)) }),
      badTitle: 'Future-dated payment with a past execution date is rejected',
      badExpected: '400 EXECUTION_DATE_INVALID',
      badExpect: is(400, 'EXECUTION_DATE_INVALID'),
      badFix: 'Reject execution dates in the past with 400 EXECUTION_DATE_INVALID (BG IG §14.11).',
    },
  ];
  for (const s of v2) {
    if (!has(ctx, 'POST', s.specPath)) continue;
    const r = await api(ctx, `${s.id}.create`, 'POST', s.path, { auth: false, consent: false, headers: redirect, json: s.body(), retries: 2 });
    if (unavailable(r)) {
      ctx.add({ checkId: s.id, layer: 'conformance', status: 'skip', severity: 'none', title: s.title, endpoint: `POST ${s.path}`, message: `Could not be tested: service unavailable (${ctx.short(r)}).` });
      continue;
    }
    if (r.status === 201 && r.json?.paymentId) {
      ctx.pass({ checkId: s.id, layer: 'conformance', title: s.title, endpoint: `POST ${s.path}`, message: `Created ${r.json.paymentId} (${r.json.transactionStatus}).` });
      checkCreated(ctx, `${s.id}-response`, `POST ${s.path} -> 201`, r);
    } else {
      ctx.add({ checkId: s.id, layer: 'conformance', status: 'fail', severity: 'medium', title: s.title, endpoint: `POST ${s.path}`, message: `A valid request was not accepted (${ctx.short(r)}).`, expected: '201 with paymentId', actual: ctx.short(r), fix: 'Accept standard bodies for this service and return 201 with paymentId and SCA links.', reference: REF.GE });
    }
    await runNegatives(ctx, [{ id: `${s.id}.neg`, title: s.badTitle, endpoint: `POST ${s.path}`, run: () => api(ctx, `${s.id}.neg`, 'POST', s.path, { auth: false, consent: false, headers: redirect, json: s.bad(), validate: false }), expect: s.badExpect, expected: s.badExpected, severity: 'medium', fix: s.badFix }]);
  }

  // 5. Services NBG lists as available but not yet in practical use: bulk payments (v1), multiple recurring payments
  // and secured payments (v2). Happy path only; bodies are fitted to the bank's documented schema.
  const extra: { id: string; title: string; path: string; specPath: string; body: () => any }[] = [
    {
      id: 'pis.bulk',
      title: 'Bulk payment initiation',
      path: `/v1/bulk-payments/${product}`,
      specPath: '/v1/bulk-payments/{payment-product}',
      body: () => {
        const b = baseBody(ctx);
        const item = (amount: string) => ({ instructedAmount: { currency: 'GEL', amount }, creditorAccount: { iban: makeGeIban(), currency: 'GEL' }, creditorName: b.creditorName, remittanceInformationUnstructured: b.remittanceInformationUnstructured });
        return { batchBookingPreferred: false, ...(b.debtorAccount ? { debtorAccount: b.debtorAccount } : {}), payments: [item('1.10'), item('1.20')] };
      },
    },
    {
      id: 'pis.multiple-recurring',
      title: 'Multiple recurring payment initiation',
      path: `/v2/multiple-recurring-payments/${product}`,
      specPath: '/v2/multiple-recurring-payments/{payment-product}',
      body: () => fitBody(ctx, '/v2/multiple-recurring-payments/{payment-product}', { ...baseBody(ctx), startDate: isoDate(days(2)), endDate: isoDate(days(180)), frequency: 'Monthly', dayOfExecution: day }),
    },
    {
      id: 'pis.secured',
      title: 'Secured payment initiation',
      path: `/v2/secured-payments/${product}`,
      specPath: '/v2/secured-payments/{payment-product}',
      body: () => fitBody(ctx, '/v2/secured-payments/{payment-product}', baseBody(ctx)),
    },
  ];
  for (const s of extra) {
    if (!has(ctx, 'POST', s.specPath)) continue;
    const json = s.body();
    const r = await api(ctx, `${s.id}.create`, 'POST', s.path, { auth: false, consent: false, headers: redirect, json, retries: 2 });
    if (unavailable(r)) {
      ctx.add({ checkId: s.id, layer: 'conformance', status: 'skip', severity: 'none', title: s.title, endpoint: `POST ${s.path}`, message: `Could not be tested: service unavailable (${ctx.short(r)}).` });
      continue;
    }
    if (r.status === 201 && r.json?.paymentId) {
      ctx.pass({ checkId: s.id, layer: 'conformance', title: s.title, endpoint: `POST ${s.path}`, message: `Created ${r.json.paymentId} (${r.json.transactionStatus}).` });
      checkCreated(ctx, `${s.id}-response`, `POST ${s.path} -> 201`, r);
    } else
      ctx.add({ checkId: s.id, layer: 'conformance', status: 'fail', severity: 'medium', title: s.title, endpoint: `POST ${s.path}`, message: `A request built from the documented schema was not accepted (${ctx.short(r)}).`, expected: '201 with paymentId and SCA links', actual: ctx.short(r), fix: 'Accept bodies that match the published schema for this service and return 201 with paymentId and SCA links.', reference: REF.GE, evidence: { request: json, response: r.text.slice(0, 500) } });
  }
}

/**
 * Fits a payment body to the documented request schema: TBC v2 schemas name the creditor as creditor.name instead of
 * creditorName, and forbid unknown members (additionalProperties: false).
 */
function fitBody(ctx: AuditContext, specPath: string, body: Record<string, any>): Record<string, any> {
  const op = ctx.spec?.operations.find((o) => o.method === 'POST' && o.path === specPath);
  const raw = op?.op.requestBody?.content?.['application/json']?.schema;
  const schema = raw?.$ref ? ctx.spec!.resolve(raw.$ref) : raw;
  const props = schema?.properties;
  if (!props) return body;
  const out: Record<string, any> = { ...body };
  if (!props.creditorName && props.creditor && out.creditorName) {
    out.creditor = { name: out.creditorName };
    delete out.creditorName;
  }
  if (schema.additionalProperties === false) for (const k of Object.keys(out)) if (!props[k]) delete out[k];
  return out;
}
