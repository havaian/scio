import { AuditContext, REF } from './context';

const AMOUNT_RE = /^-?[0-9]{1,14}(\.[0-9]{1,3})?$/;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
// Berlin Group IG 1.3.x §14.21 (the version line the Georgian guide references).
const BALANCE_TYPES = new Set(['closingBooked', 'expected', 'openingBooked', 'interimAvailable', 'interimBooked', 'forwardAvailable', 'nonInvoiced']);
// ISO 4217 X-codes (fund, metal and special codes) are missing from Intl; GE-XS2A §9.3.3/§9.3.4 require XXX for multi-currency accounts.
const ISO_X_CODES = ['XAG', 'XAU', 'XBA', 'XBB', 'XBC', 'XBD', 'XDR', 'XPD', 'XPT', 'XSU', 'XTS', 'XUA', 'XXX', 'XAF', 'XCD', 'XCG', 'XOF', 'XPF'];
export const CURRENCIES = new Set<string>([...((Intl as any).supportedValuesOf?.('currency') ?? []), ...ISO_X_CODES]);

export function ibanValid(iban: string): boolean {
  const s = iban.replace(/\s+/g, '').toUpperCase();
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{10,30}$/.test(s)) return false;
  if (s.startsWith('GE') && !/^GE\d{2}[A-Z]{2}\d{16}$/.test(s)) return false;
  const rearranged = s.slice(4) + s.slice(0, 4);
  const digits = rearranged.replace(/[A-Z]/g, (c) => String(c.charCodeAt(0) - 55));
  let rem = 0;
  for (const ch of digits) rem = (rem * 10 + Number(ch)) % 97;
  return rem === 1;
}

function walk(v: any, fn: (key: string, val: any, path: string) => void, path = '') {
  if (Array.isArray(v)) v.forEach((x, i) => walk(x, fn, `${path}[${i}]`));
  else if (v && typeof v === 'object')
    for (const [k, x] of Object.entries(v)) {
      fn(k, x, `${path}.${k}`);
      walk(x, fn, `${path}.${k}`);
    }
}

/** Data quality: completeness and consistency of returned account data. */
export function runDataChecks(ctx: AuditContext) {
  const reads = [...(ctx.state.accountReads ?? []), ...(ctx.state.cardReads ?? [])];
  // extraBodies: deposit and loan responses collected by the v2 journey.
  const bodies = [ctx.state.accounts?.json, ctx.state.cards?.json, ...reads.flatMap((r: any) => [r.details?.json, r.balances?.json, r.tx?.json]), ...(ctx.state.extraBodies ?? [])].filter(Boolean);
  if (!bodies.length) {
    ctx.add({ checkId: 'data.available', layer: 'data', status: 'skip', severity: 'none', title: 'Account data', message: 'No account data was retrieved, data-quality checks skipped.' });
    return;
  }

  const badIbans = new Set<string>();
  const badCcy = new Set<string>();
  const badAmounts: string[] = [];
  const badDates: string[] = [];
  const badBalanceTypes = new Set<string>();
  let ibans = 0, amounts = 0;
  for (const b of bodies)
    walk(b, (k, v, p) => {
      if (k === 'iban' && typeof v === 'string') {
        ibans++;
        if (!ibanValid(v)) badIbans.add(v);
      }
      if (k === 'currency' && typeof v === 'string' && CURRENCIES.size && !CURRENCIES.has(v)) badCcy.add(v);
      if (k === 'amount') {
        amounts++;
        if (typeof v !== 'string' || !AMOUNT_RE.test(v)) badAmounts.push(`${p} = ${JSON.stringify(v)}`);
      }
      if (/(bookingDate|valueDate|referenceDate)$/.test(k) && typeof v === 'string' && !DATE_RE.test(v)) badDates.push(`${p} = ${v}`);
      if (k === 'balanceType' && typeof v === 'string' && !BALANCE_TYPES.has(v)) badBalanceTypes.add(v);
    });

  if (badIbans.size)
    ctx.add({ checkId: 'data.iban', layer: 'data', status: 'fail', severity: 'medium', title: 'IBAN check digits', message: `${badIbans.size} of ${ibans} IBANs fail the ISO 13616 mod-97 check (or the Georgian 22-character format). A TPP validating IBANs before a payment would reject them.`, actual: [...badIbans].slice(0, 5).join(', '), fix: 'Return real, checksum-valid IBANs (GE + 2 check digits + 2-letter bank code + 16 digits). In test data, generate check digits instead of hard-coding them.', reference: REF.IBAN });
  else if (ibans) ctx.pass({ checkId: 'data.iban', layer: 'data', title: 'IBAN check digits', message: `${ibans} IBANs valid.` });

  if (badCcy.size) ctx.add({ checkId: 'data.currency', layer: 'data', status: 'fail', severity: 'medium', title: 'Currency codes', message: 'Non-ISO currency codes returned.', actual: [...badCcy].join(', '), fix: 'Use ISO 4217 alphabetic codes.', reference: REF.CCY });
  else ctx.pass({ checkId: 'data.currency', layer: 'data', title: 'Currency codes', message: 'All currency codes are ISO 4217.' });

  if (badAmounts.length) ctx.add({ checkId: 'data.amount-format', layer: 'data', status: 'fail', severity: 'medium', title: 'Amount format', message: `${badAmounts.length} of ${amounts} amounts are not strings in the standard decimal format. Numbers lose precision in JSON parsers.`, actual: badAmounts.slice(0, 5).join('; '), fix: 'Send amounts as strings matching -?[0-9]{1,14}(.[0-9]{1,3})?.', reference: REF.BG });
  else if (amounts) ctx.pass({ checkId: 'data.amount-format', layer: 'data', title: 'Amount format', message: `${amounts} amounts in standard string format.` });

  if (badDates.length) ctx.add({ checkId: 'data.date-format', layer: 'data', status: 'fail', severity: 'low', title: 'Date format', message: 'Dates not in ISO 8601 YYYY-MM-DD.', actual: badDates.slice(0, 5).join('; '), fix: 'Use ISODate (YYYY-MM-DD) for booking and value dates.', reference: REF.BG });
  else ctx.pass({ checkId: 'data.date-format', layer: 'data', title: 'Date format', message: 'Booking and value dates are ISO 8601.' });

  if (badBalanceTypes.size) ctx.add({ checkId: 'data.balance-types', layer: 'data', status: 'fail', severity: 'low', title: 'Balance types', message: 'Balance types outside the standard code list.', actual: [...badBalanceTypes].join(', '), fix: 'Use the standard balanceType code list (closingBooked, expected, interimAvailable, ...).', reference: REF.BG });

  // Minimum balance types per endpoint (GE XS2A IG §9.3.3, §9.3.4, §9.3.5, §9.4.7).
  const types = (bals: any[] | undefined) => new Set((bals ?? []).map((b: any) => b.balanceType));
  const minChecks: { where: string; have: Set<string>; need: string[]; anyOf?: boolean; sec: string }[] = [];
  for (const a of ctx.state.accounts?.json?.accounts ?? []) if (Array.isArray(a.balances)) minChecks.push({ where: `account list · ${a.resourceId}`, have: types(a.balances), need: ['interimAvailable', 'interimBooked'], anyOf: true, sec: 'GE-XS2A §9.3.3' });
  for (const rd of ctx.state.accountReads ?? []) {
    const det = rd.details?.json?.account;
    if (Array.isArray(det?.balances)) minChecks.push({ where: `account details · ${rd.id}`, have: types(det.balances), need: ['interimAvailable', 'interimBooked'], sec: 'GE-XS2A §9.3.4' });
    if (rd.balances?.status === 200) minChecks.push({ where: `balances · ${rd.id}`, have: types(rd.balances.json?.balances), need: ['closingBooked', 'interimAvailable'], sec: 'GE-XS2A §9.3.5' });
  }
  // Card accounts return every balance an account returns (§9.4.7, so §9.3.5); "at least interimAvailable" is for /v1/cards/{id}/balances only.
  for (const rd of ctx.state.cardReads ?? []) if (rd.balances?.status === 200) minChecks.push({ where: `card-account balances · ${rd.id}`, have: types(rd.balances.json?.balances), need: ['closingBooked', 'interimAvailable'], sec: 'GE-XS2A §9.4.7 (as §9.3.5)' });
  for (const m of minChecks) {
    const missing = m.anyOf ? (m.need.some((n) => m.have.has(n)) ? [] : m.need) : m.need.filter((n) => !m.have.has(n));
    ctx.add({
      checkId: 'data.balance-minimum',
      layer: 'data',
      status: missing.length ? 'fail' : 'pass',
      severity: missing.length ? 'medium' : 'none',
      title: 'Required balance types present',
      endpoint: m.where,
      message: missing.length ? `Missing ${m.anyOf ? 'any interim balance' : missing.join(' and ')}; returned: ${[...m.have].join(', ') || 'none'}.` : `Returned: ${[...m.have].join(', ')}.`,
      expected: `${m.anyOf ? 'at least one interim balance (interimAvailable preferred)' : m.need.join(' + ')} per ${m.sec}`,
      actual: [...m.have].join(', ') || 'none',
      fix: missing.length ? `Return ${m.anyOf ? 'at least one interim balance, preferably interimAvailable' : m.need.join(' and ')} for this endpoint.` : undefined,
      reference: REF.GE,
    });
  }

  // Transactions: requested window respected, unique ids, signs consistent with credit/debit fields.
  // Card accounts answer under cardTransactions with cardTransactionId (GE-XS2A §9.4.8: no entryReferenceFrom paging for cards).
  const win = ctx.state.txWindow;
  const cardIds = new Set<any>(ctx.state.cardReads ?? []);
  for (const r of reads) {
    if (!r.tx || r.tx.status !== 200) continue;
    const card = cardIds.has(r);
    const list = card ? r.tx.json?.cardTransactions : r.tx.json?.transactions;
    const booked: any[] = list?.booked ?? [];
    const pending: any[] = list?.pending ?? [];
    const idField = card ? 'cardTransactionId' : 'entryReference';
    const where = `${card ? 'card-account ' : ''}transactions of ${r.id}`;
    // Banks book on Tbilisi dates and may list items certain to post today (GE-XS2A §9.3.6), while the window is a UTC date: one day of tolerance on dateTo.
    const upper = win?.to ? new Date(Date.parse(win.to) + 86400_000).toISOString().slice(0, 10) : undefined;
    const outOfWindow = booked.filter((t) => win && t.bookingDate && (t.bookingDate < win.from || (upper && t.bookingDate > upper)));
    // entryReference (cardTransactionId for cards) is mandatory on every transaction, drives entryReferenceFrom paging on accounts and is unique across booked and pending (GE §9.3.6.6).
    const all = [...booked, ...pending];
    const ids = all.map((t) => t[idField]).filter(Boolean);
    const dupes = ids.filter((id, i) => ids.indexOf(id) !== i);
    const missingId = all.length - ids.length;
    if (!booked.length) ctx.add({ checkId: 'data.tx-window', layer: 'data', status: 'info', severity: 'none', title: 'Date filter respected', endpoint: where, message: `No booked transactions returned for ${win?.from}..${win?.to}, so the date filter could not be observed.` });
    else if (outOfWindow.length) ctx.add({ checkId: 'data.tx-window', layer: 'data', status: 'fail', severity: 'medium', title: 'Date filter respected', endpoint: where, message: `${outOfWindow.length} of ${booked.length} transactions fall outside dateFrom/dateTo ${win.from}..${win.to} (one day of tolerance after dateTo for Tbilisi booking dates).`, actual: outOfWindow.slice(0, 5).map((t) => t.bookingDate).join(', '), fix: 'Apply dateFrom/dateTo to bookingDate on the server.', reference: REF.BG });
    else ctx.pass({ checkId: 'data.tx-window', layer: 'data', title: 'Date filter respected', endpoint: where, message: `${booked.length} transactions, all inside ${win.from}..${win.to}.` });
    if (!all.length) ctx.add({ checkId: 'data.tx-ids', layer: 'data', status: 'info', severity: 'none', title: 'Transaction identifiers', endpoint: where, message: 'No transactions returned, so identifiers could not be checked.' });
    // GE-XS2A does not name cardTransactionId; Berlin Group makes it optional. For cards only a repeated id is a failure,
    // a missing one is a low warning (TPPs cannot de-duplicate).
    else if (dupes.length || missingId) ctx.add({ checkId: 'data.tx-ids', layer: 'data', status: card && !dupes.length ? 'warn' : 'fail', severity: card && !dupes.length ? 'low' : 'medium', title: 'Transaction identifiers', endpoint: where, message: `${missingId} of ${all.length} transactions lack ${idField} and ${dupes.length} repeat one. TPPs ${card ? '' : 'page with entryReferenceFrom and '}de-duplicate by it.`, fix: `Return a unique ${idField} (Max35Text) on every transaction, unique across booked and pending.`, reference: REF.BG });
    else ctx.pass({ checkId: 'data.tx-ids', layer: 'data', title: 'Transaction identifiers', endpoint: where, message: `${idField} present and unique on all ${all.length} transactions.` });
  }
}
