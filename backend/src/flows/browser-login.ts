import { createHash, X509Certificate } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { certChain, CERT_DIR } from '../common/credentials';
import { TargetConfig } from '../common/types';

/**
 * Bank login pages that need a real browser (JavaScript apps, multi-step forms): headless Chromium via playwright-core.
 * Enabled when the image is built with WITH_BROWSER=true (CHROMIUM_PATH points to the system Chromium).
 * Works like a person: fills user, password and OTP fields, ticks account boxes, presses the approving button,
 * and stops at the redirect to the TPP (that request is intercepted, never sent).
 */
export const browserEnabled = () => !!process.env.CHROMIUM_PATH && existsSync(process.env.CHROMIUM_PATH) && process.env.BROWSER_LOGIN !== 'false';

export interface BrowserLoginResult {
  /** Final redirect to the TPP, with code (or error) in the query. */
  redirect?: string;
  steps: string[];
  error?: string;
  /** Compact structure of the page where the login stopped (forms, inputs incl. hidden, account rows, alerts). */
  dump?: string;
  /** What a person had to do on the bank's pages (consent journey friction), counted once per distinct screen. */
  metrics?: JourneyMetrics;
}

/**
 * Consent journey friction, as a person would experience it. Repeats the automation needs on the same screen
 * (a retry after an unchanged page) are not counted; the fixed waits of the automation are not timed.
 */
export interface JourneyMetrics {
  /** Distinct screens acted on (URL path + set of fields). */
  screens: number;
  /** Values typed: user name fields, password fields, OTP entries (a code split over one box per digit = 1). */
  typed: { user: number; password: number; otp: number };
  /** Account or option choices: checkboxes, radios, account tiles or rows. */
  choices: number;
  /** Buttons pressed (approve, confirm, next). */
  clicks: number;
  /** Main-frame page loads, redirects included, until the return to the TPP. */
  navigations: number;
  /** Distinct hosts the person passes through (domains only, no paths). */
  hosts: string[];
}

export function emptyMetrics(): JourneyMetrics {
  return { screens: 0, typed: { user: 0, password: 0, otp: 0 }, choices: 0, clicks: 0, navigations: 0, hosts: [] };
}

/**
 * SPKI hashes of the target's extra CA (e.g. GBA NoTrust test root and intermediate): Chromium accepts server chains
 * containing these keys and nothing else beyond the public roots. TLS checking stays on.
 */
function spkiList(target: TargetConfig): string[] {
  const ca = target.credentials?.ca;
  if (!ca) return [];
  const file = resolve(CERT_DIR, ca);
  if (!existsSync(file)) return [];
  return certChain(readFileSync(file)).map((c: X509Certificate) => createHash('sha256').update(c.publicKey.export({ type: 'spki', format: 'der' })).digest('base64'));
}

const OTP = /otp|sms|code|pin|token|one.?time|კოდ/i;
const USER = /user|login|uname|email|psu|name|phone|mobile|id|მომხმარებ/i;
const APPROVE = /approve|allow|accept|confirm|yes|agree|authori|grant|give|continue|next|submit|send|verify|log ?in|sign ?in|proceed|ok\b|დადასტურ|ავტორიზ|შესვლა|გაგრძელ|თანხმ|ვეთანხმ|ნებართვ|დაშვ|მიღებ|გაგზავნ|შემდეგ|დიახ|გაცემ/i;
const DENY = /deny|reject|cancel|decline|back|resend|re-send|again|უარ|გაუქმ|ხელახლა|თავიდან/i;

export async function browserLogin(target: TargetConfig, startUrl: string, redirectUri: string, timeoutMs = 90_000): Promise<BrowserLoginResult> {
  const psu = target.credentials?.psu;
  const steps: string[] = [];
  if (!psu) return { steps, error: 'no test PSU configured' };
  // Loaded lazily: the dependency is only needed when the browser login runs.
  const { chromium } = await import('playwright-core');
  const spki = spkiList(target);
  const browser = await chromium.launch({
    executablePath: process.env.CHROMIUM_PATH,
    headless: true,
    args: ['--no-sandbox', '--disable-dev-shm-usage', ...(spki.length ? [`--ignore-certificate-errors-spki-list=${spki.join(',')}`] : [])],
  });
  let redirect: string | undefined;
  let dump: string | undefined;
  const metrics = emptyMetrics();
  const screens = new Set<string>();
  try {
    const context = await browser.newContext({ locale: 'en-US', userAgent: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130 Safari/537.36 Scio-Auditor' });
    // The redirect to the TPP carries the code: capture it and stop there. The request event also sees the
    // target of HTTP redirects (302 from the authorization server), which routing alone may not intercept.
    context.on('request', (req) => {
      if (!redirect && req.url().startsWith(redirectUri)) redirect = req.url();
    });
    await context.route((u) => u.toString().startsWith(redirectUri), async (route) => {
      redirect ??= route.request().url();
      await route.fulfill({ status: 200, contentType: 'text/plain', body: 'ok' });
    });
    const page = await context.newPage();
    page.setDefaultTimeout(10_000);
    // Friction: page loads and hosts on the person's way (the return to the TPP itself is not counted).
    page.on('framenavigated', (f) => {
      if (f !== page.mainFrame() || f.url().startsWith(redirectUri)) return;
      metrics.navigations++;
      try {
        const host = new URL(f.url()).host;
        if (host && !metrics.hosts.includes(host)) metrics.hosts.push(host);
      } catch {
        // about:blank and similar
      }
    });
    const deadline = Date.now() + timeoutMs;
    await page.goto(startUrl, { waitUntil: 'domcontentloaded' }).catch((e) => steps.push(`goto: ${String(e?.message ?? e).split('\n')[0]}`));
    let lastSig = '';
    let same = 0;
    let loggedIn = false;
    while (!redirect && Date.now() < deadline) {
      await page.waitForLoadState('networkidle', { timeout: 8000 }).catch(() => undefined);
      if (!redirect && page.url().startsWith(redirectUri)) redirect = page.url();
      if (redirect) break;
      const inputs = page.locator('input:visible, textarea:visible');
      const n = await inputs.count();
      const fields: { kind: string; idx: number; group?: string }[] = [];
      for (let i = 0; i < n; i++) {
        const el = inputs.nth(i);
        const type = ((await el.getAttribute('type')) ?? 'text').toLowerCase();
        const desc = [await el.getAttribute('name'), await el.getAttribute('id'), await el.getAttribute('placeholder'), await el.getAttribute('aria-label'), await el.getAttribute('autocomplete')].filter(Boolean).join(' ');
        if (['hidden', 'submit', 'button', 'image', 'search'].includes(type)) continue;
        if (type === 'radio') {
          // One choice per group (e.g. account to share): the first, unless one is already selected.
          const name = (await el.getAttribute('name')) ?? `#${i}`;
          if (!fields.some((f) => f.kind === 'radio' && f.group === name)) fields.push({ kind: 'radio', idx: i, group: name });
        } else if (type === 'checkbox') fields.push({ kind: 'checkbox', idx: i });
        else if (type === 'password') fields.push({ kind: loggedIn && OTP.test(desc) ? 'otp' : 'password', idx: i });
        else if (OTP.test(desc) || ((type === 'tel' || type === 'number') && loggedIn)) fields.push({ kind: 'otp', idx: i });
        else if (USER.test(desc) || type === 'email' || type === 'text') fields.push({ kind: loggedIn && !USER.test(desc) ? 'otp' : 'user', idx: i });
      }
      // Second step after the login: a password-type box without a user field is the OTP (e.g. Keycloak OTP form).
      if (loggedIn && !fields.some((f) => f.kind === 'user')) for (const f of fields) if (f.kind === 'password') f.kind = 'otp';
      const sig = `${page.url().split('?')[0]}|${fields.map((f) => f.kind).join(',')}`;
      same = sig === lastSig ? same + 1 : 0;
      lastSig = sig;
      if (same >= 2) {
        steps.push(`stuck on ${page.url().split('?')[0]} (${fields.map((f) => f.kind).join(', ') || 'no fields'})`);
        // What the page offers, so the next fix does not need a page dump.
        const labels = await page.locator('button:visible, input[type=submit]:visible, input[type=button]:visible, [role=button]:visible, a:visible').evaluateAll((els) => els.slice(0, 12).map((e) => ((e as any).innerText || (e as any).value || e.getAttribute('aria-label') || '').trim().slice(0, 40)).filter(Boolean)).catch(() => [] as string[]);
        const text = ((await page.locator('body').innerText().catch(() => '')) ?? '').replace(/\s+/g, ' ').trim().slice(0, 300);
        steps.push(`buttons: [${labels.join(' | ')}]; text: ${text}`);
        dump = await pageDump(page);
        break;
      }
      // OTP split over one box per digit (maxlength 1): one character per box.
      const otpFields = fields.filter((f) => f.kind === 'otp');
      const otp = psu.otp ?? '';
      const perDigit = otpFields.length > 1 && otpFields.length === otp.length;
      for (const f of fields) {
        const el = inputs.nth(f.idx);
        if (perDigit && f.kind === 'otp') {
          await el.fill(otp[otpFields.indexOf(f)]).catch(() => undefined);
        } else if (f.kind === 'checkbox' || f.kind === 'radio') {
          if (!(await el.isChecked().catch(() => true))) await el.check().catch(() => undefined);
        } else {
          const value = f.kind === 'password' ? psu.password : f.kind === 'otp' ? (psu.otp ?? '') : psu.user;
          await el.fill(value).catch(() => undefined);
        }
      }
      if (fields.some((f) => f.kind === 'password')) loggedIn = true;
      steps.push(`${page.url().split('?')[0]}: ${fields.map((f) => f.kind).join(', ') || 'no fields'}`);
      // A screen the person sees once: its fields count once, however often the automation retries it.
      const newScreen = !screens.has(sig);
      if (newScreen) {
        screens.add(sig);
        metrics.screens++;
        metrics.typed.user += fields.filter((f) => f.kind === 'user').length;
        metrics.typed.password += fields.filter((f) => f.kind === 'password').length;
        if (otpFields.length) metrics.typed.otp += perDigit ? 1 : otpFields.length;
        metrics.choices += fields.filter((f) => f.kind === 'checkbox' || f.kind === 'radio').length;
      }
      // Press the approving button; else Enter in the last filled field.
      // Custom (non-input) checkboxes, e.g. account tiles with role=checkbox.
      const roleBoxes = page.locator('[role=checkbox][aria-checked=false]:visible');
      const roleCount = await roleBoxes.count().catch(() => 0);
      for (let i = 0; i < (await roleBoxes.count()); i++) await roleBoxes.nth(i).click({ timeout: 3000 }).catch(() => undefined);
      // Native checkboxes / radios hidden behind styled labels (e.g. account rows on a consent page).
      const ticked = await tickHidden(page);
      if (ticked.length) steps.push(`ticked hidden: ${ticked.join(', ')}`);
      if (newScreen) metrics.choices += roleCount + ticked.length;
      // Page unchanged after one approve click: the account may have to be picked by clicking its row (IBAN).
      if (same === 1) {
        const rows = await clickIbanRows(page);
        if (rows.length) steps.push(`clicked account rows: ${rows.join(', ')}`);
        metrics.choices += rows.length;
      }
      const buttons = page.locator('button:visible, input[type=submit]:visible, input[type=button]:visible, [role=button]:visible, a:visible');
      const count = await buttons.count();
      const meta: { i: number; label: string; submit: boolean; link: boolean }[] = [];
      for (let i = 0; i < count; i++) {
        const b = buttons.nth(i);
        const tag = await b.evaluate((e) => e.tagName.toLowerCase()).catch(() => '');
        const label = `${(await b.innerText().catch(() => '')) ?? ''} ${(await b.getAttribute('value')) ?? ''} ${(await b.getAttribute('name')) ?? ''} ${(await b.getAttribute('id')) ?? ''} ${(await b.getAttribute('aria-label')) ?? ''}`;
        meta.push({ i, label, submit: tag !== 'a' && ((await b.getAttribute('type')) ?? 'submit') === 'submit', link: tag === 'a' });
      }
      // 1. a button that says approve/confirm/...; 2. otherwise the last submit button that does not say deny/cancel.
      const pick = meta.find((m) => APPROVE.test(m.label) && !DENY.test(m.label)) ?? [...meta].reverse().find((m) => m.submit && !m.link && !DENY.test(m.label));
      let clicked = false;
      if (pick) {
        await buttons.nth(pick.i).click({ timeout: 5000 }).catch(() => undefined);
        clicked = true;
        if (newScreen) metrics.clicks++;
      }
      if (!clicked && fields.length) await inputs.nth(fields[fields.length - 1].idx).press('Enter').catch(() => undefined);
      if (!clicked && fields.length && newScreen) metrics.clicks++;
      if (!clicked && !fields.length) await page.waitForTimeout(2000);
      await page.waitForTimeout(1500);
    }
    if (!redirect && Date.now() >= deadline) {
      steps.push('timed out');
      dump = await pageDump(page);
    }
    return scrubResult({ redirect, steps, dump, metrics }, psu);
  } catch (e: any) {
    return scrubResult({ redirect, steps, dump, metrics, error: String(e?.message ?? e).split('\n')[0] }, psu);
  } finally {
    await browser.close().catch(() => undefined);
  }
}

/** Applies scrubSecrets to everything the caller stores (steps, dump, error). The redirect carries the code and is redacted by the caller. */
function scrubResult(r: BrowserLoginResult, psu: { password: string; otp?: string }): BrowserLoginResult {
  const secrets = [psu.password, psu.otp];
  return { ...r, steps: r.steps.map((x) => scrubSecrets(x, secrets)), dump: r.dump && scrubSecrets(r.dump, secrets), error: r.error && scrubSecrets(r.error, secrets) };
}

/**
 * Ticks native checkboxes / radios that are not visible (styled label on top): clicks the label, else sets the
 * state with input + change events. One choice per radio group. Returns the names of the ticked inputs.
 */
async function tickHidden(page: import('playwright-core').Page): Promise<string[]> {
  return page
    .evaluate(() => {
      const doc = (globalThis as any).document;
      const out: string[] = [];
      const groups = new Set<string>();
      for (const el of Array.from(doc.querySelectorAll('input[type=checkbox], input[type=radio]')) as any[]) {
        const r = el.getBoundingClientRect();
        const st = (globalThis as any).getComputedStyle(el);
        const visible = r.width > 1 && r.height > 1 && st.visibility !== 'hidden' && st.opacity !== '0';
        if (visible || el.disabled || el.checked) continue;
        if (el.type === 'radio') {
          if (groups.has(el.name)) continue;
          groups.add(el.name);
          if (Array.from(doc.querySelectorAll('input[type=radio]')).some((x: any) => x.name === el.name && x.checked)) continue;
        }
        const label = (el.id && doc.querySelector(`label[for="${el.id.replace(/"/g, '\\"')}"]`)) || el.closest('label');
        if (label) label.click();
        if (!el.checked) {
          el.checked = true;
          el.dispatchEvent(new (globalThis as any).Event('input', { bubbles: true }));
          el.dispatchEvent(new (globalThis as any).Event('change', { bubbles: true }));
        }
        out.push(el.name || el.id || el.type);
      }
      return out;
    })
    .catch(() => [] as string[]);
}

const IBAN = /\b[A-Z]{2}\d{2}[A-Z0-9]{2}\d{10,30}\b/;

/** Clicks the row (closest clickable container) of every account shown by IBAN. Returns the IBANs clicked. */
async function clickIbanRows(page: import('playwright-core').Page): Promise<string[]> {
  const cells = page.locator(`text=${IBAN.toString()}`);
  const out: string[] = [];
  const n = Math.min(await cells.count().catch(() => 0), 5);
  for (let i = 0; i < n; i++) {
    const cell = cells.nth(i);
    const iban = ((await cell.innerText().catch(() => '')) ?? '').match(IBAN)?.[0] ?? '?';
    const row = cell.locator('xpath=ancestor-or-self::*[self::label or self::li or self::tr or @onclick or @role="option" or @role="checkbox" or contains(@class,"account") or contains(@class,"card")][1]');
    const target = (await row.count().catch(() => 0)) ? row.first() : cell;
    await target.click({ timeout: 3000 }).catch(() => undefined);
    out.push(iban);
  }
  return out;
}

/** Compact page structure for debugging a stuck login (kept far below the page size; no values of password fields, nor of hidden, OTP or user fields, see renderDump). */
async function pageDump(page: import('playwright-core').Page): Promise<string | undefined> {
  return page
    .evaluate((ibanSrc: string): RawDump => {
      const doc = (globalThis as any).document;
      const iban = new RegExp(ibanSrc);
      const raw: RawDump = { url: doc.location.href, forms: [], fields: [], alerts: [], accounts: [], scripts: [] };
      for (const f of Array.from(doc.forms) as any[]) raw.forms.push({ action: f.getAttribute('action') ?? '', method: f.getAttribute('method') ?? '', id: f.id });
      for (const el of Array.from(doc.querySelectorAll('input, select, textarea, button')) as any[]) {
        const r = el.getBoundingClientRect();
        const desc = [el.name, el.id, el.getAttribute('placeholder'), el.getAttribute('aria-label'), el.getAttribute('autocomplete')].filter(Boolean).join(' ');
        raw.fields.push({ tag: el.tagName.toLowerCase(), type: el.type ?? '', name: el.name ?? '', id: el.id ?? '', desc, value: String(el.value ?? '').slice(0, 40), checked: !!el.checked, disabled: !!el.disabled, form: el.form?.id ?? (el.form ? 'yes' : 'no'), box: `${Math.round(r.width)}x${Math.round(r.height)}`, text: (el.innerText ?? '').trim().slice(0, 30) });
      }
      for (const el of Array.from(doc.querySelectorAll('.alert, .error, .validation-summary-errors, .field-validation-error, [role=alert], .text-danger')) as any[]) {
        const t = (el.innerText ?? '').trim();
        if (t) raw.alerts.push(t.slice(0, 200));
      }
      const walker = doc.createTreeWalker(doc.body, 4);
      let node: any;
      let k = 0;
      while ((node = walker.nextNode()) && k < 3) {
        if (!iban.test(node.textContent ?? '')) continue;
        let el = node.parentElement;
        for (let up = 0; up < 3 && el?.parentElement && el.parentElement !== doc.body; up++) el = el.parentElement;
        raw.accounts.push((el?.outerHTML ?? '').replace(/\s+/g, ' ').slice(0, 1500));
        k++;
      }
      raw.scripts = Array.from(doc.scripts).map((s: any) => s.getAttribute('src')).filter(Boolean);
      return raw;
    }, IBAN.source)
    .then(renderDump)
    .catch((e) => `dump failed: ${String(e?.message ?? e).split('\n')[0]}`);
}

export interface RawDump {
  url: string;
  forms: { action: string; method: string; id: string }[];
  fields: { tag: string; type: string; name: string; id: string; desc: string; value: string; checked: boolean; disabled: boolean; form: string; box: string; text: string }[];
  alerts: string[];
  accounts: string[];
  scripts: string[];
}

/** Query strings (Keycloak session_code, execution, tab_id, ...) and fragments are cut; "?***" marks that there was one. */
export const stripQuery = (u: string) => u.replace(/[?#].*$/s, (q) => (q.startsWith('?') ? '?***' : ''));

/** Inputs whose values may be shown: buttons and choices. Hidden, password, OTP, user and other typed values are blanked. */
const SHOWN_TYPES = new Set(['submit', 'button', 'reset', 'checkbox', 'radio', 'select-one', 'select-multiple']);

/**
 * Turns the raw page structure into the stored dump: field names, types and sizes stay (enough to fix the automation),
 * session links and typed or hidden values do not ("***" means the field had a value).
 */
export function renderDump(raw: RawDump): string {
  const lines: string[] = [`url: ${raw.url.split(/[?#]/)[0]}`];
  for (const f of raw.forms) lines.push(`form action=${stripQuery(f.action)} method=${f.method} id=${f.id}`);
  for (const el of raw.fields) {
    const show = SHOWN_TYPES.has(el.type) && !OTP.test(el.desc) && !/password|secret/i.test(el.desc);
    const v = show ? el.value : el.value ? '***' : '';
    lines.push(`${el.tag} type=${el.type} name=${el.name} id=${el.id} value=${v}${el.checked ? ' checked' : ''}${el.disabled ? ' disabled' : ''} form=${el.form} box=${el.box} text=${el.text}`);
  }
  for (const t of raw.alerts) lines.push(`alert: ${t}`);
  for (const h of raw.accounts) lines.push(`account html: ${sanitizeHtml(h)}`);
  if (raw.scripts.length) lines.push(`scripts: ${raw.scripts.map(stripQuery).join(', ')}`);
  return lines.join('\n');
}

/** Account rows as HTML: attribute values that can carry session data or typed input are cut the same way. */
function sanitizeHtml(html: string): string {
  return html
    .replace(/\b(value)\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)/gi, '$1="***"')
    .replace(/\b(action|href|src|formaction)\s*=\s*("([^"]*)"|'([^']*)')/gi, (_m, a, _q, d, s) => `${a}="${stripQuery(d ?? s ?? '')}"`);
}

/** Last line of defence: the test user's password and OTP never leave this module, even if a page echoes them. */
export function scrubSecrets(text: string, secrets: (string | undefined)[]): string {
  let out = text;
  for (const s of secrets) if (s && s.length >= 3) out = out.split(s).join('***');
  return out;
}
