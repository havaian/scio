import { randomBytes } from 'node:crypto';
import { HttpResponse } from '../common/http';
import { AuditContext, REF } from '../checks/context';
import { checkRequestIdEcho, checkResponseSeals, checkSchemaResults, errCode } from '../checks/live-conformance.checks';
import { runDataChecks } from '../checks/data.checks';
import { api, pkcePair } from './full.flow';
import type { JwsOptions } from '../common/credentials';
import { browserEnabled, browserLogin, emptyMetrics, JourneyMetrics } from './browser-login';
import { latencyFinding, stats } from '../checks/performance.checks';
import type { Exchange } from '../common/types';

/**
 * Real bank sandbox journey (Alta Software XS2A: Liberty, Silk, Cartu):
 * consent with mTLS + signed request -> SCA link (scaOAuth / scaRedirect / startAuthorisation)
 * -> bank login page with the portal's demo user -> token -> consent status -> account reads.
 *
 * Paths and request bodies come from the bank's own spec, so nothing here is bank-specific.
 * Steps that depend on our automation (login page) are reported as "skip" with the reason, never as a bank failure.
 */
export async function runSandboxFlow(ctx: AuditContext, certInfo: string, tppId?: string, signerOptions?: JwsOptions) {
  const spec = ctx.spec;
  const idEnv = ctx.target.credentials?.clientIdEnv;
  const clientId = (idEnv && process.env[idEnv]) || ctx.target.clientId || tppId || '';
  const redirectUri = ctx.target.redirectUri ?? 'https://scio.uz/callback';
  // Distinct TPP-Nok-Redirect-URI with the redirectUri prefix, so the login automation still stops there.
  const nokUri = nokRedirectUri(redirectUri);

  // 1. Consent: POST path and request example from the bank's spec, dates moved into the future.
  // Without a published spec (e.g. TBC, documented on a web portal only), the standard path and body are used.
  const consentOp = spec?.operations.find((o) => o.method === 'POST' && /\/consents(\/account-access)?$/.test(o.path));
  if (spec && !consentOp) {
    ctx.add({ checkId: 'flow.sandbox', layer: 'conformance', status: 'skip', severity: 'none', title: 'Sandbox flow', message: 'The spec has no POST .../consents operation.' });
    return;
  }
  const consentPath = consentOp?.path ?? '/v1/consents';
  const body = consentBody(consentOp?.op ?? {});
  // PSU-ID only when configured: banks validate its format (e.g. Liberty wants PASGE-11AB12345678), and redirect SCA does not need it.
  const psuId = ctx.target.credentials?.psu?.psuId ?? '';
  const sendConsent = (json: any = body, extra: Record<string, string> = {}, operation = 'sandbox.consent', auth = false) =>
    api(ctx, operation, 'POST', consentPath, {
      auth,
      consent: false,
      retries: 2,
      json,
      headers: { 'TPP-Redirect-URI': redirectUri, 'TPP-Nok-Redirect-URI': nokUri, 'TPP-Redirect-Preferred': 'true', 'PSU-ID': psuId, ...extra },
    });
  let consent = await sendConsent();
  // Body the bank accepted (the documented example, or its corrected copy); reused for further consents.
  let acceptedBody: any = body;
  const endpoint = `POST ${consentPath}`;
  // Some banks reject a JWS without "typ", which the Georgian profile does not recommend (GE-JWS §6: if used, JOSE).
  // Retry once with typ=JOSE and report the bank's requirement.
  if (consent.status === 401 && signerOptions && !signerOptions.typ && /typ\b/i.test(consent.text)) {
    signerOptions.typ = 'JOSE';
    consent = await sendConsent(body, {}, 'sandbox.consent.diag');
    ctx.add({ checkId: 'sec.jws-typ-required', layer: 'security', status: 'warn', severity: 'low', title: 'JWS profile followed for incoming signatures', endpoint, message: `The bank rejects a request signature without "typ" (${consent.status === 401 ? 'still refused with typ=JOSE' : 'accepted with typ=JOSE'}). The Georgian JWS guide marks "typ" as not recommended, so a TPP following the guide is refused.`, expected: 'Signature accepted with or without "typ" (GE-JWS §6)', actual: '401 SIGNATURE_INVALID: typ is missing', fix: 'Accept protected headers without "typ"; validate it only when present (must be JOSE).', reference: 'Georgian JWS Implementation Guide 0.5.RC1 §6' });
  }
  // Some verifiers look "(request-target)" up as a real HTTP header and fail with 500. GE-JWS §7 requires it in sigD.pars,
  // so this is the bank's defect: report it, then retry without it to reach the rest of the journey.
  if (consent.status === 500 && signerOptions && !signerOptions.omitRequestTarget && /\(request-target\)/i.test(consent.text)) {
    signerOptions.omitRequestTarget = true;
    const retry = await sendConsent(body, {}, 'sandbox.consent.diag');
    ctx.add({ checkId: 'sec.jws-request-target', layer: 'security', status: 'fail', severity: 'medium', title: 'Signature with (request-target) verified', endpoint, message: `The bank answers 500 ("${consent.json?.title ?? 'Required header not found (request-target)'}") to a signature whose sigD.pars includes (request-target), which the Georgian JWS guide requires. ${retry.status < 500 ? `Without it the request got ${ctx.short(retry)}, so the bank only accepts non-compliant signatures.` : `Without it the request still failed (${ctx.short(retry)}).`}`, expected: '(request-target) = "<method> <path>" built from the request line, not read as a header (GE-JWS §7, §9.5)', actual: consent.text.slice(0, 300), fix: 'Build (request-target) from the HTTP method and path when verifying; never look it up as a header.', reference: 'Georgian JWS Implementation Guide 0.5.RC1 §7, §9.5' });
    consent = retry;
  }
  // x5c is sent as GE-JWS §6 requires (signing certificate only). If the bank refuses the signature or certificate,
  // retry once with the issuing chain in x5c; acceptance then is the bank's deviation, reported as such.
  const refusedSeal = (r: typeof consent) => (r.status === 401 || r.status === 403) && (/^(CERTIFICATE|SIGNATURE)_/.test(errCode(r) ?? '') || (r.status === 401 && !errCode(r))) && !/typ\b|\(request-target\)/i.test(r.text);
  if (refusedSeal(consent) && signerOptions?.chainAvailable && !signerOptions.x5cChain) {
    signerOptions.x5cChain = true;
    const retry = await sendConsent(body, {}, 'sandbox.consent.diag');
    if (!refusedSeal(retry)) {
      ctx.add({ checkId: 'sec.jws-x5c-single', layer: 'security', status: 'fail', severity: 'medium', title: 'Signature with x5c = signing certificate accepted', endpoint, message: `The bank refused a request signature whose x5c holds only the signing certificate (${ctx.short(consent)}), as GE-JWS §6 requires, and accepted it with the issuing chain added (${ctx.short(retry)}). A TPP following the guide is refused.`, expected: 'x5c with one entry, the QSealC (GE-JWS §6, §8.1); the bank builds the chain from its trusted CAs', actual: consent.text.slice(0, 300), fix: 'Accept x5c with only the signing certificate and resolve intermediates from the trusted CA list (GE-JWS §8.2, §8.3).', reference: 'Georgian JWS Implementation Guide 0.5.RC1 §6, §8.1' });
      consent = retry;
    } else {
      // The chain made no difference: back to the compliant form, the refusal is handled below.
      signerOptions.x5cChain = false;
    }
  }
  // The bank's own example may break a standard rule (e.g. Liberty: recurringIndicator false with frequencyPerDay 4,
  // BG IG: one-off access means frequencyPerDay 1). Report the example, then continue with the corrected request.
  if (consent.status === 400) {
    const fixed = consistentConsent(body);
    if (fixed) {
      const retry = await sendConsent(fixed, {}, 'sandbox.consent.diag');
      if (retry.status === 201) {
        ctx.add({ checkId: 'spec.consent-example', layer: 'conformance', status: 'fail', severity: 'low', title: 'Documented consent example is valid', endpoint, message: `The bank's own consent example is rejected by the bank (${ctx.short(consent)}: ${consent.json?.detail ?? consent.json?.title ?? ''}). The corrected request was accepted. TPPs copying the documentation fail on the first call.`, expected: 'Example consistent with BG IG (one-off access: frequencyPerDay 1)', actual: JSON.stringify(body).slice(0, 300), fix: 'Correct the example in the published spec.', reference: REF.BG, evidence: { documented: body, accepted: fixed } });
        consent = retry;
        acceptedBody = fixed;
      }
    }
  }
  ctx.state.consentResponse = consent;
  if (consent.status === 0 && /UNABLE_TO_VERIFY|SELF_SIGNED|CERT_|unable to get local issuer/i.test(consent.error ?? '')) {
    ctx.add({ checkId: 'flow.sandbox', layer: 'security', status: 'skip', severity: 'none', title: 'Sandbox consent', endpoint, message: `The sandbox's server certificate could not be verified (${consent.error}). Put the bank's CA certificate in the file named by credentials.ca to trust it for this target only. ${certInfo}` });
    return finish(ctx);
  }
  if (consent.status === 0 || consent.status >= 500) {
    ctx.add({ checkId: 'flow.sandbox', layer: 'reliability', status: 'skip', severity: 'none', title: 'Sandbox consent', endpoint, message: `Sandbox unavailable (${ctx.short(consent)}). ${certInfo}` });
    return finish(ctx);
  }
  const code = errCode(consent) ?? '';
  if (/^(CERTIFICATE|SIGNATURE)_/.test(code) || (consent.status === 401 && !code)) {
    // Our certificate or signature was refused: a setup problem on our side until shown otherwise.
    ctx.add({ checkId: 'flow.sandbox', layer: 'security', status: 'skip', severity: 'none', title: 'Sandbox consent', endpoint, message: `The bank refused the client certificate or signature (${ctx.short(consent)}). ${certInfo}. Check that the certificate from the bank portal is the one in certs/.`, actual: consent.text.slice(0, 300) });
    return finish(ctx);
  }
  if (consent.status !== 201 || !consent.json?.consentId) {
    ctx.add({ checkId: 'flow.consent', layer: 'conformance', status: 'fail', severity: 'high', title: 'Create consent with the documented example', endpoint, message: `The bank rejected its own documented request example (${ctx.short(consent)}).`, expected: '201 Created with consentId', actual: consent.text.slice(0, 300), fix: 'Accept the published example, or correct the example in the spec.', reference: REF.BG, evidence: { request: body } });
    return finish(ctx);
  }
  let consentId: string = consent.json.consentId;
  ctx.state.consentId = consentId;
  ctx.pass({ checkId: 'flow.consent', layer: 'conformance', title: 'Create consent with the documented example', endpoint, message: `Consent ${consentId} created with mTLS${ctx.target.credentials?.sign !== false ? ' and a signed request' : ''}.` });

  // GE-XS2A §5.4: the bank must verify the TPP's seal. One read-only call without Digest / x-jws-signature
  // (consent status of the consent just created) shows whether it does.
  if (ctx.target.credentials?.sign !== false && signerOptions) {
    const st = await api(ctx, 'sandbox.unsigned', 'GET', `${consentPath}/${consentId}/status`, { auth: false, consent: false, unsigned: true, validate: false, retry: false });
    if (st.status > 0 && st.status < 500) {
      const accepted = st.status >= 200 && st.status < 300;
      // A refusal counts only when it names the missing seal; any other refusal says nothing about seal checking.
      const sealRefusal = /^SIGNATURE_/.test(errCode(st) ?? '') || /signature|digest|jws/i.test(st.text);
      if (!accepted && !sealRefusal)
        ctx.add({ checkId: 'sec.message-signing', layer: 'security', status: 'info', severity: 'none', title: 'Unsigned requests are refused', endpoint: `GET ${consentPath}/{consentId}/status`, message: `Refused (${ctx.short(st)}), but not for the missing seal, so seal enforcement could not be observed.` });
      else ctx.add({ checkId: 'sec.message-signing', layer: 'security', status: accepted ? 'fail' : 'pass', severity: accepted ? 'high' : 'none', title: 'Unsigned requests are refused', endpoint: `GET ${consentPath}/{consentId}/status`, message: accepted ? `A request without Digest and x-jws-signature was served (${ctx.short(st)}). The bank does not verify the TPP's seal.` : `Refused without a seal (${ctx.short(st)}).`, expected: '401 SIGNATURE_MISSING (GE-XS2A §5.4, §7.4)', actual: ctx.short(st), fix: accepted ? 'Require and verify the TPP seal (Digest + x-jws-signature, GE-JWS) on every request.' : undefined, reference: 'GE-XS2A §5.4, §7.4; GE-JWS §5' });
    }
  }
  // GE-JWS §5 / GE-XS2A §7.4: a seal whose sigT is more than 60 s old or more than 2 s ahead must not be processed.
  // Two read-only calls (consent status) with a shifted sigT show whether the bank enforces the window (replay protection).
  if (ctx.target.credentials?.sign !== false && signerOptions) {
    const windows: { id: string; offset: number; label: string }[] = [
      { id: 'sec.sigt-stale', offset: -300, label: 'a sigT 5 minutes old' },
      { id: 'sec.sigt-future', offset: 60, label: 'a sigT 1 minute in the future' },
    ];
    for (const w of windows) {
      signerOptions.sigTOffsetSec = w.offset;
      const st = await api(ctx, `sandbox.${w.id}`, 'GET', `${consentPath}/${consentId}/status`, { auth: false, consent: false, validate: false, retry: false });
      signerOptions.sigTOffsetSec = 0;
      if (st.status === 0 || st.status >= 500) continue;
      const accepted = st.status >= 200 && st.status < 300;
      const sealRefusal = /^(SIGNATURE_|TIMESTAMP_)/.test(errCode(st) ?? '') || /signature|sigT|timestamp|time|clock|jws/i.test(st.text);
      ctx.add({ checkId: w.id, layer: 'security', status: accepted ? 'fail' : sealRefusal ? 'pass' : 'info', severity: accepted ? 'medium' : 'none', title: 'Signature time window enforced', endpoint: `GET ${consentPath}/{consentId}/status`, message: accepted ? `A request sealed with ${w.label} was served (${ctx.short(st)}). Captured signed requests can be replayed.` : sealRefusal ? `Refused with ${w.label} (${ctx.short(st)}).` : `Refused (${ctx.short(st)}), but not clearly for the signature time, so the window could not be observed.`, expected: 'refused: sigT must be within -60 s..+2 s of the bank\'s clock (GE-JWS §5, GE-XS2A §7.4)', actual: ctx.short(st), fix: accepted ? 'Compare sigT with the server clock (UTC, NTP) before processing and refuse outside -60 s..+2 s.' : undefined, reference: 'GE-JWS §5; GE-XS2A §7.4' });
    }
  }
  // GE-IAA §6.7: with redirect/OAuth SCA the bank must not ask the TPP to confirm (no "confirmation" link).
  const cl = consent.json._links ?? {};
  if (cl.scaOAuth || cl.scaRedirect)
    ctx.add({ checkId: 'live.no-confirmation-link', layer: 'conformance', status: cl.confirmation ? 'fail' : 'pass', severity: cl.confirmation ? 'low' : 'none', title: 'No confirmation step for redirect SCA', endpoint, message: cl.confirmation ? 'The consent response returns a "confirmation" link together with a redirect/OAuth SCA link.' : 'No "confirmation" link with the redirect/OAuth SCA link.', expected: 'no confirmation link (GE-IAA §6.7)', fix: cl.confirmation ? 'Drop the confirmation link for redirect SCA; the token exchange completes the authorisation.' : undefined, reference: 'GE-IAA §6.7' });

  // 2. SCA: follow whichever link the bank returned.
  let links = consent.json._links ?? {};
  // No SCA link at all: start the authorisation explicitly at the documented path (BG IG: POST .../consents/{consentId}/authorisations).
  let startPath = links.startAuthorisation ? href(ctx, links.startAuthorisation) : undefined;
  if (!links.scaOAuth && !links.scaRedirect && !startPath) {
    const op = spec?.operations.find((o) => o.method === 'POST' && /\/consents\/\{[^}]+\}\/authorisations$/.test(o.path));
    if (op) {
      startPath = ctx.url(op.path.replace(/\{[^}]+\}/, encodeURIComponent(consentId)));
      ctx.add({ checkId: 'live.consent-links', layer: 'conformance', status: 'fail', severity: 'medium', title: 'Consent response links the next step', endpoint, message: 'The consent response carries no scaOAuth, scaRedirect or startAuthorisation link, so a TPP has to guess how to authorise it.', expected: '_links with scaOAuth / scaRedirect / startAuthorisation (BG IG §6.3.1.1)', actual: JSON.stringify(consent.json?._links ?? {}).slice(0, 300), fix: 'Return the hyperlink for the SCA step in _links.', reference: REF.BG });
    }
  }
  if (!links.scaOAuth && !links.scaRedirect && startPath) {
    let start = await api(ctx, 'sandbox.authorisation', 'POST', startPath, { absolute: true, auth: false, consentId, json: {}, headers: { 'TPP-Redirect-URI': redirectUri, 'TPP-Nok-Redirect-URI': nokUri, 'PSU-ID': psuId } });
    // Some implementations (Alta v2) say the redirect URI is "not provided" although the header is sent:
    // try the other request forms one by one, and report which one (if any) the bank accepted.
    if (start.status === 400 && /redirect/i.test(start.text)) {
      const endpoint = `POST ${new URL(startPath).pathname.replace(consentId, '{consentId}')}`;
      const first = start;
      const full = { 'TPP-Redirect-URI': redirectUri, 'TPP-Nok-Redirect-URI': nokUri, 'TPP-Redirect-Preferred': 'true', 'PSU-ID': psuId };
      const variants: { label: string; json?: unknown; headers: Record<string, string> }[] = [
        { label: 'no body, with TPP-Nok-Redirect-URI and TPP-Redirect-Preferred', json: undefined, headers: full },
        { label: 'body null (the spec example), with TPP-Nok-Redirect-URI and TPP-Redirect-Preferred', json: null, headers: full },
        { label: 'lower-case header names', json: undefined, headers: Object.fromEntries(Object.entries(full).map(([k, v]) => [k.toLowerCase(), v])) },
        { label: 'URIs in the body', json: { tppRedirectUri: redirectUri, tppNokRedirectUri: nokUri }, headers: full },
      ];
      const tried: string[] = [];
      let worked: string | undefined;
      for (const v of variants) {
        const r = await api(ctx, 'sandbox.authorisation.diag', 'POST', startPath, { absolute: true, auth: false, consentId, json: v.json, headers: v.headers });
        tried.push(`${v.label}: ${ctx.short(r)}`);
        if (r.status < 300) {
          start = r;
          worked = v.label;
          break;
        }
      }
      // Last form: a new consent that also carries TPP-Nok-Redirect-URI and TPP-Explicit-Authorisation-Preferred,
      // then the authorisation without a body (the redirect URI may only be stored at consent creation).
      if (!worked) {
        const extra = { 'TPP-Nok-Redirect-URI': nokUri, 'TPP-Explicit-Authorisation-Preferred': 'true' };
        const c2 = await sendConsent(acceptedBody, extra, 'sandbox.consent.diag');
        const id2: string | undefined = c2.json?.consentId;
        const path2 = c2.json?._links?.startAuthorisation ? href(ctx, c2.json._links.startAuthorisation) : id2 ? startPath.replace(consentId, encodeURIComponent(id2)) : undefined;
        if (id2 && path2) {
          const r = await api(ctx, 'sandbox.authorisation.diag', 'POST', path2, { absolute: true, auth: false, consentId: id2, json: undefined, headers: full });
          tried.push(`new consent with TPP-Nok-Redirect-URI + TPP-Explicit-Authorisation-Preferred, authorisation without body: ${ctx.short(r)}`);
          if (r.status < 300) {
            start = r;
            worked = 'new consent with TPP-Nok-Redirect-URI + TPP-Explicit-Authorisation-Preferred, authorisation without body';
            consentId = id2;
            ctx.state.consentId = id2;
          }
        } else tried.push(`new consent with extra headers: ${ctx.short(c2)}`);
      }
      // A failure only when another form with the same URI was accepted; otherwise the bank may refuse the URI itself
      // (e.g. not registered for our client), which is reported with the bank's text.
      ctx.add({ checkId: 'live.redirect-uri-header', layer: 'conformance', status: worked ? 'fail' : 'info', severity: worked ? 'medium' : 'none', title: 'TPP-Redirect-URI header honoured', endpoint, message: `The bank answered ${ctx.short(first)} ("${first.json?.title ?? first.text.slice(0, 80)}") although TPP-Redirect-URI was sent on the consent and on the authorisation. ${worked ? `Accepted with: ${worked}.` : 'No other request form with the same URI was accepted either, so the header handling could not be judged.'}`, expected: 'Redirect SCA started with TPP-Redirect-URI (BG IG §5.3.1, §6.3.1)', actual: first.text.slice(0, 300), evidence: { tried }, reference: REF.BG });
    }
    links = start.json?._links ?? {};
  }
  let token: string | undefined;
  // Scope the authorization server accepted (reused for a second consent), and the consent id it was built with.
  let loginScope: string | undefined;
  let loginConsentId = consentId;
  if (links.scaOAuth) {
    const meta = await api(ctx, 'sandbox.oauth-metadata', 'GET', href(ctx, links.scaOAuth), { absolute: true, auth: false, consent: false, validate: false });
    const authEp = meta.json?.authorization_endpoint;
    const tokenEp = meta.json?.token_endpoint;
    if (!authEp || !tokenEp) {
      ctx.add({ checkId: 'flow.authorize', layer: 'conformance', status: 'fail', severity: 'high', title: 'OAuth server metadata', endpoint: 'GET _links.scaOAuth', message: `The scaOAuth link did not return authorization_endpoint and token_endpoint (${ctx.short(meta)}).`, expected: 'RFC 8414 metadata', reference: REF.OAUTH });
      return finish(ctx);
    }
    const { verifier, challenge } = pkcePair();
    // BG IG §13: scope "AIS:<consentId>". If the server rejects it, try the spellings banks use and report the deviation.
    const scopes = [`AIS:${consentId}`, `openid AIS:${consentId}`, `AIS:${consentId} openid`, 'openid AIS', 'AIS', 'openid'];
    let back: string | undefined;
    let used = scopes[0];
    const refused: string[] = [];
    for (const scope of scopes) {
      const q = new URLSearchParams({ response_type: 'code', client_id: clientId, scope, redirect_uri: redirectUri, state: randomBytes(8).toString('hex'), code_challenge: challenge, code_challenge_method: 'S256' });
      back = await login(ctx, `${authEp}${authEp.includes('?') ? '&' : '?'}${q}`, redirectUri);
      used = scope;
      const err = back ? new URL(back).searchParams.get('error') : null;
      if (err !== 'invalid_scope') break;
      refused.push(scope);
      back = undefined;
    }
    const accepted = refused.length < scopes.length ? used : undefined;
    loginScope = accepted;
    loginConsentId = consentId;
    // Accepted with the consent id in it: only an extra "openid" is required (low). Without it nothing binds the token to the consent.
    const bound = !!accepted?.includes(consentId);
    if (refused.length)
      ctx.add({ checkId: 'flow.oauth-scope', layer: 'conformance', status: bound ? 'warn' : 'fail', severity: bound ? 'low' : 'medium', title: 'Standard OAuth scope accepted', endpoint: 'GET authorization_endpoint', message: `The authorization server rejects the standard scope "AIS:<consentId>" with invalid_scope.${accepted ? ` It accepted "${accepted.replace(consentId, '<consentId>')}" instead, which ${bound ? 'requires an extra openid scope' : 'does not bind the token to the consent'}.` : ' No common alternative was accepted either.'}`, expected: 'scope=AIS:<consentId> (BG IG §13, GE-IAA §6.7)', actual: `invalid_scope for: ${refused.map((s) => s.replace(consentId, '<consentId>')).join(' | ')}`, fix: 'Accept AIS:<consentId> (and PIS:<paymentId>) as scopes, bound to the consent created before.', reference: REF.BG });
    const backErr = back ? new URL(back).searchParams.get('error') : null;
    if (backErr) {
      ctx.add({ checkId: 'flow.authorize', layer: 'conformance', status: 'fail', severity: 'high', title: 'OAuth authorization', endpoint: 'GET authorization_endpoint', message: `The authorization server redirected back with error=${backErr} (${new URL(back!).searchParams.get('error_description') ?? ''}).`, reference: REF.OAUTH });
      return finish(ctx);
    }
    const authCode = back ? new URL(back).searchParams.get('code') : null;
    if (!authCode) return loginSkipped(ctx);
    // client_secret_basic when the bank issues a client secret (e.g. Credo); otherwise mTLS client auth.
    const secret = ctx.target.credentials?.clientSecretEnv ? process.env[ctx.target.credentials.clientSecretEnv] : undefined;
    const t = await ctx.http.request({ operation: 'sandbox.token', method: 'POST', url: tokenEp, headers: secret ? { Authorization: `Basic ${Buffer.from(`${clientId}:${secret}`).toString('base64')}` } : undefined, form: { grant_type: 'authorization_code', code: authCode, redirect_uri: redirectUri, code_verifier: verifier, client_id: clientId } });
    token = t.json?.access_token;
    if (!token) {
      ctx.add({ checkId: 'flow.token', layer: 'conformance', status: 'fail', severity: 'high', title: 'Token exchange', message: `Token request failed (${ctx.short(t)}).`, actual: t.text.slice(0, 300), reference: REF.OAUTH });
      return finish(ctx);
    }
    ctx.state.token = t.json;
  } else if (links.scaRedirect) {
    const back = await login(ctx, href(ctx, links.scaRedirect), redirectUri);
    if (!back) return loginSkipped(ctx);
    // Back on the TPP-Nok-Redirect-URI, or with an error: the login with the demo user failed (our automation), not the bank.
    if (failedLanding(back, nokUri)) {
      ctx.state.loginSkipReason = `The bank login did not succeed with the demo user: the bank returned to ${back.startsWith(nokUri) ? 'the TPP-Nok-Redirect-URI' : 'the redirect URI with an error'} (${back.replace(/([?&]code=)[^&]+/, '$1***').slice(0, 200)}).`;
      return loginSkipped(ctx);
    }
  } else {
    ctx.add({ checkId: 'flow.authorize', layer: 'conformance', status: 'fail', severity: 'high', title: 'SCA link returned', message: 'Neither the consent nor the authorisation response carried scaOAuth or scaRedirect, so the PSU cannot authorise.', expected: '_links.scaOAuth or _links.scaRedirect (BG IG §6.3.1)', actual: `_links: ${JSON.stringify(links)}`, reference: REF.BG });
    return finish(ctx);
  }
  ctx.pass({ checkId: 'flow.authorize', layer: 'conformance', title: 'Consent authorised (redirect SCA)', message: `Logged in as the portal's demo user and returned to the redirect URI${token ? ' with a code exchanged for a token' : ''}.` });

  // 3. Consent status, then account reads. Account paths sit next to the consent path in the spec.
  const status = await api(ctx, 'sandbox.consent-status', 'GET', `${consentPath}/${consentId}/status`, { auth: !!token });
  const valid = status.json?.consentStatus === 'valid';
  // Whether the consent used for the account reads is valid (the original one, or the pre-step one below).
  let consentValid = valid;
  ctx.add({ checkId: 'flow.consent-valid', layer: 'conformance', status: valid ? 'pass' : 'fail', severity: valid ? 'none' : 'high', title: 'Consent valid after SCA', message: valid ? 'consentStatus is "valid".' : `consentStatus is "${status.json?.consentStatus ?? ctx.short(status)}" after a completed SCA.`, expected: 'valid', reference: REF.BG });

  // Token issued but the consent stays unauthorised (e.g. BoG: only "openid" accepted, nothing binds the login to the consent).
  // BG IG also allows OAuth2 as a pre-step: a consent created with the PSU's token. Try it and report the outcome.
  if (!valid && token) {
    const pre = await sendConsent(acceptedBody, {}, 'sandbox.consent-prestep', true);
    const id2: string | undefined = pre.json?.consentId;
    const st2 = id2 ? await api(ctx, 'sandbox.consent-status', 'GET', `${consentPath}/${id2}/status`, { auth: true, consentId: id2 }) : undefined;
    const ok2 = st2?.json?.consentStatus === 'valid';
    if (ok2) {
      consentValid = true;
      consentId = id2!;
      ctx.state.consentId = id2;
    }
    ctx.add({ checkId: 'flow.oauth-prestep', layer: 'conformance', status: ok2 ? 'warn' : 'fail', severity: ok2 ? 'low' : 'medium', title: 'Consent bound by OAuth pre-step', endpoint: `POST ${consentPath}`, message: ok2 ? `A consent created with the PSU's access token (OAuth2 pre-step) is "valid" at once. The redirect flow from the scaOAuth link does not bind the login to the consent, so a TPP following _links never gets a usable consent.` : `A consent created with the PSU's access token (OAuth2 pre-step) did not become valid either (${pre.status === 201 ? `consentStatus "${st2?.json?.consentStatus ?? (st2 ? ctx.short(st2) : '?')}"` : ctx.short(pre)}).`, expected: 'Consent valid after the SCA the consent response links to (BG IG §6.3, §13)', actual: pre.text.slice(0, 300), fix: 'Bind the authorisation to the consent (scope AIS:<consentId>) or document the pre-step flow.', reference: REF.BG });
  }

  const accountsPath = ctx.target.accountsPath ?? '/v1/accounts';
  const accounts = await api(ctx, 'ais.accounts', 'GET', accountsPath, { auth: !!token });
  ctx.state.accounts = accounts;
  const list: any[] = accounts.json?.accounts ?? [];
  const from = new Date(Date.now() - 90 * 86400_000).toISOString().slice(0, 10);
  ctx.state.txWindow = { from, to: new Date().toISOString().slice(0, 10) };
  ctx.state.accountReads = [];
  for (const a of list.slice(0, 2)) {
    const id = encodeURIComponent(a.resourceId);
    const details = await api(ctx, 'ais.account', 'GET', `${accountsPath}/${id}`, { auth: !!token });
    const balances = await api(ctx, 'ais.balances', 'GET', `${accountsPath}/${id}/balances`, { auth: !!token });
    const tx = await api(ctx, 'ais.transactions', 'GET', `${accountsPath}/${id}/transactions?bookingStatus=booked&dateFrom=${from}`, { auth: !!token });
    ctx.state.accountReads.push({ id: a.resourceId, details, balances, tx });
  }
  const ok = accounts.status === 200 && list.length > 0;

  // The bank's own example asks for the account list only (BG: access.availableAccounts), so balances and transactions
  // are refused, as the standard says. To check them too, a second consent names the accounts found
  // (access.accounts / balances / transactions with their IBANs) and goes through the same SCA once more.
  const listOnlyExample = !!acceptedBody?.access?.availableAccounts && !acceptedBody?.access?.balances && !acceptedBody?.access?.transactions;
  const firstReads = ctx.state.accountReads as { id: string; details: HttpResponse; balances: HttpResponse; tx: HttpResponse }[];
  const deniedFirst = firstReads.some((x) => x.balances.status !== 200 || x.tx.status !== 200);
  let detailed: { status: 'pass' | 'fail' | 'skip'; text: string } | undefined;
  if (ok && listOnlyExample && deniedFirst && token && loginScope) {
    const refs = list.slice(0, 2).filter((a) => a.iban).map((a) => (a.currency ? { iban: a.iban, currency: a.currency } : { iban: a.iban }));
    const body2 = { ...structuredClone(acceptedBody), access: { accounts: refs, balances: refs, transactions: refs }, recurringIndicator: true, frequencyPerDay: 4 };
    const c2 = await sendConsent(body2, {}, 'sandbox.consent-detailed');
    const id2: string | undefined = c2.json?.consentId;
    let links2 = c2.json?._links ?? {};
    if (id2 && !links2.scaOAuth && links2.startAuthorisation) {
      const st = await api(ctx, 'sandbox.authorisation', 'POST', href(ctx, links2.startAuthorisation), { absolute: true, auth: false, consentId: id2, json: {}, headers: { 'TPP-Redirect-URI': redirectUri, 'TPP-Nok-Redirect-URI': nokUri, 'PSU-ID': psuId } });
      links2 = st.json?._links ?? {};
    }
    if (!id2 || !refs.length) detailed = { status: 'skip', text: `second consent not created (${ctx.short(c2)})` };
    else if (!links2.scaOAuth) detailed = { status: 'skip', text: 'second consent returned no scaOAuth link' };
    else {
      const meta2 = await api(ctx, 'sandbox.oauth-metadata', 'GET', href(ctx, links2.scaOAuth), { absolute: true, auth: false, consent: false, validate: false });
      const { verifier: v2, challenge: ch2 } = pkcePair();
      const q2 = new URLSearchParams({ response_type: 'code', client_id: clientId, scope: loginScope.split(loginConsentId).join(id2), redirect_uri: redirectUri, state: randomBytes(8).toString('hex'), code_challenge: ch2, code_challenge_method: 'S256' });
      const ep = meta2.json?.authorization_endpoint;
      const back2 = ep ? await login(ctx, `${ep}${ep.includes('?') ? '&' : '?'}${q2}`, redirectUri) : undefined;
      const code2 = back2 ? new URL(back2).searchParams.get('code') : null;
      const secret2 = ctx.target.credentials?.clientSecretEnv ? process.env[ctx.target.credentials.clientSecretEnv] : undefined;
      const t2 = code2 && meta2.json?.token_endpoint ? await ctx.http.request({ operation: 'sandbox.token', method: 'POST', url: meta2.json.token_endpoint, headers: secret2 ? { Authorization: `Basic ${Buffer.from(`${clientId}:${secret2}`).toString('base64')}` } : undefined, form: { grant_type: 'authorization_code', code: code2, redirect_uri: redirectUri, code_verifier: v2, client_id: clientId } }) : undefined;
      const token2: string | undefined = t2?.json?.access_token;
      if (!token2) detailed = { status: 'skip', text: code2 ? `token for the second consent refused (${t2 ? ctx.short(t2) : 'no token endpoint'})` : 'second bank login did not complete' };
      else {
        // Resource ids can be per consent (BG IG: resourceId identifies the account within the consent), so the
        // account list is read again with the new consent and accounts are matched by IBAN.
        const acc2 = await api(ctx, 'ais.accounts', 'GET', accountsPath, { auth: true, token: token2, consentId: id2 });
        const list2: any[] = acc2.json?.accounts ?? [];
        const reads2 = [];
        for (const r1 of firstReads) {
          const iban = list.find((a) => a.resourceId === r1.id)?.iban;
          const id = encodeURIComponent(list2.find((a) => iban && a.iban === iban)?.resourceId ?? r1.id);
          const balances = await api(ctx, 'ais.balances', 'GET', `${accountsPath}/${id}/balances`, { auth: true, token: token2, consentId: id2 });
          const tx = await api(ctx, 'ais.transactions', 'GET', `${accountsPath}/${id}/transactions?bookingStatus=booked&dateFrom=${from}`, { auth: true, token: token2, consentId: id2 });
          reads2.push({ ...r1, balances, tx });
        }
        ctx.state.accountReads = reads2;
        const good = reads2.filter((x) => x.balances.status === 200 && x.tx.status === 200).length;
        detailed = { status: good === reads2.length ? 'pass' : 'fail', text: `second consent for ${refs.length} named account(s): balances and transactions read for ${good}/${reads2.length}` };
      }
    }
    ctx.add({ checkId: 'flow.detailed-consent', layer: 'conformance', status: detailed.status, severity: detailed.status === 'fail' ? 'high' : 'none', title: 'Balances and transactions with a detailed consent', endpoint: `POST ${consentPath}`, message: `The bank's own consent example covers the account list only, so Scio asked for a second consent naming the accounts (access.accounts / balances / transactions): ${detailed.text}.`, expected: 'Balances and transactions readable with a consent that grants them (BG IG §6.3.1.1)', reference: REF.BG });
  }

  // What the per-account reads actually returned. A consent for the account list only (BG: access.availableAccounts,
  // as in some banks' own examples) does not cover balances or transactions, so 401/403 there is expected, not a bank failure.
  const reads = (ctx.state.accountReads as { details: HttpResponse; balances: HttpResponse; tx: HttpResponse }[]) ?? [];
  const okCount = (k: 'details' | 'balances' | 'tx') => reads.filter((x) => x[k].status === 200).length;
  const listOnly = listOnlyExample && detailed?.status !== 'pass' && detailed?.status !== 'fail';
  const refused = reads.length && (okCount('balances') < reads.length || okCount('tx') < reads.length);
  const readText = reads.length
    ? `${detailed?.status === 'pass' || detailed?.status === 'fail' ? ' Balances and transactions via a second, detailed consent.' : ''} Per account (${reads.length}): details ${okCount('details')}/${reads.length}, balances ${okCount('balances')}/${reads.length}, transactions ${okCount('tx')}/${reads.length}.${refused ? (listOnly ? ' Balances and transactions were refused because the consent (the bank\'s own example, access.availableAccounts) covers the account list only.' : ' Some reads were refused although the consent covers them.') : ''}`
    : '';
  ctx.add({ checkId: 'flow.sandbox', layer: 'conformance', status: ok ? (refused && !listOnly ? 'warn' : 'pass') : 'fail', severity: ok ? (refused && !listOnly ? 'medium' : 'none') : 'high', title: 'Sandbox AIS journey', endpoint: `GET ${accountsPath}`, message: ok ? `Read ${list.length} account(s).${readText}` : `Account list failed ${consentValid ? 'after a valid consent' : 'because no consent became valid'} (${ctx.short(accounts)}).`, reference: REF.BG });
  if (ok) runDataChecks(ctx);
  finish(ctx);
}

/** Shared live checks on whatever the flow reached. */
function finish(ctx: AuditContext) {
  consentJourney(ctx);
  checkSchemaResults(ctx);
  checkRequestIdEcho(ctx);
  checkResponseSeals(ctx);
  journeyStats(ctx);
}

/**
 * Layers 2 and 3 for bank sandboxes, from the journey's own calls (no extra traffic: the banks were promised
 * one consent and a few reads per audit). About 10-20 samples, so latency is judged on the median.
 * Diagnostic calls are left out: the altered repeats Scio sends to get past or probe a bank deviation
 * (typ, (request-target), x5c, consent example, redirect URI variants), tagged with a ".diag" operation.
 * Those deviations are reported as their own findings. The standard requests, with their retried 5xx/timeouts, stay in.
 */
export function journeyStats(ctx: AuditContext) {
  const xs = ctx.http.exchanges.filter((x) => /^(sandbox|ais)\./.test(x.operation));
  if (!xs.length) return;
  const diag = new Set<Exchange>(xs.filter((x) => x.operation.endsWith('.diag')));
  const used = xs.filter((x) => !diag.has(x));
  // No HTTP answer at all (e.g. connect timeouts from an address the bank has not allowlisted): nothing to time,
  // and not judged as an outage, since the cause may be on the network path. The flow finding already says so.
  if (!used.some((x) => x.status > 0)) return;
  const groups: [string, RegExp][] = [
    ['consent', /^sandbox\.consent(-prestep|-detailed)?$/],
    ['consent status', /^sandbox\.consent-status$/],
    ['authorisation', /^sandbox\.(authorisation|oauth-metadata)$/],
    ['token', /^sandbox\.token$/],
    ['accounts', /^ais\.accounts$/],
    ['account details', /^ais\.account$/],
    ['balances', /^ais\.balances$/],
    ['transactions', /^ais\.transactions$/],
  ];
  const perOp = groups.map(([name, re]) => stats(name, used.filter((x) => re.test(x.operation)))).filter((g) => g.samples);
  const all = stats('sandbox journey (all calls)', used);
  ctx.state.endpointStats = [...(ctx.state.endpointStats ?? []), all, ...perOp];

  // Too few answered calls (the journey stopped early) to say anything about reliability or latency: reported, not scored.
  const MIN_CALLS = 5;
  if (used.length < MIN_CALLS) {
    for (const [checkId, layer, title] of [['rel.availability', 'reliability', 'Availability and error rate'], ['lat.p95', 'latency', 'Response time']] as const)
      ctx.add({ checkId, layer, status: 'info', severity: 'none', title, endpoint: all.operation, message: `Only ${used.length} call(s) of the sandbox journey were answered before it stopped (p50 ${all.p50} ms); at least ${MIN_CALLS} are needed to judge ${layer}, so this layer is not scored.`, evidence: all });
    return;
  }

  const t = ctx.thresholds;
  const assumed = t.source === 'assumed' ? ' (assumed threshold until NBG indicators are confirmed)' : '';
  const excluded = diag.size ? ` ${diag.size} diagnostic call(s) left out (altered repeats of requests Scio sent to get past or probe a reported bank deviation).` : '';
  const availOk = all.availabilityPct >= t.availabilityPct && all.errorRatePct <= t.errorRatePct;
  ctx.add({
    checkId: 'rel.availability',
    layer: 'reliability',
    status: availOk ? 'pass' : 'fail',
    severity: availOk ? 'none' : all.availabilityPct < 95 ? 'high' : 'medium',
    title: 'Availability and error rate',
    endpoint: all.operation,
    message: `${all.availabilityPct}% available, ${all.errorRatePct}% errors over the ${all.samples} calls of the sandbox journey. Status mix: ${Object.entries(all.statuses).map(([k, v]) => `${k}×${v}`).join(', ')}.${excluded}`,
    expected: `>= ${t.availabilityPct}% available, <= ${t.errorRatePct}% errors${assumed}`,
    actual: `${all.availabilityPct}% / ${all.errorRatePct}%`,
    fix: availOk ? undefined : 'Investigate the 5xx answers and timeouts in the sandbox; TPPs cannot complete the journey through them.',
    reference: REF.GE,
    evidence: { ...all, diagnosticCallsExcluded: diag.size },
  });
  latencyFinding(ctx, all, assumed, 'low');
}

/** TPP-side API steps of the consent journey (retries of the same step count once; .diag probes are Scio's, not the TPP's). */
const TPP_STEPS: [string, string][] = [
  ['sandbox.consent', 'create consent'],
  ['sandbox.authorisation', 'start authorisation'],
  ['sandbox.oauth-metadata', 'read OAuth metadata'],
  ['sandbox.token', 'exchange code for token'],
  ['sandbox.consent-prestep', 'second consent with the PSU token (OAuth pre-step)'],
  ['sandbox.consent-detailed', 'second consent naming the accounts'],
];

type Journey = JourneyMetrics & { via: 'browser' | 'form'; completed: boolean; rejected?: boolean };

/** OAuth error on the return to the TPP (error=... in the redirect query). */
const authError = (back?: string) => !!back && /[?&]error=/.test(back);

/**
 * The first login is the consent journey a TPP's user goes through. Later logins (a second consent Scio needs to get
 * past a bank deviation, e.g. a documented example that covers the account list only) are kept apart, so they never
 * replace the first one's figures.
 */
function recordJourney(ctx: AuditContext, j: Journey) {
  // An authorization request refused before any screen (e.g. invalid_scope, then retried with another scope) is not a
  // journey a person goes through: counted apart, so it never stands in for the real login.
  if (j.rejected) {
    ctx.state.rejectedAuth = (ctx.state.rejectedAuth ?? 0) + 1;
    return;
  }
  if (!ctx.state.consentJourney) ctx.state.consentJourney = j;
  else (ctx.state.extraLogins ??= []).push(j);
}

/**
 * Consent journey analysis (track brief: "count the steps and friction a user faces when authorizing access at each
 * bank"). Info only, never scored: friction is a comparison between banks, not a clause of the standard.
 */
export function consentJourney(ctx: AuditContext) {
  const j = ctx.state.consentJourney as Journey | undefined;
  if (!j) return;
  const extra = (ctx.state.extraLogins ?? []) as Journey[];
  const ops = new Set(ctx.http.exchanges.map((x) => x.operation));
  const tppSteps = TPP_STEPS.filter(([op]) => ops.has(op)).map(([, label]) => label);
  const typed = j.typed.user + j.typed.password + j.typed.otp;
  const rejected = (ctx.state.rejectedAuth ?? 0) as number;
  const evidence = { ...j, tppSteps: tppSteps.length, tppStepNames: tppSteps, typedTotal: typed, extraLogins: extra.length, extraLoginsCompleted: extra.filter((x) => x.completed).length, rejectedAuthRequests: rejected };
  const extraText =
    (extra.length ? ` Scio ran ${extra.length} further login(s) to work around bank deviations (another OAuth scope or a second consent; ${extra.filter((x) => x.completed).length} completed); not counted above.` : '') +
    (rejected ? ` ${rejected} authorization request(s) were refused before any login screen (e.g. invalid_scope).` : '');
  const person = `${j.screens} screen(s), ${typed} value(s) typed (user ${j.typed.user}, password ${j.typed.password}, OTP ${j.typed.otp}), ${j.choices} account/option choice(s), ${j.clicks} button press(es), ${j.navigations} page load(s) across ${j.hosts.length} host(s)${j.hosts.length ? ` (${j.hosts.join(', ')})` : ''}`;
  ctx.add({
    checkId: 'ux.consent-journey',
    layer: 'conformance',
    status: 'info',
    severity: 'none',
    title: 'Consent journey friction',
    endpoint: 'SCA (redirect)',
    message: `${j.completed ? 'Completed' : 'Stopped before the return to the TPP'}: the person faced ${person}. The TPP needed ${tppSteps.length} API step(s) before reading data: ${tppSteps.join(' -> ') || 'none recorded'}.${extraText}${j.via === 'form' ? ' Counted by the plain form filler (no JavaScript), so screens may be under-counted.' : ''}`,
    reference: REF.BG,
    evidence,
  });
}

function loginSkipped(ctx: AuditContext) {
  if (ctx.state.loginSkipReason) {
    ctx.add({ checkId: 'flow.authorize', layer: 'conformance', status: 'skip', severity: 'none', title: 'Bank login (SCA)', message: ctx.state.loginSkipReason });
    return finish(ctx);
  }
  ctx.add({ checkId: 'flow.authorize', layer: 'conformance', status: 'skip', severity: 'none', title: 'Bank login (SCA)', message: 'The login page could not be completed automatically with the demo user. Open the calls for this finding to see the pages; the form may need a field this automation does not know.' });
  finish(ctx);
}

/** TPP-Nok-Redirect-URI: the redirect URI with result=nok, so it shares the prefix the login automation stops at. */
export function nokRedirectUri(redirectUri: string): string {
  return `${redirectUri}${redirectUri.includes('?') ? '&' : '?'}result=nok`;
}

/** True when the PSU came back on the Nok URI or with an error parameter (failed login, no consent authorised). */
export function failedLanding(back: string, nokUri: string): boolean {
  if (back.startsWith(nokUri)) return true;
  try {
    const q = new URL(back).searchParams;
    return q.get('result') === 'nok' || q.has('error');
  } catch {
    return false;
  }
}

/** Absolute URL for a _links entry ({href} or string; relative hrefs are relative to the bank host). */
function href(ctx: AuditContext, link: any): string {
  const h: string = typeof link === 'string' ? link : link?.href ?? '';
  return new URL(h, ctx.target.baseUrl.replace(/\/?$/, '/')).toString();
}

/** A copy of the consent body made consistent with BG IG rules, or undefined when nothing needed fixing. */
export function consistentConsent(body: any): any | undefined {
  if (!body || typeof body !== 'object') return undefined;
  const out = structuredClone(body);
  let changed = false;
  // BG IG: "For a one-off access, this attribute is set to 1."
  if (out.recurringIndicator === false && out.frequencyPerDay !== undefined && out.frequencyPerDay !== 1) {
    out.frequencyPerDay = 1;
    changed = true;
  }
  return changed ? out : undefined;
}

/** First request example from the spec, with validity dates moved 89 days ahead. */
export function consentBody(op: any): any {
  const content = op.requestBody?.content ?? {};
  const media: any = content['application/json'] ?? Object.values(content)[0] ?? {};
  const ex = media.example ?? (Object.values(media.examples ?? {})[0] as any)?.value;
  // Standard body (BG IG; TBC marks all five fields required).
  const body = structuredClone(ex ?? { access: { availableAccounts: 'allAccounts' }, recurringIndicator: false, frequencyPerDay: 4, combinedServiceIndicator: false });
  const until = new Date(Date.now() + 89 * 86400_000).toISOString().slice(0, 10);
  for (const k of ['validUntil', 'validTo']) if (k in body) body[k] = until;
  if (!('validUntil' in body) && !('validTo' in body)) body.validUntil = until;
  return body;
}

/**
 * Walks the bank's login pages: follows redirects, fills forms (user, password, OTP, approve) with the
 * portal's demo user, keeps session cookies. Returns the final redirect to redirectUri, if reached.
 */
async function login(ctx: AuditContext, startUrl: string, redirectUri: string): Promise<string | undefined> {
  const psu = ctx.target.credentials?.psu;
  if (!psu) {
    ctx.state.loginSkipReason = 'No test PSU (bank login) is configured for this target; the bank has to provide one.';
    return undefined;
  }
  // Headless browser when available (JavaScript login apps, multi-step forms); the plain form filler otherwise.
  if (browserEnabled()) {
    const started = performance.now();
    const r = await browserLogin(ctx.target, startUrl, redirectUri);
    if (r.metrics) recordJourney(ctx, { via: 'browser', completed: !!r.redirect && !authError(r.redirect), rejected: authError(r.redirect) && r.metrics.screens === 0, ...r.metrics });
    ctx.http.exchanges.push({ targetId: ctx.target.id, operation: 'sca.browser', method: 'GET', url: startUrl, status: r.redirect ? 302 : 0, ok: !!r.redirect, durationMs: Math.round(performance.now() - started), error: r.error, requestHeaders: {}, responseHeaders: r.redirect ? { location: r.redirect.replace(/([?&]code=)[^&]+/, '$1***') } : {}, bodySnippet: r.steps.join('\n').slice(0, 2000), ts: new Date().toISOString() });
    // Where the login stopped, as a separate call entry (operation sca.browser.dump) so the next fix needs no extra run.
    if (r.dump) ctx.http.exchanges.push({ targetId: ctx.target.id, operation: 'sca.browser.dump', method: 'GET', url: startUrl, status: 0, ok: false, durationMs: 0, requestHeaders: {}, responseHeaders: {}, bodySnippet: r.dump.slice(0, 12000), ts: new Date().toISOString() });
    if (!r.redirect) ctx.state.loginSkipReason = `The bank login could not be completed in a headless browser with the demo user${r.error ? ` (${r.error})` : ''}. Steps: ${r.steps.join(' -> ') || 'none'}.`;
    return r.redirect;
  }
  const jar = new Map<string, string>();
  let url = startUrl;
  let method = 'GET';
  let form: Record<string, string> | undefined;
  // Friction counted by the plain form filler: one screen per form filled, every page load and redirect.
  const m: JourneyMetrics = emptyMetrics();
  const j: Journey = { via: 'form', completed: false, ...m };
  try {
    return await formLogin();
  } finally {
    // Recorded once the outcome is known (a refusal before any form is not a journey, see recordJourney).
    recordJourney(ctx, j);
  }

  async function formLogin(): Promise<string | undefined> {
  for (let hop = 0; hop < 12; hop++) {
    if (url.startsWith(redirectUri)) {
      j.completed = !authError(url);
      j.rejected = authError(url) && j.screens === 0;
      return url;
    }
    j.navigations++;
    try {
      const host = new URL(url).host;
      if (!j.hosts.includes(host)) j.hosts.push(host);
    } catch {
      // relative or malformed: the request below reports it
    }
    const r: HttpResponse = await ctx.http.request({ operation: method === 'GET' ? 'sca.page' : 'sca.submit', method, url, form, headers: cookieHeader(jar) });
    for (const c of r.setCookies ?? []) {
      const [pair] = c.split(';');
      const i = pair.indexOf('=');
      if (i > 0) jar.set(pair.slice(0, i).trim(), pair.slice(i + 1).trim());
    }
    const loc = r.headers['location'];
    if (r.status >= 300 && r.status < 400 && loc) {
      url = new URL(loc, url).toString();
      method = 'GET';
      form = undefined;
      continue;
    }
    if (r.status !== 200) return undefined;
    const f = parseForms(r.text)[0];
    if (!f) return undefined;
    form = fillForm(f, psu!);
    j.screens++;
    j.clicks++;
    for (const [k] of Object.entries(form)) {
      const field = f.fields?.find((x: any) => x.name === k);
      const type = (field?.type ?? '').toLowerCase();
      if (type === 'hidden' || type === 'submit') continue;
      if (type === 'password') j.typed.password++;
      else if (type === 'checkbox' || type === 'radio') j.choices++;
      else if (/otp|sms|code|pin/i.test(k)) j.typed.otp++;
      else j.typed.user++;
    }
    url = new URL(f.action || url, url).toString();
    method = f.method;
  }
  return undefined;
  }
}

function cookieHeader(jar: Map<string, string>): Record<string, string> {
  return jar.size ? { Cookie: [...jar].map(([k, v]) => `${k}=${v}`).join('; ') } : {};
}

export interface HtmlForm {
  action: string;
  method: string;
  fields: { tag: string; name: string; type: string; value: string; checked: boolean }[];
}

/** Minimal HTML form reader (no scripts): inputs, buttons, selects. */
export function parseForms(html: string): HtmlForm[] {
  const attr = (tag: string, name: string) => new RegExp(`\\s${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i').exec(tag)?.slice(1).find((v) => v !== undefined) ?? '';
  const forms: HtmlForm[] = [];
  for (const m of html.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form>/gi)) {
    const fields: HtmlForm['fields'] = [];
    for (const t of m[2].matchAll(/<(input|button|select|textarea)\b([^>]*)>(?:([\s\S]*?)<\/select>)?/gi)) {
      const tag = t[1].toLowerCase();
      const name = attr(t[0], 'name');
      if (!name) continue;
      let value = attr(t[0], 'value');
      if (tag === 'select') value = /<option\b[^>]*\bselected\b[^>]*value\s*=\s*"([^"]*)"/i.exec(t[3] ?? '')?.[1] ?? /<option\b[^>]*value\s*=\s*"([^"]*)"/i.exec(t[3] ?? '')?.[1] ?? '';
      fields.push({ tag, name, type: (attr(t[0], 'type') || (tag === 'button' ? 'submit' : 'text')).toLowerCase(), value, checked: /\schecked\b/i.test(t[0]) });
    }
    forms.push({ action: attr(m[0], 'action'), method: (attr(m[0], 'method') || 'GET').toUpperCase(), fields });
  }
  return forms;
}

/** Fills user/password/OTP fields, ticks every account checkbox, presses the approving button. */
export function fillForm(f: HtmlForm, psu: { user: string; password: string; otp?: string }): Record<string, string> {
  const out: Record<string, string> = {};
  const seenRadio = new Set<string>();
  for (const x of f.fields) {
    if (x.type === 'submit' || x.type === 'image') continue;
    if (x.type === 'password') out[x.name] = psu.password;
    else if (x.type === 'checkbox') out[x.name] = x.value || 'on';
    else if (x.type === 'radio') {
      if (!seenRadio.has(x.name) || x.checked) out[x.name] = x.value;
      seenRadio.add(x.name);
    } else if (x.type !== 'hidden' && /otp|sms|code|pin|token/i.test(x.name)) out[x.name] = psu.otp ?? '';
    else if (x.type !== 'hidden' && /user|login|uname|email|psu|name/i.test(x.name) && !x.value) out[x.name] = psu.user;
    else out[x.name] = x.value;
  }
  const buttons = f.fields.filter((x) => x.type === 'submit' && x.name);
  const approve = buttons.find((b) => /approve|allow|accept|confirm|yes|agree|authori|continue|submit|login|sign/i.test(`${b.name} ${b.value}`)) ?? buttons.find((b) => !/deny|reject|cancel|no$/i.test(`${b.name} ${b.value}`));
  if (approve) out[approve.name] = approve.value;
  return out;
}
