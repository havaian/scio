import type { Dispatcher } from 'undici';
import { HttpRecorder } from '../common/http';
import { RequestSigner } from '../common/credentials';
import { loadThresholds } from '../common/config';
import { Exchange, TargetConfig } from '../common/types';
import { AuditContext } from '../checks/context';
import { api, createConsent, exchangeCode, obtainCode, pkcePair } from '../flows/full.flow';
import { isUp } from './uptime';
import { MONITOR_OPS } from './latency-profile';

/** Only simulated full-mode targets (the organizers' mock) get authenticated probes; real banks never do. */
export const authenticatedTarget = (t: TargetConfig) => t.simulated && t.mode === 'full' && !t.specOnly;

const READ_OPS: string[] = [MONITOR_OPS.accounts, MONITOR_OPS.balances, MONITOR_OPS.transactions];
const isoDate = (d: Date) => d.toISOString().slice(0, 10);

interface Session {
  token: string;
  consentId: string;
  /** UTC ms after which the token is not used any more (a minute before the token's own expiry). */
  until: number;
}

/**
 * Light authenticated AIS journey for the monitor: accounts, balances and transactions of the first account.
 * The consent and token are reused until the token expires or a read is refused, so a new consent is created
 * about once an hour, not on every probe. Consent, authorize and token calls are stored as monitor.ais.setup.
 */
export class AisProbe {
  private sessions = new Map<string, Session>();
  private busy = new Set<string>();

  async run(t: TargetConfig, client: { dispatcher?: Dispatcher; signer?: RequestSigner; signBase?: string }): Promise<Exchange[]> {
    if (!authenticatedTarget(t) || this.busy.has(t.id)) return [];
    this.busy.add(t.id);
    const th = loadThresholds();
    const http = new HttpRecorder(t.id, th.requestTimeoutMs, client);
    const ctx = new AuditContext(t, http, th);
    try {
      let s = this.sessions.get(t.id);
      if (s && Date.now() > s.until) s = undefined;
      const reused = !!s;
      s ??= await this.setup(ctx);
      if (!s) return this.label(http);
      let accounts = await this.read(ctx, s, MONITOR_OPS.accounts, '/v1/accounts');
      if (reused && (accounts.status === 401 || accounts.status === 403)) {
        // The stored token or consent was refused: that call belongs to the setup, then start over once.
        http.exchanges[http.exchanges.length - 1].operation = MONITOR_OPS.setup;
        this.sessions.delete(t.id);
        s = await this.setup(ctx);
        if (!s) return this.label(http);
        accounts = await this.read(ctx, s, MONITOR_OPS.accounts, '/v1/accounts');
      }
      const id = accounts.json?.accounts?.[0]?.resourceId;
      if (id) {
        const acc = `/v1/accounts/${encodeURIComponent(id)}`;
        await this.read(ctx, s, MONITOR_OPS.balances, `${acc}/balances`);
        const to = new Date();
        await this.read(ctx, s, MONITOR_OPS.transactions, `${acc}/transactions?bookingStatus=booked&dateFrom=${isoDate(new Date(to.getTime() - 30 * 86400_000))}&dateTo=${isoDate(to)}`);
      }
      // A refused read (expired consent, access limit reached): the next probe starts with a new consent.
      if (http.exchanges.some((x) => READ_OPS.includes(x.operation) && [401, 403, 429].includes(x.status))) this.sessions.delete(t.id);
      return this.label(http);
    } finally {
      this.busy.delete(t.id);
    }
  }

  /** Discovery, consent, authorize (the mock approves the simulated SCA page), token. */
  private async setup(ctx: AuditContext): Promise<Session | undefined> {
    const redirectUri = ctx.target.redirectUri ?? 'https://example.org/cb';
    const disc = await api(ctx, 'oauth.discovery', 'GET', ctx.oauthUrl('/.well-known/oauth-authorization-server'), { absolute: true, auth: false, consent: false, retry: false });
    ctx.state.discovery = disc.status === 200 ? disc.json : undefined;
    const consent = await createConsent(ctx, 'consent.create');
    const consentId = consent.status === 201 ? consent.json?.consentId : undefined;
    if (!consentId) return undefined;
    const { verifier, challenge } = pkcePair();
    const code = await obtainCode(ctx, `AIS:${consentId}`, challenge, redirectUri);
    if (!code) return undefined;
    const tok = await exchangeCode(ctx, code, verifier, redirectUri);
    if (tok.status !== 200 || !tok.json?.access_token) return undefined;
    const life = Number(tok.json.expires_in) > 0 ? Number(tok.json.expires_in) : 3600;
    const s = { token: tok.json.access_token, consentId, until: Date.now() + Math.max(60, life - 60) * 1000 };
    this.sessions.set(ctx.target.id, s);
    return s;
  }

  /** One read, no retry: the monitor records what a TPP would see at this moment. */
  private read(ctx: AuditContext, s: Session, operation: string, path: string) {
    return api(ctx, operation, 'GET', path, { token: s.token, consentId: s.consentId, retry: false, validate: false });
  }

  /** Everything that is not one of the three reads is setup; up/down as for the front door. */
  private label(http: HttpRecorder): Exchange[] {
    for (const x of http.exchanges) {
      if (!READ_OPS.includes(x.operation)) x.operation = MONITOR_OPS.setup;
      x.ok = isUp(x.status, x.error);
    }
    return http.exchanges;
  }
}
