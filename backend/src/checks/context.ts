import { HttpRecorder, HttpResponse } from '../common/http';
import { Finding, TargetConfig, Thresholds } from '../common/types';
import { Spec } from '../spec/spec';

export const REF = {
  BG: 'Berlin Group NextGenPSD2 XS2A Implementation Guidelines 1.3.x (referenced by the Georgian guide)',
  GE: 'Georgian NextGenPSD2 XS2A Implementation Guide 0.8.RC3 (Banking Association of Georgia)',
  PKCE: 'RFC 7636 (PKCE)',
  OAUTH: 'RFC 6749 (OAuth 2.0)',
  MTLS: 'RFC 8705 (OAuth 2.0 mutual-TLS client authentication and certificate-bound tokens)',
  FAPI: 'FAPI security profile (OpenID Foundation)',
  HSTS: 'RFC 6797 (HTTP Strict Transport Security)',
  IBAN: 'ISO 13616 (IBAN, mod-97 checksum)',
  CCY: 'ISO 4217 (currency codes)',
  OAS: 'OpenAPI Specification 3.0',
};

/** Shared state for one target within one run. */
export class AuditContext {
  readonly findings: Finding[] = [];
  /** Named responses captured during the flow, used by later checks. */
  readonly state: Record<string, any> = {};

  constructor(
    readonly target: TargetConfig,
    readonly http: HttpRecorder,
    readonly thresholds: Thresholds,
    public spec?: Spec,
  ) {}

  add(f: Omit<Finding, 'targetId'>) {
    this.findings.push({ targetId: this.target.id, ...f });
  }

  pass(f: Omit<Finding, 'targetId' | 'status' | 'severity'>) {
    this.add({ status: 'pass', severity: 'none', ...f });
  }

  url(path: string): string {
    return this.target.baseUrl.replace(/\/$/, '') + path;
  }

  oauthUrl(path: string): string {
    return (this.target.oauthHost ?? new URL(this.target.baseUrl).origin).replace(/\/$/, '') + path;
  }

  short(r: HttpResponse): string {
    if (r.error) return `no HTTP response: ${r.error}`;
    const code = r.json?.tppMessages?.[0]?.code ?? r.json?.code ?? r.json?.error;
    return `HTTP ${r.status}${code ? ` ${code}` : ''}`;
  }
}

export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
