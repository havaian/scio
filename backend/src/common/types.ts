export type Layer = 'conformance' | 'reliability' | 'latency' | 'security' | 'data';
export type Status = 'pass' | 'fail' | 'warn' | 'info' | 'skip';
export type Severity = 'high' | 'medium' | 'low' | 'none';

export const LAYERS: Layer[] = ['conformance', 'reliability', 'latency', 'security', 'data'];

export interface TargetConfig {
  id: string;
  name: string;
  bank: string;
  /** full = test environment, passive = public probes, bis = TBC Business Integration Services (proprietary, read-only). */
  mode: 'full' | 'passive' | 'bis';
  simulated: boolean;
  baseUrl: string;
  oauthHost?: string;
  specUrl?: string;
  specFile?: string;
  discoveryUrl?: string;
  redirectUri?: string;
  clientId?: string;
  skipEndpointProbes?: boolean;
  /** Account list path relative to baseUrl, as the bank's spec has it (default /v1/accounts). */
  accountsPath?: string;
  /** Only the published spec is checked (no API host published or reachable): no probes, not monitored. */
  specOnly?: boolean;
  /** Where the endpoint was found (bank documentation). */
  source?: string;
  /** What is assumed about this target (shown in reports). */
  note?: string;
  /** BIS - Accounts: client credentials come from the environment, never from this file. */
  bis?: { clientIdEnv: string; clientSecretEnv: string; scope: string; tokenUrl?: string; accountNumber?: string; currency?: string };
  /** Test certificate for sandbox flows (mTLS + request signing). PEM file names inside certs/. */
  credentials?: {
    cert?: string;
    key?: string;
    /** Environment variable holding the private key password (never put the password in this file). */
    passphraseEnv?: string;
    /** Separate QSealC for signing; defaults to cert/key. */
    signCert?: string;
    signKey?: string;
    /** Extra root CA to trust for this bank's servers (the portal's root certificate, PEM or DER). */
    ca?: string;
    /** Sign requests with Digest + x-jws-signature (GE-JWS). Default true. */
    sign?: boolean;
    /** Environment variable with the OAuth client secret, when the token endpoint uses client_secret_basic (e.g. Credo). */
    clientSecretEnv?: string;
    /** Environment variable with the OAuth client ID issued by the bank (overrides clientId and the certificate's TPP identifier). */
    clientIdEnv?: string;
    /** Sandbox test user for the bank's login page (shared demo credentials published on the portal). */
    psu?: { user: string; password: string; /** Environment variable holding the password (privately issued test users); overrides password. */ passwordEnv?: string; otp?: string; /** PSU-ID header value, only if the bank wants one (format is bank-specific). */ psuId?: string };
  };
}

export interface Thresholds {
  source: string;
  availabilityPct: number;
  errorRatePct: number;
  latencyP95Ms: number;
  latencyP99Ms: number;
  /** Below this many samples p95/p99 equal the max and are not reported as percentiles. */
  latencyMinSamples?: number;
  /** A target needs at least this many rule-based verdicts (pass/fail/warn) to get a score. */
  minEvaluatedChecks?: number;
  requestTimeoutMs: number;
  probeRepetitions: number;
  probeSpacingMs: number;
  tlsMinVersion: string;
  certExpiryWarnDays: number;
  aiAutoConfidence?: number;
  aiReviewConfidence?: number;
  /** Minimum seconds between audit runs that probe real (non-simulated) banks. */
  minRunIntervalSec?: number;
  /** Audits started from the dashboard/API per Tbilisi calendar day (0 = unlimited). The CLI is exempt. */
  maxRunsPerDay?: number;
  /** Automated audits at daily slots (Tbilisi time; legacy: timeTashkent without slots) and whether the dashboard/API may start audits too. */
  schedule?: { enabled?: boolean; timeTashkent?: string; manualRuns?: boolean; timezone?: string; slots?: { time: string; targets?: 'all' | 'simulated' }[] };
  /** Continuous uptime monitor (minutes between samples, days kept). */
  monitor?: { simulatedIntervalMin?: number; realIntervalMin?: number; retentionDays?: number; /** Seconds before re-checking a failed sample; down only if the re-check fails too. */ confirmDownSec?: number; /** Minutes between authenticated AIS probes on simulated targets (0 = off). */ authenticatedIntervalMin?: number };
  /** A layer needs at least this many rule-based verdicts to get a score (otherwise null, shown as "not enough checks"). */
  minLayerChecks?: number;
}

export interface Finding {
  runId?: string;
  targetId: string;
  checkId: string;
  layer: Layer;
  status: Status;
  severity: Severity;
  title: string;
  endpoint?: string;
  message: string;
  expected?: string;
  actual?: string;
  fix?: string;
  reference?: string;
  evidence?: unknown;
  /** Advisory AI triage (never affects status or score). */
  ai?: any;
  /** 'ai' = produced by an AI feature (e.g. AI-generated tests): shown, never scored. */
  source?: 'rules' | 'ai';
}

export interface Exchange {
  runId?: string;
  targetId: string;
  operation: string;
  method: string;
  url: string;
  status: number;
  ok: boolean;
  durationMs: number;
  serverTimingMs?: number;
  error?: string;
  requestHeaders: Record<string, string>;
  responseHeaders: Record<string, string>;
  bodySnippet: string;
  /** Base64 SHA-256 of the full response body (not stored in the DB). */
  bodySha256?: string;
  /** Base64 SHA-512 of the full response body (not stored in the DB). */
  bodySha512?: string;
  ts: string;
}

export interface RunSummary {
  id: string;
  startedAt: string;
  finishedAt?: string;
  status: 'running' | 'done' | 'failed';
  targets: string[];
  thresholdsSource: string;
  error?: string;
  /** Who started the run; only 'api' runs count toward the daily quota. */
  source?: 'schedule' | 'api' | 'cli';
}
