# Scio

**Open banking API auditor for Georgia.** Scio tests how closely each bank's open banking API follows the Georgian standard (v0.8, Berlin Group NextGenPSD2 based), and how reliable, fast and secure it is in practice. It checks against the Georgian XS2A Implementation Guide 0.8.RC3 and the Berlin Group guidelines it builds on, clause by clause. It produces a per-bank scorecard, a cross-bank incompatibility report, a quality report, continuous daily and monthly uptime, and fix-it guidance for every deviation.

Built by team ATABAI for the AI & Open Banking Hackathon 2026 (Track 2: Open Banking Interoperability & Quality Assurance).

Users: third-party providers (TPPs) integrating with several banks, banks checking their own APIs, and NBG as supervisor.

## Important: test environment

The organizers supplied only the TBC mock API. Sandbox access to real banks was obtained by the team directly from the banks (test certificates from developer portals or issued on request, plus test users). Scio:

- runs the **full flow** against the organizers' **TBC mock API** (`tbc-bank-mock-open-banking-api.vercel.app`, simulated data): AIS consent, OAuth with PKCE, account and card reads; **payment initiation** (single, recurring, future-dated, status, cancellation); **deposit and loan information** through the v2 account-access consent; negative and security tests;
- sends **read-only, unauthenticated probes** to 8 public endpoints or sandboxes of 7 real banks, found through NBG's list of ASPSPs (discovery documents, TLS, client-certificate enforcement, header validation). It never tries to bypass authentication and sends a handful of requests per run;
- checks the **published OpenAPI documents** of Bank of Georgia, Liberty, Silk, Cartu, Credo, ProCredit, Terabank and PASHA Bank (`backend/config/specs/`) with the same static checks as the mock, plus a cross-bank comparison. Terabank and PASHA publish no reachable sandbox host, so they are spec-only targets (no probes, not monitored). A published YAML that only loads after repairs is reported (`spec.parse`);
- runs the **full sandbox journey** (mTLS, signed requests, OAuth, headless bank login, account reads) on Bank of Georgia, Liberty, Silk and Cartu with the certificates the team obtained; TBC and Credo join once their certificates arrive (see [Bank sandboxes](#bank-sandboxes));
- **monitors availability continuously** (NBG asks for "consolidated daily and monthly uptime metrics"): one light request per target every 5 minutes, with the bank's test certificate where the team has one (so the answer is a real HTTP status, not a TLS refusal). A failed sample is re-checked after 30 s before it counts as down. On the organizers' mock only (never real banks) it also runs a light authenticated AIS journey every 15 minutes (accounts, balances and transactions of the first account, reusing consent and token until they expire), so latency and uptime can be compared by hour of the day (09:00 vs 15:00 vs 21:00), not only at the daily audit.

Thresholds (availability ≥ 99.5%, error rate ≤ 1%, p95 ≤ 1000 ms) are **assumptions** until NBG's regulatory indicators are confirmed, and every report labels them as such.

## What it checks

The four layers from the track brief, plus data quality. Every finding carries the expected and actual behaviour, a fix, and the standard it refers to.

| Layer | Checks |
|---|---|
| **1. Standard compatibility** | Published OpenAPI document: malformed path templates, undeclared path parameters, X-Request-ID optionality, unused security schemes, examples that violate their own schemas, schemas that validators cannot compile, undocumented error and success responses, error examples that contradict their status code, example IBANs that fail their checksum, one header under two names, version in base path. Cross-bank: shared spec templates (banks publishing the identical set of operations, so one fix repairs all of them; informational), server URLs, declared standard version, core 0.8 AIS/PIS operations present, authentication documented, amounts typed as strings, string types (IBAN, currency) documented as strings. Live: every response validated against the bank's own schema; X-Request-ID echo; consent creation and deletion; error body structure (`tppMessages` or RFC 7807 with a code; member names in the wrong letter case are named as such) and message code vs HTTP status, by the same rule in the live journey and the passive probes. AIS negative tests (missing/invalid X-Request-ID, missing/invalid token, missing/unknown Consent-ID, unknown account, malformed consent, invalid and reversed dates). **Payments:** creation response, OAuth authorisation, ISO 20022 status, payment resource equals what was sent, cancellation, recurring and future-dated services, bulk, multiple recurring and secured payments; **idempotency** (the same initiation with the same X-Request-ID must not create a second payment, GE-XS2A §7.7); negatives (missing creditor, wrong IBAN check digit, 4-decimal or negative amount, unknown currency, unknown product, unknown paymentId, past execution date, endDate before startDate). **Deposits and loans:** v2 consent, authorisation, lists, details, balances, and whether the documented path is the one actually served. |
| **2. Performance & reliability** | 30 calls per endpoint and per API (accounts, balances, transactions, payment status, deposits, loans): availability, error rate (timeouts, 5xx, 429), status-code mix, Retry-After on 429/503. An outage during the flow is reported as a reliability failure and the affected checks as "could not be tested", never as conformance failures. **Continuous monitor:** daily and monthly uptime per target, an hour-of-day latency profile (Tbilisi hours, p50/p95/up% per operation), incidents, CSV export with `http_samples` (samples with an HTTP answer; the rest were judged on the TLS handshake alone). Expired or wrong-name server certificates count as down. |
| **3. Latency** | p50 / p95 / p99 / max per endpoint and per bank, plus bank-reported processing time (`Server-Timing`) to separate network from server time. p95 and p99 are only reported with ≥ 20 samples; below that they equal the slowest call, so the median is judged and the report says so. Next to them, the uptime monitor's p50 / p95 over the last 24 h (about 100+ front-door samples per target and day), shown for context and not scored. |
| **4. Security** | OAuth discovery: client authentication methods (FAPI), certificate-bound tokens (RFC 8705), PKCE methods. Active tests: authorization code replay, wrong PKCE verifier, redirect_uri mismatch, AIS token used on a payment, AIS consent used on deposits, deleted consent still usable. Client certificate (mTLS) enforcement (a TLS alert counts as enforced; a reset or an unverifiable server certificate does not), server certificate chain, TLS version and expiry, HSTS, CORS, token lifetime. Message signing: X-JWS-Signature and Digest present, **Digest equal to the SHA-256 or SHA-512 of the body**, **response signature verified** with the key in `x5c`, JWS protected header per GE-JWS (b64=false; sigT in UTC without fractions and within -60 s..+2 s; sigD with the ETSI HttpHeaders mId and digest; x5c holding only the signing certificate; no x5t, jwk or cty; RS/PS/ES 256/512; crit). Sandboxes: an unsigned request and requests with a stale or future sigT must be refused (three read-only consent-status calls). |
| **Consent journey** | Sandbox banks: what a person must do to authorise access (distinct screens, values typed, account choices, button presses, page loads, hosts) and how many API steps the TPP needs before reading data (consent, authorisation, OAuth metadata, token, extra consents). Shown side by side on the Quality page; informational, not scored. |
| **Service coverage** | Variable recurring payments (sweeping), which NBG lists as available: whether each published spec has VRP operations, next to its fixed-amount recurring services. Informational (no published clause fixes the API). |
| **Data quality** | IBAN check digits (ISO 13616), ISO 4217 currencies, amount format, ISO dates, balance type codes (including deposits and loans), minimum balance types per endpoint, date filter respected, unique transaction ids. |

### Clause mapping

Every check is mapped to the clause it enforces in `backend/config/standard-map.json`, shown on each finding, in the incompatibility report and in the HTML report:

| Key | Document |
|---|---|
| GE-XS2A | Georgian NextGenPSD2 XS2A Implementation Guide 0.8.RC3 (Banking Association of Georgia) |
| GE-IAA | Georgian Identification, Authentication and Authorization Guide 0.8.RC1 |
| GE-JWS | Georgian JWS Implementation Guide 0.5.RC1 |
| BG-IG | Berlin Group NextGenPSD2 Implementation Guidelines 1.3.11 (the Georgian guide references 1.3.9; the cited sections 4.12, 4.13 and 14.x keep the same numbering) |
| OAS, RFC, FAPI1, ISO | OpenAPI 3.0.3, IETF RFCs, FAPI 1.0 Part 1, ISO 13616 / 4217 |

Each mapping is marked verified (clause read in the source document) or unverified. Examples: X-Request-ID mandatory and UUID (GE-XS2A §7.7); status per message code, e.g. CONSENT_UNKNOWN 400 when sent in a header (BG-IG §14.11.1); JWS seal on every request and response (GE-XS2A §5.4, §7.4; GE-JWS §5, §7); TLS 1.2+ with QWAC mutual TLS and RFC 8705 client authentication (GE-XS2A §5.2). Latency has no clause: neither standard sets a number.

### Scoring

Per layer: passed / (passed + weighted problems). A failure weighs its severity (high 3, medium 2, low 1), a warning half of that, a pass 1. Info, skipped and AI-generated results are not scored. Overall = mean of the layers that were evaluated. A target with fewer than 10 evaluated checks (`minEvaluatedChecks`) gets no score, only the count: a handful of front-door checks would otherwise read like a full journey. Every overall score is shown with the number of checks it rests on, and every layer score with its own count; a layer with fewer than 3 checks (`minLayerChecks`) shows no score (reliability and latency use sample counts instead). Overall scores rest on different check sets (the mock gets the full suite, a spec-only bank the static checks), so banks are ranked on a **like-for-like** basis: only the checks every scored real bank received. The score is fully deterministic (`backend/src/reports/report.service.ts`, covered by unit tests).

## AI layer

Two engines, each used for what it does best. Both are optional; without them every rule-based check still runs.

| Engine | Where it runs | What Scio uses it for |
|---|---|---|
| **Jev** (TypeSafe) | API | Typed decisions with calibrated confidence: triage of every finding, error-message quality |
| **QVAC** (Tether): Qwen3 1.7B + EmbeddingGemma 300M | On this machine, nothing leaves it | AI-generated negative tests, plain-language summaries, grouping findings into shared root causes, local fallback for triage |

### Jev

[Jev](https://docs.typesafe.ai) answers typed questions with calibrated confidence instead of generating text.

- **Triage:** for every failure and warning, Jev picks the impact (security exposure, blocks integration, breaks some flows, degrades quality, cosmetic) and the owner (spec, implementation, authorization server, infrastructure, test data). Impact maps to severity for the comparison with the rules: security exposure = high, blocks integration and breaks some flows = medium, the rest low.
- **Error message quality:** for every distinct error response, Jev scores how actionable it is (0-3) and whether it describes what the client actually did wrong.

Governance, following NBG model-risk expectations:

- Rules decide pass/fail and the score. **AI never changes either**; its output is advisory.
- Confidence gates the outcome: ≥ 0.8 shown as confident, 0.5-0.8 flagged for review, < 0.5 handed to a human (`config/thresholds.json`). Answers handed to a human are listed as "sent to human review" and left out of averages, counts and the conclusions in the text.
- Rules are the baseline and AI the challenger: when Jev's impact disagrees with the rule severity, the disagreement is shown, never resolved silently.
- Sent to Jev: finding metadata (check, endpoint, observation, expected and actual values, clause) and the bodies of error responses to Scio's own requests against test environments (the mock, bank sandboxes, unauthenticated probes). IBAN-like strings (upper or lower case, compact or in groups of four) are masked first. Scio only uses test users and test accounts.
- Without `TYPESAFE_API_KEY` the Jev features are skipped (or answered locally by QVAC, see below) and everything else works.

### QVAC (local)

- **AI-generated tests.** Qwen3 reads each endpoint's parameters from the OpenAPI spec and proposes negative tests. Its output is constrained by a JSON schema to parameters and mutation types that exist (empty, wrong type, invalid format, too long, unknown value, special characters, reversed date range). Code rejects invalid proposals (for example omitting an optional parameter), builds the request values itself, runs the test against test environments only, and judges the result: a 4xx is correct, a 2xx means invalid input was accepted, a 5xx means it crashed the endpoint. Parameters already covered by rule-based tests are not offered. Results are shown with an "AI-generated" label and are not scored.
- **Plain-language summaries.** One per bank, for supervisors and developers, written only from computed facts. Two guardrails in code: every number in the text must exist in the facts (only 1-3 are free, as list counts), and the text may not describe a layer as a problem when that layer scored 85 or more (or was not tested). A failing summary is regenerated once with the errors fed back, and otherwise shown as "needs review".
- **Shared root causes.** EmbeddingGemma embeds each failure's title and fix; findings with cosine similarity ≥ 0.76 (`QVAC_CLUSTER_SIM`) are grouped, across checks and banks. One fix closes the whole group.
- **Triage fallback.** Without a Jev key, Qwen3 answers the same triage questions. A generative model has no calibrated confidence, so every local answer is flagged for review.

Enable with `QVAC_ENABLED=true`. Needs the optional dependency `@qvac/sdk` (about 2 GB installed), roughly 2-4 GB of RAM, and the model files (about 1.33 GB) in the repo's `models/` folder (git-ignored):

```bash
# Docker: WITH_QVAC=true and QVAC_ENABLED=true in .env, then
docker compose build backend
docker compose run --rm backend npm run qvac:setup   # downloads both models once into ./models
docker compose up -d

# Local
cd backend
npm run build
npm run qvac:setup      # downloads both models once into ../models
QVAC_ENABLED=true npm start
```

`qvac:setup` uses plain HTTPS from Hugging Face instead of QVAC's peer-to-peer registry, which times out on some networks. To use other copies, set `QVAC_LLM_MODEL` / `QVAC_EMBED_MODEL` to a local path or URL. Loading takes a few seconds; each generation takes about 5-10 s on CPU, so a run with QVAC takes a few minutes longer.

## Architecture

```
frontend/  Vue 3 + Vite + Tailwind (shadcn-style components): scorecard, findings, incompatibility, quality, uptime, runs
backend/   NestJS
  src/flows/     consent -> OAuth (PKCE) -> token -> AIS reads; shared authorisation for payments and v2 consents
  src/checks/    static-spec, live-conformance, pis (payments), loans (deposits/loans), performance, security, data, passive
  src/monitor/   continuous uptime monitor, authenticated mock probes, daily/monthly aggregation (Tbilisi calendar), hour-of-day latency profile, CSV
  src/alerts/    alert rules (down/recovered, latency, new high findings, certificate expiry), Telegram and email
  src/mcp/       read-only MCP server for AI assistants (streamable HTTP at /api/mcp, stdio via npm run mcp)
  src/metrics/   Prometheus text format at /api/metrics (monitor state, uptime, latest scores and findings) for Grafana
  src/spec/      OpenAPI loading, route matching, JSON Schema validation (ajv)
  src/ai/        Jev client, triage and error-quality checks, QVAC local features
  src/reports/   scoring, incompatibility matrix, HTML report
  src/storage/   SQLite (node:sqlite): runs, findings, raw request/response log, monitor samples
  test/          unit tests (node:test): scoring, IBAN, percentiles, uptime, JWS header, Digest, redaction, login page dump, run guardrails, mTLS classification
  config/        targets.json (banks, with the source of each endpoint), thresholds.json, standard-map.json, vendored mock spec
docker-compose.yml   backend + frontend (nginx), dashboard on 127.0.0.1:4530
```

Every recorded call is stored: method, URL, request headers, response status and headers, and the first 2,000 characters of the response body. Request bodies are not stored, and helper calls marked silent are not recorded. Secrets are redacted before storing: every `Authorization` value keeps only its scheme (`Basic ***`, `Bearer ***`); API-key, secret, password and cookie headers are masked; access, refresh and ID tokens, client secrets, PKCE verifiers, passwords and OTPs are masked in response bodies (JSON or form-encoded) and URLs; authorization codes in `Location` headers; session cookie values in `Set-Cookie`. `x-jws-signature` is public and kept. Each finding in the dashboard has "Show the calls behind this result": the exact requests, headers, X-Request-IDs and responses behind the verdict.

## Run it

Requirements: Node.js 22.21+ (22.x) or 24.9+ (built-in SQLite; QVAC's runtime needs these versions), or Docker.

**Docker**

```bash
docker compose up --build
# dashboard: http://localhost:4530 (bound to 127.0.0.1; public access goes through the host nginx)
```

Settings go in a `.env` file next to `docker-compose.yml` (git-ignored); copy `.env.example`:

```bash
TYPESAFE_API_KEY=...     # Jev
WITH_QVAC=true           # build the image with the local AI SDK (much larger image)
QVAC_ENABLED=true        # use it; models in ./models (qvac:setup, see AI layer)
MONITOR_ENABLED=true     # continuous uptime monitor
CORS_ORIGIN=https://...  # optional: exact origin(s) allowed to call the API cross-site; unset = CORS off (the dashboard is same-origin)
```

**Local**

```bash
cd backend
npm ci && npm run build
TYPESAFE_API_KEY=... npm start        # API on :3000 (key optional)

cd ../frontend
npm ci && npm run dev                 # dashboard on :5173, proxies /api to :3000
```

**Automated audits**

Audits run automatically at daily slots in Tbilisi time (UTC+4; `schedule.slots` in `backend/config/thresholds.json`): 09:00, 15:00 and 21:00, all targets each time, so real banks get 3 audits a day (a slot set to `"simulated"` audits the organizers' mock only). A slot's targets do not depend on runs earlier that day; a slot that collides with a running audit is skipped (logged). If the server was down at today's most recent slot and no audit was started since that slot's time (failed or interrupted ones count), that slot's audit starts about a minute after start-up. Without `slots`, a legacy `timeTashkent` means one audit of all targets a day at that Tashkent time, as before. The dashboard shows all slots and the next audit; all times in the dashboard, HTML report and CLI are Tbilisi time; it has no Run button while `schedule.manualRuns` is `false` (default), so the API refuses manual starts with `403`. Turn the schedule off with `AUDIT_SCHEDULE_ENABLED=false`.

**Clearing audits**

```bash
docker compose exec backend npm run runs:clear -- --yes    # local: cd backend && npm run runs:clear -- --yes
```

Deletes every audit run with its findings and call logs; uptime history stays. Without `--yes` it only explains what it would do.

**CLI (headless)**

```bash
cd backend
npm run audit -- --targets tbc-mock,paysera-ge --out reports
```

Writes `reports/<run>/report.json` and `report.html` and prints the scorecard. Exit code 1 means high-severity failures were found (useful in CI). The CLI does not start the uptime monitor. In Docker, run it next to the server with `docker compose exec backend npm run audit`; it refuses to start (exit code 2) while another audit is running, in the server or another CLI.

**Tests**

```bash
cd backend
npm test
```

**API**

| Method | Path | |
|---|---|---|
| GET | `/api/health` | server up, whether an audit is running |
| POST | `/api/runs` | start an audit (`{ "targets": [...] }` optional); `403` unless `schedule.manualRuns` is true |
| GET | `/api/runs/schedule` | audit slots (Tbilisi time), next slot and run time, whether manual runs are allowed |
| GET | `/api/runs/quota` | daily limit for API runs, used today, remaining, reset time |
| GET | `/api/runs`, `/api/runs/:id` | run status |
| GET | `/api/reports/:id` (`latest`) | full report JSON |
| GET | `/api/reports/:id/html` | printable HTML report |
| GET | `/api/reports/:id/download/html`, `/download/json` | the same report as a file download (`scio-report-<run>.html` / `.json`) |
| GET | `/api/reports/:id/exchanges` | raw request/response log (`?target=`, `?operation=`) |
| GET | `/api/uptime` (`?days=`, `?tz=tbilisi` or `tashkent`) | daily and monthly uptime per target, by Tbilisi calendar days (`tz=tashkent` kept for compatibility) |
| GET | `/api/alerts` | alerting on/off, channel names, last 50 alerts |
| POST | `/api/mcp` | read-only MCP server (streamable HTTP), see MCP server |
| GET | `/api/metrics` | Prometheus text format: monitor up/status/duration and uptime (24h, 7d, 30d) per target, latest audit scores per layer, like-for-like score, finding counts. Gauges recomputed at scrape time; point a Prometheus scrape job at it to chart Scio in Grafana |
| GET | `/api/uptime.csv` (`?days=`, `?tz=`) | the same, one row per target and day |
| GET | `/api/latency-profile` (`?days=7`) | samples, p50, p95 and up% per target, monitor operation and Tbilisi hour (0-23); authenticated setup calls excluded |
| GET | `/api/ai/status` | checks the Jev and QVAC connections; the result is cached for 10 minutes (each check is a paid Jev call) |

## MCP server

Scio is also an MCP (Model Context Protocol) server, so an AI assistant (Claude Desktop or Code, Cursor) can answer questions such as "Is Bank of Georgia's consent flow compatible with the standard?", "What must Silk fix first?" or "What was TBC mock uptime this week?" from the latest audit, with clause references. It is read-only: it serves the same public data as the dashboard, never starts an audit and never calls a bank. Answers state the run id, each target's access level (mock, sandbox, spec only, probes) and that thresholds are assumptions.

Tools:

- `list_banks` - targets with access level, overall score and check count, like-for-like score, fail/warn counts, run time
- `get_bank_report` - one bank: layer scores, top problems with expected/actual, fix and standard clause, note and limitations
- `get_findings` - findings filtered by bank, layer, status, severity or check id (max 50)
- `compare_banks` - 2-4 banks: like-for-like score and the checks where their verdicts differ
- `explain_check` - a check's standard clauses (verified or not) and the verdict per bank
- `get_uptime` - monitor uptime over up to 31 days with coverage and incidents, daily buckets for one bank

A bank can be given as a target id (`bog-sandbox`) or a name (`Bank of Georgia`, `silk`, `tbc mock`).

**Remote** (Streamable HTTP, stateless, 60 requests per minute per IP) at `https://scio.uz/api/mcp`:

```bash
claude mcp add --transport http scio https://scio.uz/api/mcp
```

**Local** (stdio, reads the server's database; build first with `npm run build`). Claude Desktop `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "scio": {
      "command": "node",
      "args": ["/path/to/scio/backend/dist/mcp-stdio.js"],
      "env": {
        "DB_FILE": "/path/to/scio/backend/data/scio.sqlite",
        "CONFIG_DIR": "/path/to/scio/backend/config"
      }
    }
  }
}
```

The stdio server turns off the uptime monitor, the audit schedule and alerts in its own process; uptime figures come from samples the running server stored.

## Alerting

The backend checks the database every minute (`alerts` in `backend/config/thresholds.json`) and sends a short message, with Tbilisi time and a dashboard link when `PUBLIC_URL` is set, when:

- a monitored target goes down, and again when it recovers (with the outage length); monitor failures are already confirmed by a re-check;
- the median response of HTTP-answered monitor samples over the last 30 min (at least 5) exceeds `alerts.latencyAlertMs` (a median threshold, separate from the p95 indicator `latencyP95Ms`, which is used when it is unset), and again when it is back under;
- a finished audit has high-severity failures that the previous finished audit of the same bank did not have (title, fix, clause); a bank's first audit is the baseline;
- an audit finishes (scheduled or CLI): one summary with each target's access level, overall score with check count, like-for-like score, failures and new high-severity failures (`rules.auditFinished`, on by default);
- a bank's server certificate (from that bank's latest audit with TLS evidence, so mock-only audits, such as CLI runs of the mock, do not hide it) or the team's test certificate expires within `certExpiryWarnDays` or has expired; checked daily, repeated at most every `certRepeatDays` (7).

State is kept in the database, so a restart does not repeat alerts. Every alert is logged and the last 50 are listed at `GET /api/alerts` and on the dashboard (channel names only, no tokens or addresses).

Channels (set in `.env`, all optional; alerting stays off until one is set, `ALERTS_ENABLED=false` turns it off): Telegram (`TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`) and email over SMTP (`SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURE`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM`, `ALERT_EMAIL_TO` comma-separated). Every configured channel gets every alert; one failing channel does not stop the other.

Telegram bot: message @BotFather, send `/newbot` and copy the token. Send any message to the new bot (or add it to a group), then open `https://api.telegram.org/bot<token>/getUpdates` and copy `chat.id` (negative for groups).

```bash
docker compose exec backend npm run alerts:test    # local: cd backend && npm run build && npm run alerts:test
```

Sends one test message to every configured channel and prints which succeeded (exit code 1 if any failed).

## Adding a bank

Add an entry to `backend/config/targets.json`. `mode: "full"` runs the complete active flow, negative tests included (only for environments built for testing, such as the organizers' mock); `mode: "passive"` runs the static spec checks and read-only probes. A `credentials` block (certificates in `certs/<bank>/`, the bank's test user) adds the sandbox journey to a passive target. Put the page where the endpoint was found in `source`, and anything assumed in `note`; both appear in the reports.

## Bank sandboxes

Liberty, Silk and Cartu publish sandboxes (Alta Software) that need a PSD2 test certificate and a redirect login. The developer portals generate test certificates on their **Cert** page, and publish a shared demo user (`demo` / `demo`, OTP `1234`), which is already in `targets.json`.

1. On each portal's Cert page, request a test certificate (name, email, CN, organisation, TPP identifier, private key password). The portal returns five files: `TestPsd2CertQWAC.crt/.pfx` (mTLS), `TestPsd2CertQSealC.crt/.pfx` (signing) and `AltasoftPsd2RootCa.crt` (the sandbox root CA).
2. Copy the certificates as they are and take the private keys out of the `.pfx` files (Liberty shown; same for `silk`):

   ```bash
   mkdir -p certs/liberty
   cp TestPsd2CertQWAC.crt certs/liberty/qwac.crt
   cp TestPsd2CertQSealC.crt certs/liberty/qseal.crt
   cp AltasoftPsd2RootCa.crt certs/liberty/root-ca.crt
   openssl pkcs12 -in TestPsd2CertQWAC.pfx -nocerts -out certs/liberty/qwac.key
   openssl pkcs12 -in TestPsd2CertQSealC.pfx -nocerts -out certs/liberty/qseal.key
   ```

   Each `openssl` asks for the portal password, then a new PEM pass phrase: use one pass phrase for both keys of a bank. Problems: OpenSSL 3 rejects older `.pfx` files with `unsupported algorithm`, add `-legacy`; `-nodes` instead of a pass phrase writes the key unencrypted, readable by anyone with access to the folder. `.crt` files may be PEM or DER, both are read.
3. Put the pass phrases in `.env` (`LIBERTY_CERT_PASSWORD=...`, `SILK_CERT_PASSWORD=...`), then `docker compose up -d`. This recreates the backend container so it picks up the new environment and the `certs/` mount; a run in progress is lost.

Cartu's certificate download returns 404, so `cartu-sandbox` uses Silk's files (same Alta Software platform). If Cartu refuses them, the step is reported as "could not be tested"; once Cartu's own certificate arrives, put it in `certs/cartu/` and change the paths in `targets.json`.

Bank of Georgia issued the team test certificates as two `.p12` files (QWAC for mTLS, QSealC for signing) and a test user (`BOG_OB_SBX`, OTP `4444`, in `targets.json`; its password goes in `.env` as `BOG_PSU_PASSWORD`). Export them with their chain:

```bash
mkdir -p certs/bog
openssl pkcs12 -in ATABAI-wac.p12 -nokeys -out certs/bog/qwac.crt
openssl pkcs12 -in ATABAI-wac.p12 -nocerts -out certs/bog/qwac.key
openssl pkcs12 -in ATABAI-seal.p12 -nokeys -out certs/bog/qseal.crt
openssl pkcs12 -in ATABAI-seal.p12 -nocerts -out certs/bog/qseal.key
```

Use one PEM pass phrase for both keys and put it in `.env` as `BOG_CERT_PASSWORD`. The chain inside the `.crt` files is sent in the TLS handshake and in `x5c`. If the sandbox's server certificate is not publicly trusted, the run says so; put BoG's CA in `certs/bog/root-ca.crt` (optional file).

Credo publishes its sandbox (`openbankgw.credo.ge/sandbox/0.8/v1`) and a demo user (`testclient` / `testclient`, OTP `111111`). Its token endpoint uses `client_secret_basic`, so besides the certificate in `certs/credo/` it needs `CREDO_CLIENT_ID` and `CREDO_CLIENT_SECRET` in `.env`.

TBC's test environment (`test-openbanking.tbcbank.ge`) uses the same journey: its XS2A host and token endpoint require a client certificate (`tls_client_auth`), so `tbc-test` runs it once TBC issues test certificates (`certs/tbc/`, `TBC_CERT_PASSWORD`) and a test PSU. TBC documents its API on a web portal without a downloadable spec, so the standard consent path and body are used.

The root CA is trusted for that bank's calls only, next to the public roots; it is never added system-wide.

`certs/` is git-ignored and mounted read-only. With a certificate in place, the next audit runs, after the passive probes:

- consent creation with the bank's own documented request example, over **mTLS**, signed with **Digest + x-jws-signature** (detached JWS, b64=false, sigT, sigD with the GE-JWS header list, x5c with only the signing certificate as GE-JWS §6 requires; if the bank refuses that, one retry with the chain, reported as the bank's deviation), with the QSealC (`signCert`/`signKey`; the QWAC if those are not set);
- SCA from whatever link the bank returns (`scaOAuth` metadata + PKCE, `scaRedirect`, or `startAuthorisation` first), then the bank's login pages with the demo user (forms read and filled automatically, session cookies kept);
- token exchange (OAuth case; `client_id` from `clientId` or the certificate's organizationIdentifier), consent status, accounts, balances and transactions;
- the live checks on those responses: schemas against the bank's spec, X-Request-ID echo, response seals and Digest, data quality.

Bank login pages are filled in a headless Chromium (`WITH_BROWSER=true`, the default build): it types the demo user, password and OTP, ticks account boxes, presses the approving button and stops at the redirect to `redirectUri` (intercepted, never sent). Server certificates are still verified; a bank's test CA from `credentials.ca` is accepted for that bank only (by public-key pin). With `WITH_BROWSER=false` a plain HTML form filler is used, which cannot handle JavaScript login apps.

Without a certificate the step is reported as "not run" with the reason. A refused certificate or signature, or a login page the automation cannot fill, is reported as "could not be tested" with the calls attached, never as a bank failure. The banks do not document their OAuth endpoints or login pages; the automation was built up against the real BoG, Liberty and Silk sandboxes (JavaScript login apps, one-digit OTP boxes, Georgian button labels, hidden account checkboxes, bank-specific deviations). When a login page still stops it, the call log keeps the steps (`sca.browser`) and a page summary (`sca.browser.dump`: forms, inputs, alerts, account rows), so the next fix needs no extra run. Field names, types and sizes are kept; query strings of form actions and links (session codes) and the values of hidden, password, OTP, user and other typed fields are removed, and the test user's password and OTP are scrubbed from steps and summary.

### TBC BIS - Accounts

`tbc-bis` covers TBC's Business Integration Services - Accounts on `test-api.tbcbank.ge`: a proprietary business API, judged against TBC's own documentation (and OAuth / RFC 9457 rules), never against NextGenPSD2. It gets a client-credentials token (`scope=bab_accounts`), reads movements for the last 30 days, a statement summary and a balance, sends the documented error cases (no token, account without currency, unknown account, invalid date), checks IBANs and dates, and samples latency. BIS - Transfers is never called. Set `TBC_BIS_CLIENT_ID` and `TBC_BIS_CLIENT_SECRET` in `.env` (the app's key and secret from myapps.tbcbank.ge); without them only the unauthenticated checks run.

## Guardrails

- Rules decide every verdict and score; AI output is advisory, labelled, and never scored.
- One audit at a time (`409` for the API, exit code 2 for the CLI), and at least 60 s between runs that touch real banks (`429`, `minRunIntervalSec`). Both are checked in the database, so they hold between the server and the CLI. A run still marked running after 2 hours no longer blocks.
- Runs interrupted by a server restart are marked failed ("interrupted (server restart)") when the server starts; CLI runs only once they are 2 hours old, since they may still be alive in their own process.
- Audits run on the schedule only (09:00, 15:00 and 21:00 Tbilisi time, all targets: real banks at most 3 scheduled audits per Tbilisi day, each sandbox one journey per audit). If manual runs are switched on (`schedule.manualRuns`), at most `maxRunsPerDay` (default 1) API runs per Tbilisi calendar day (`429`), counted in the database so restarts do not reset it. Scheduled and CLI runs are not counted and not limited by it.
- Production endpoints only get read-only, unauthenticated requests; active and negative tests run only on targets marked `full` (the organizers' mock). Bank sandboxes get one happy-path journey per audit with the team's test certificates (one consent, up to two accounts; a second consent only for a documented fallback such as the OAuth pre-step), plus three read-only consent-status calls that test seal enforcement (unsigned, stale sigT, future sigT).
- Certificates and keys never enter git or the database; credentials, session cookies, tokens and codes are redacted in the call log (scope under [Architecture](#architecture)).
- Outages are never read as passes or conformance failures: retries with backoff, then "could not be tested".
- Secrets are redacted before anything is stored; AI calls get finding metadata and test-environment error bodies with IBAN-like strings masked.
- The API has no CORS unless `CORS_ORIGIN` is set; the dashboard is served from the same origin.
- Every assumed threshold, target path and unverified clause is labelled as such in the dashboard and reports.

## Limitations

- The organizers' TBC mock is the only target that gets the full active suite (payments, deposits, loans, negative and security tests); real bank sandboxes get the happy-path journey only. The mock's spec marks signature, digest and request-ID headers as relaxed and it uses mock tokens, so its security results describe the mock, not TBC. The mock also injects outages on purpose ("short outages are enabled"), which shows up in reliability and uptime.
- For Liberty, Silk and Cartu, paths come from their published specs (Liberty `/0.8/v1`, Silk and Cartu `/v2`). Their OAuth endpoints and login pages are not documented, so the sandbox journey discovers them from the consent links and fills the login forms on a best-effort basis.
- Recurring and future-dated payments, deposits and loans were added to the Georgian framework after XS2A guide 0.8.RC3, so those checks map to Berlin Group conventions and are marked unverified.
- The uptime monitor only samples while the Scio server is running.
- Real banks require a client certificate (QWAC). Until a bank's certificate arrives, only its front door and published spec can be tested: latency of authenticated endpoints and most live conformance checks need the sandbox journey. JWS signatures are verified with the certificate in `x5c` and the Digest is recomputed; trust in the bank's QSealC chain is not judged (it needs the bank's CA list).
- Bank sandboxes (run of Oct 23): Liberty completes the journey (12 accounts, balances and transactions); BoG completes login and token but its authorization server only accepts the scope `openid`, so the consent stays `received`; Silk refuses to start the authorisation ("redirect URI not provided"); Cartu times out on connect (likely an IP allowlist); TBC and Credo did not issue certificates. Each stop is reported as "could not be tested" or as a bank finding, never as a pass.
- Thresholds are assumptions until NBG publishes indicators.
- TLS inspection needs a direct connection; behind an intercepting proxy it is skipped.
- AI output is advisory and never scored. Jev depends on an external API; results include the model version for traceability.
- The local 1.7B model is small: its triage is biased toward "security exposure" and its test proposals are basic, which is why code validates every proposal and every local answer goes to review.

## Third-party components

| Component | Licence |
|---|---|
| NestJS (`@nestjs/*`) | MIT |
| ajv, ajv-formats | MIT |
| undici | MIT |
| reflect-metadata, rxjs | Apache-2.0 |
| @modelcontextprotocol/sdk | MIT |
| nodemailer | MIT-0 |
| zod | MIT |
| Vue, vue-router, Vite | MIT |
| Tailwind CSS, tailwind-merge, clsx | MIT |
| class-variance-authority | Apache-2.0 |
| lucide-vue-next | ISC |
| nginx (Docker image) | BSD-2-Clause |
| playwright-core | Apache-2.0 |
| Chromium (Debian package, `WITH_BROWSER=true`) | BSD-3-Clause and bundled licences |
| Node.js official Docker image (Debian base) | MIT and others (Node.js); Debian package licences |
| Jev / TypeSafe API | commercial API, TypeSafe terms |
| @qvac/sdk (Tether) | Apache-2.0 |
| Qwen3 1.7B (GGUF by Unsloth) | Apache-2.0 |
| EmbeddingGemma 300M (GGUF by Unsloth) | Gemma terms of use |

Test targets: TBC Bank mock open banking API by the hackathon organizers; public endpoints or sandboxes of TBC Bank, Bank of Georgia, ProCredit Bank, Liberty Bank, Silk Bank, Cartu Bank and Paysera Bank Georgia (listed by NBG at https://nbg.gov.ge/en/page/open-banking-detailed-data-and-documentation).

## Team

ATABAI: Abdumalik Usmonov (CTO), Azizbek Saidov (CEO).
