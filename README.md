<!-- prettier-ignore -->
<div align="center">

<img src="./web/app/src/assets/images/ellysia/Ellysia-BgN.png" alt="Ellysia" height="110" />

# Ellysia — Security Operations Platform

[![Python 3.10+](https://img.shields.io/badge/Python-3.10-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org)
[![Flask 3.0](https://img.shields.io/badge/Flask-3.0-000?style=flat-square&logo=flask)](https://flask.palletsprojects.com)
[![Vue 3](https://img.shields.io/badge/Vue-3-42b883?style=flat-square&logo=vuedotjs&logoColor=white)](https://vuejs.org)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1?style=flat-square&logo=postgresql&logoColor=white)](https://www.postgresql.org)
[![Redis](https://img.shields.io/badge/Redis-7-DC382D?style=flat-square&logo=redis&logoColor=white)](https://redis.io)
[![Ollama](https://img.shields.io/badge/Ollama-llama3.2-ff7000?style=flat-square&logo=ollama)](https://ollama.com)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker&logoColor=white)](https://www.docker.com)

[Overview](#overview) · [Features](#features) · [Architecture](#architecture) · [Modules](#modules) · [Quick start](#quick-start) · [Authentication](#authentication) · [API reference](#api-reference) · [TaskQueue](#taskqueue-rq--redis) · [Testing](#testing) · [Continuous deployment (CI/CD)](#continuous-deployment-cicd) · [Database migrations](#database-migrations) · [Docker](#docker) · [AI & email](#ai-and-email-configuration) · [Technology stack](#technology-stack) · [Configuration](#configuration)

---

</div>

## Overview

**Ellysia** is a modular security operations platform that combines vulnerability scanning, anti-phishing email analysis (including live mailbox monitoring), encrypted credential management, infrastructure monitoring, and AI-powered security awareness training into a single server — with a multi-tenant commercial layer (plans, usage limits, organizations) on top, and web and mobile interfaces.

The REST API (Flask) orchestrates asynchronous scans and analysis over **RQ + Redis** queues, while pluggable AI backends (Ollama / OpenAI / Google Gemini) generate reports, awareness pills, and contextual verdicts. All modules share an OAuth 2.0 + JWT authentication layer with TOTP MFA, recovery codes, and fine-grained attribute-based access control.

> [!NOTE]
> **Acheron spans four sibling repositories.** The vault's crypto engine is implemented twice — [AcheronCore](https://github.com/ProjectEllysia/AcheronCore) in Java and [AcheronCoreWeb](https://github.com/ProjectEllysia/AcheronCoreWeb) in TypeScript — sharing no code, only a wire format that interop test vectors pin in both directions. [AcheronSchema](https://github.com/ProjectEllysia/AcheronSchema) holds the storable catalogue as a language-neutral contract every client verifies against. The Android app is [AcheronMobile](https://github.com/ProjectEllysia/AcheronMobile) (Kotlin/Jetpack Compose); it consumes the `/acheron` endpoints documented below, like any other client.

> [!IMPORTANT]
> The API assumes a **Linux** environment. Scan tools (Nmap, Nikto, Nuclei, traceroute) are Linux-native. On Windows, use WSL (`wsl` → `cd API && python run.py`) or `docker compose`.

## Features

- **Vulnerability scanning** — Nmap (port/OS detection), Nikto (web vulns), Nuclei (template-based), and **Lybra**, a self-built detection engine: its own TCP and UDP discovery, protocol dissectors for HTTP, SSH, FTP, SMTP/IMAP/POP3, SMB, TLS, MySQL, PostgreSQL, SQL Server, MongoDB, Redis, LDAP, RDP, VNC, SNMP, DNS, NTP, NetBIOS, mDNS, IKE and unauthenticated admin APIs (Docker, Elasticsearch, Kubernetes, etcd, Consul, Kibana); declarative checks with request chaining (extracted variables reused across requests), payload expansion (capped), and script plugins; version→confirmer promotion for high-profile CVEs; a default-credentials engine (Tomcat/Jenkins-style panels, gated behind an explicit aggressive-mode request *and* the authorized-targets registry); redacted raw-evidence capture per confirmed finding; and CPE→CVE matching against a local NVD/CISA-KEV/FIRST-EPSS knowledge base — with scheduled execution via APScheduler.
- **AI-powered PDF reports** — Scan results enriched by a pluggable LLM backend with "Controls, Not Counts" calibrated risk assessment, plus per-host traceroute. Lybra and Nuclei reports group findings by *remediable unit* rather than listing them flat — one block per affected product, carrying the single version upgrade that closes the whole block, with configuration findings kept in their own section — preceded by an index table of every group and navigable through a collapsed-by-default PDF bookmark tree.
- **Anti-phishing analysis** — 46 atomic rules across 10 rule families evaluate email headers and content (SPF, DKIM, DMARC, ARC, QR-code/quishing detection, domain impersonation, IOC extraction), producing a calibrated `Legitimate` / `Suspicious` / `Phishing` verdict with optional AI summaries.
- **Automated mailbox monitoring** — Connect Gmail or Microsoft 365 via OAuth; Iris periodically pulls new mail and analyzes it automatically, and emails the user when a connected mailbox receives phishing.
- **Encrypted credential vault** — AES-256-GCM client-side encryption with optimistic-concurrency sync. The SPA consumes the engine as `@projectellysia/acheron-core-web`; the [AcheronMobile](https://github.com/ProjectEllysia/AcheronMobile) Android app uses the Java twin, [AcheronCore](https://github.com/ProjectEllysia/AcheronCore).
- **Security awareness training** — AI generates awareness pills across dozens of topics, enriched with current alerts from INCIBE-CERT and the local vulnerability knowledge base, each with an attached quiz; campaigns deliver them to distribution lists with per-recipient tracking.
- **Infrastructure monitoring** — Lightweight agent heartbeats (CPU/memory/disk/network/processes) feed presence detection, software inventory (tagged), Lybra-powered inventory analysis, threshold-based anomaly alerting, and email notification on critical events.
- **Plans, usage limits & organizations** — A commercial layer meters usage per plan (scans, pills, campaigns, mailbox connections, assets, ...) and lets a subscriber invite members into a shared-billing organization.
- **Persistent task queue** — Background jobs survive API restarts (Redis-backed RQ), run in isolated OS processes, and support cooperative cancellation.
- **OAuth 2.0 + JWT + TOTP MFA** — Refresh tokens, token revocation, Argon2id password hashing, TOTP two-factor auth with recovery codes, role-based access with ABAC attributes, and in-app/email reminders for accounts without MFA.
- **Hardened web serving** — Security headers and HSTS applied by Caddy, which also terminates TLS and proxies the SPA and API.
- **Database migrations** — Schema changes are versioned, reversible, and applied automatically on startup via Alembic.

## Architecture

```
                ┌───────────────────────────────────────────────────────────┐
                │                    Ellysia API (Flask)                    │
                │  system · oauth · users · plans · organizations · themis  │
                │       acheron · aegis · iris · hygeia                     │
                │  ┌──────────────────────────────────────────────────┐     │
                │  │  APScheduler ──► TaskQueue (RQ + Redis)          │     │
   Web SPA ────►│  │               ┌────────────────────────────┐     │     │
  (Vue 3, Caddy)│  │               │ RQ Workers (isolated procs)│     │──►  Nmap / Nikto / Nuclei / Lybra
                │  │               │   themis.scan/report/...   │     │──►  Ollama / OpenAI / Gemini
   Android  ────►│  │               │   aegis.generate/campaign  │     │──►  NVD · CISA-KEV · FIRST-EPSS
  (Kotlin)      │  │               │   iris.analyze/ingest/...  │     │──►  INCIBE-CERT (Aegis alerts)
   Hygeia agent─►│  │               │   hygeia.notify            │     │──►  Gmail / Microsoft Graph
                │  │               └────────────────────────────┘     │     │──►  SMTP relay (herald)
                │  │  tools: scribe (AI) · herald (email)              │     │
                │  └──────────────────────────────────────────────────┘     │
                │  PostgreSQL (15432)  ·  Alembic migrations                │
                └───────────────────────────────────────────────────────────┘
```

```
Ellysia/
├── API/        # Flask backend (run.py → create_app())
│   ├── alembic/                 # Schema migrations (versioned)
│   ├── src/modules/
│   │   ├── system/              # Config, logging, TaskQueue admin, RQ worker
│   │   ├── users/               # OAuth 2.0 + JWT, TOTP MFA, user CRUD, ABAC
│   │   ├── accounts/            # Plans, usage limits, organizations (/plans, /organizations)
│   │   ├── features/            # Feature modules (themis, iris, aegis, acheron, hygeia)
│   │   ├── tools/               # Cross-cutting strategy layers
│   │   │   ├── scribe/          # AI generation abstraction (Ollama/OpenAI/Gemini)
│   │   │   └── herald/          # Email sending abstraction (SMTP)
│   │   ├── infrastructure/      # ORM plumbing (UnitOfWork, repos, sessions)
│   │   └── shared/              # Base models, exceptions, schemas, documents
│   └── tests/
├── web/
│   └── app/     # Vue 3 SPA (Vite + Pinia + Vue Router), served by Caddy
├── landing/     # Static marketing site, published to gh-pages
└── docker-compose.yml           # dev / local-ai / container profiles
```

> [!NOTE]
> `API/` and `web/` stay in the same repository on purpose: they share a deployment (one `docker-compose.yml`, one Caddy) and a routing contract — the `@api` / `@spa_bajo_prefijo_api` matchers in `web/Caddyfile` must track both `run.py:_register_blueprints` and the SPA router. `API/tests/unit/test_caddy_api_routes.py` enforces it, pinning the order of the two `handle` blocks.

## Modules

| Module | Description | Status |
|---|---|---|
| **Themis** | Nmap, Nikto, Nuclei and Lybra (self-built engine: TCP/UDP discovery, 20+ protocol dissectors, declarative and script checks) scans with PDF reports grouped by remediable unit, traceroute, scheduled execution, AI enrichment, finding triage, folders, and an authorized-targets registry. | Operational |
| **Iris** | Phishing detection via a 46-rule engine across 10 families, IOC extraction, AI summaries, PDF reports, and automated Gmail/Microsoft 365 mailbox monitoring with phishing email notifications. | Operational |
| **Acheron** | Client-encrypted credential vault with granular sync, optimistic-concurrency updates and a password generator, consumed by the web client and [AcheronMobile](https://github.com/ProjectEllysia/AcheronMobile). The API only ever stores ciphertext. | Operational |
| **Aegis** | AI-generated security awareness pills with current alerts from INCIBE-CERT and the Lybra knowledge base, quizzes, multi-format export (Markdown/HTML/JSON), and campaign delivery with per-recipient tracking. | Operational |
| **Hygeia** | Lightweight agent-based monitoring: heartbeat ingestion, presence detection, software inventory with tags, Lybra-powered inventory analysis, and threshold anomaly alerting. | Operational |
| **Accounts** | Commercial layer: plan catalog, per-key usage limits/metering, subscription lifecycle, and shared-billing organizations with invitations. | Operational |
| **Scribe** | Abstraction layer for AI generation — pluggable strategies (Ollama, OpenAI, Google Gemini) per module. | Operational |
| **Herald** | Abstraction layer for email sending — pluggable strategies (SMTP relay) per module, transversal like Scribe. | Operational |
| **Ellysia Web** | Vue 3 SPA with module hubs (Themis, Iris, Aegis, Acheron, Hygeia), scan/analysis workspaces, vault client, asset dashboard, plans & organization management, public quiz, an admin area (config, logs, queue, plans, users), and a single catalog-driven error view for HTTP failures (404 / 403 / 409 / 500 + generic codes, wired into the router, the app error handlers and Caddy's `handle_errors`). | Operational |
| **AcheronMobile** ↗ | Android app with Jetpack Compose UI, Material 3 design, and the [AcheronCore](https://github.com/ProjectEllysia/AcheronCore) Java engine for offline vault operations. Lives in [AcheronMobile](https://github.com/ProjectEllysia/AcheronMobile), not in this repository — it consumes `/acheron` over HTTP like any other client. | Operational |

## Quick start

> [!NOTE]
> Requires: Python 3.10+, Docker, PostgreSQL, Redis, Ollama (only for local AI), and scan tools (Nmap, Nikto, Nuclei).

```bash
# 1. Clone
git clone https://github.com/ProjectEllysia/EllysiaServer.git
cd EllysiaServer

# 2. Configure docker-compose (root .env, used by the containers)
cp .env.example .env    # edit POSTGRES_* and REDIS_PASSWORD

# 3. Start infrastructure (PostgreSQL 15432, Redis, Ollama)
docker compose --profile dev up -d

# 4. Configure the API
cd API
cat > .env <<EOF
JWT_SECRET_KEY=your-secret-key
MFA_ENCRYPTION_KEY=<base64 fernet key, optional until MFA is used>
POSTGRES_USER=SecOps
POSTGRES_PASSWORD=<from .env root>
POSTGRES_HOST=localhost
POSTGRES_PORT=15432
POSTGRES_DB=Ellysia
REDIS_PASSWORD=<from .env root>
CREATE_DATABASE=True
EOF

pip install -r requirements.txt
python run.py          # → http://0.0.0.0:5000

# 5. Start a background worker for async tasks (separate terminal)
python -m src.modules.system.taskqueue.worker
```

> [!TIP]
> After first boot, set `CREATE_DATABASE=False` to avoid dropping your data on the next restart. The schema is kept up-to-date automatically via Alembic migrations. `python run.py --with-worker` spawns the RQ worker as a subprocess instead of a separate terminal. `.env.example` at the repo root documents every variable, including the optional Google Gemini and Gmail/Microsoft Graph OAuth credentials.

### Web SPA (development)

```bash
cd web/app
npm install
npm run dev            # dev server on :80, proxies /oauth,/themis,... to Flask :5000
```

> [!NOTE]
> The Vite dev server binds port **80** (not 5173) and proxies API prefixes to `http://localhost:5000`, bypassing SPA subroutes like `/themis/escaneos`. With the API running in Docker, point it at the published port: `VITE_API_TARGET=http://localhost:15000` in `web/app/.env.local`. Binding port 80 may require privileges on Linux/macOS.

### Authentication

Ellysia uses OAuth 2.0 with `grant_type: password` and refresh tokens (JWT signed with PyJWT). JSON keys use **camelCase**.

```http
POST /oauth/token
Content-Type: application/json

{ "grantType": "password", "username": "root", "password": "root" }
```

**Response:**
```json
{ "access_token": "<jwt>", "token_type": "Bearer", "expires_in": 1800, "refresh_token": "<token>" }
```

> [!WARNING]
> All protected endpoints require `Authorization: Bearer <access_token>`. `POST /oauth/revoke` revokes the current token, `POST /oauth/revoke-all` invalidates all tokens for the authenticated user. If the user has TOTP MFA enabled, `/oauth/token` returns a challenge instead of tokens, resolved via `POST /oauth/mfa/verify`.

The web application checks MFA once when an authenticated session enters the SPA. If MFA is not active, it shows a dismissible toast linking to `/profile#mfa`. A daily users scheduler sends the same reminder by email to verified users without a confirmed TOTP credential, respecting `general.security.mfa.notice_interval_days` (30 days by default).

## API Reference

### Themis — vulnerability scanning

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/themis/nmap` | Port scan (supports CIDR ranges) |
| `POST` | `/themis/nikto` | Web configuration / vulnerability scan |
| `POST` | `/themis/nuclei` | Template-based scan (single host per scan) |
| `POST` | `/themis/lybra` | Self-built engine scan (own port discovery — `target` required). `timeout` (seconds) bounds the whole scan, not just port discovery: every phase checks the remaining clock, so a scan that runs out stops probing and finishes as partial instead of being killed by the queue. `aggressive: true` requests the aggressive mode (active-check families marked `mode: aggressive` in the feed, plus the default-credentials engine); it only takes effect when the target is *also* in the caller's authorized-targets registry — a double gate, since a registered target is only pre-authorized for passive scanning |
| `GET` | `/themis/scan-status?id=` | Scan status / progress: pending · running · done · cancelled |
| `POST` | `/themis/scans/<id>/cancel` | Cancel a running scan |
| `GET` | `/themis/results` · `/themis/results/<id>` | List scans (filterable, paginated) / scan detail. The Lybra listing carries per-scan counters, not every finding, and flags with `isPartial` a scan that ran out of time (or was cancelled) before covering the whole target. A failed scan carries `failureReason` — `host_unreachable`, `port_discovery_failed`, `no_results`, `orphaned`, `timeout` or `internal_error` — so the caller can tell a target that never answered from an error inside the engine; it is `null` on scans that failed before the field existed |
| `GET` | `/themis/lybra/scans/<id>/findings` | Lybra findings grouped by remediable unit (product + port), each group with its CVEs, KEV membership, worst priority and the version that closes it |
| `GET` | `/themis/findings/<id>/evidence` | The raw (redacted, hashed) response that produced a confirmed finding — 404 for a finding owned by another user |
| `PATCH` | `/themis/findings/<id>` | Set a finding's triage state with a reason: `accepted` (the risk is real and assumed — expires for review), `false_positive` (the engine was wrong — never counts as risk) or `open` |
| `GET` | `/themis/findings/false-positives` | Findings the user refuted, with the check, CPE and feed version that produced each — labelled samples for calibrating the engine |
| `GET` | `/themis/kb/status` | Per-source freshness of the NVD/KEV/EPSS/OVAL mirror: last attempt, last success, staleness and the `feedVersion` findings are stamped with |
| `GET` | `/themis/lybra/unresolved-products` | Product names the CPE matcher could not resolve, ranked by frequency and split by origin — the working document for the alias feed |
| `DELETE` | `/themis/<id>` · `/themis/scans` | Delete a scan / bulk delete |
| `GET` | `/themis/stats` · `/themis/history/hosts` · `/themis/history/stats` | Scan counters and per-host historical trends |
| `POST/GET/DELETE` | `/themis/authorized-targets[/<id>]` | Registry of IP/CIDR targets a user has authorized for deeper checks |
| `GET` | `/themis/scan/<id>/traceroute` | Cached traceroute from the server to the scan target |
| `POST` | `/themis/scan/<id>/traceroute/refresh` | Re-run the traceroute in the background |
| `POST` | `/themis/generate-pdf` | Generate PDF report (`{ "id": <scanId>, "aiReport": true }`) |
| `GET` | `/themis/document-status` · `/themis/documents` · `/themis/scan/<id>/documents` | Report status and listing |
| `GET/DELETE` | `/themis/document/<id>/download` · `/themis/document/<id>` | Download / delete a PDF |
| `POST/GET/DELETE` | `/themis/scheduled-scans[/<id>]` | Scheduled scan (cron/interval), `/permanent` removes it for good |
| `POST/GET/PUT/DELETE` | `/themis/folders[/<id>]` | Organize scans in folders |
| `POST` | `/themis/folders/<id>/scans[/batch]` | Assign scan(s) to a folder |
| `DELETE` | `/themis/folders/<id>/scans/<scan_id>` | Remove a scan from a folder |

**Nmap scan example:**

```http
POST /themis/nmap
Authorization: Bearer <token>
Content-Type: application/json

{ "target": "192.168.1.0/24", "ports": "80,443,22,8080" }
```

**Response:**

```json
{
  "message": "Escaneo(s) Nmap iniciado(s) correctamente",
  "scanIds": [1, 2, 3],
  "totalScans": 3
}
```

### Iris — anti-phishing analysis

| Method | Endpoint | Permission | Description |
|---|---|---|---|
| `POST` | `/iris/analyze` | `IRIS_CREATE` | Submit email headers/content (optional: `title`) |
| `GET` | `/iris/capabilities` | `IRIS_READ` | Server-side limits the UI must honour (max message size, min headers, accepted modes, verdict thresholds) |
| `GET` | `/iris/status?id=` | `IRIS_READ` | Analysis progress and status; carries `failureCode`/`failureReason` when the analysis failed |
| `GET` | `/iris/results` | `IRIS_READ` | List analyses (paginated) |
| `GET` | `/iris/results/<id>` | `IRIS_READ` | Full report with per-rule scores, analysis quality and detector version |
| `GET` | `/iris/results/<id>/path` | `IRIS_READ` | Which rules fired and why |
| `GET` | `/iris/results/<id>/iocs` | `IRIS_READ` | Extracted indicators of compromise |
| `GET` | `/iris/results/<id>/export` | `IRIS_READ` | Full analysis bundle (result, rules, raw if still retained, Received-path, IOCs) as a downloadable JSON file |
| `POST` | `/iris/results/<id>/reanalyze` | `IRIS_CREATE` | Re-run the current ruleset as a **new** analysis (returns the new id) |
| `POST` | `/iris/results/<id>/ai-summary` | `IRIS_CREATE` | Generate an AI plain-language summary (background task); idempotent per analysis, `?regenerate=true` forces a new one |
| `POST` | `/iris/analyze/<id>/cancel` | `IRIS_UPDATE` | Cancel a running analysis |
| `DELETE` | `/iris/results/<id>` | `IRIS_DELETE` | Delete an analysis |
| `POST` | `/iris/results/<id>/document` | `IRIS_CREATE` | Generate a PDF report for an analysis |
| `GET` | `/iris/document-status` · `/iris/documents` · `/iris/results/<id>/documents` · `/iris/document/<id>/download` | `IRIS_READ` | Report status, listing and download |
| `DELETE` | `/iris/document/<id>` | `IRIS_DELETE` | Delete a generated report |
| `GET` | `/iris/mailbox/providers` | `IRIS_READ` | Supported mailbox providers (Gmail, Microsoft 365) |
| `POST` | `/iris/mailbox/connect` | `IRIS_CREATE` | Start OAuth connection to an external mailbox |
| `GET` | `/iris/mailbox/callback` | — (public) | OAuth redirect target; CSRF-protected by a signed `state` |
| `GET` | `/iris/mailbox/connections` | `IRIS_READ` | List monitored mailboxes |
| `GET` | `/iris/mailbox/connections/<id>/folders` | `IRIS_READ` | Real folders/labels for the connected account (live provider call) |
| `PATCH` | `/iris/mailbox/connections/<id>` | `IRIS_UPDATE` | Pause, resume or reconfigure a connection (`folder` is validated against the account's real folders) |
| `DELETE` | `/iris/mailbox/connections/<id>` | `IRIS_DELETE` | Disconnect a monitored mailbox |
| `POST` | `/iris/mailbox/connections/<id>/sync` | `IRIS_UPDATE` | Trigger an out-of-cycle mailbox poll |
| `GET` | `/iris/mailbox/connections/<id>/health` | `IRIS_READ` | Connection health: last successful sync vs. last attempt, discovered/accepted/pending/retrying/dead message counts, last sync duration |
| `GET`/`PUT` | `/iris/notification-preferences` | `IRIS_READ` / `IRIS_UPDATE` | Per-user notification settings: daily digest for non-critical Phishing verdicts, temporary mute, and toggles for the reauthorization-required and stuck-sync alerts. High-confidence Phishing verdicts always notify immediately regardless of these settings |
| `GET` | `/iris/retention-policy` | `IRIS_READ` | Current retention policy (raw message / full analysis expiry, in days) plus how many of the current user's analyses still retain their raw content vs. have already had it purged |

> [!NOTE]
> **`CREATE` vs `UPDATE` in Iris.** `IRIS_CREATE` guards the operations that bring a *new* entity into existence and consume quota for it — submitting an analysis, re-analysing (which inserts a brand-new analysis and returns its id, leaving the original untouched), generating an AI summary, generating a PDF. `IRIS_UPDATE` guards changes to something that already exists: cancelling a running analysis, pausing a connection, forcing a poll. The full matrix is pinned by `API/tests/integration/test_iris_permissions.py`, which asserts both that the documented attribute opens each endpoint and that every other Iris attribute is refused.

Iris applies rules across authentication (SPF, DKIM, DMARC, ARC), header anomalies, reply-chain/thread attacks, content heuristics (including QR-code/quishing detection), and domain spoofing, producing verdicts `Legitimate` / `Suspicious` / `Phishing`. Connected mailboxes are polled periodically by the scheduler and analyzed automatically; when a monitored mailbox receives mail judged `Phishing`, the user is notified by email (`iris.notify`). Thresholds are configured in `SecOpsConfig.json`.

**Raw storage, redaction and retention (M09/B17/B19).** The raw email content (headers, or the full `.eml` in full-message mode) is stored encrypted at rest in its own table, `IrisRawMessage`, separate from the `IrisAnalysis` row that holds the queryable result (score, verdict, per-rule findings). This lets the raw content be purged on its own — after `iris.rawMessageRetentionDays` (90 by default) — without losing the analytical result, which is kept indefinitely unless `iris.analysisRetentionDays` is set to a positive number (`0` disables full deletion). A scheduled job on the same scheduler that polls mailboxes (`iris.retentionCheckIntervalHours`, 24 by default) applies this policy; `GET /iris/retention-policy` shows it, along with how many of the current user's analyses still have their raw retained. Once a given analysis's raw has been purged, `GET /iris/results/<id>/path` and `.../iocs` (both derived on demand from the raw) return `410 Gone`; the main result stays fully available. The exportable PDF report — the one view of an analysis that leaves the authenticated panel once downloaded — redacts email addresses, phone numbers and card-like numbers from the raw headers dump (`iris.redactPiiInReports`, on by default), except the sender/recipient/reply-to/return-path addresses already shown in the report's own summary, which are the evidence the report exists to show.

**Trust boundary.** `Authentication-Results` and `Received` headers are partly written by whoever sent the message: MTAs *prepend* their own `Received`, so the lower hops are supplied by the sender and can be fabricated. Iris only trusts an `Authentication-Results` whose `authserv-id` matches a hop **above** the trust boundary — the contiguous run of hops belonging to the delivering organisation, plus any verifier listed in `features.iris.data.trusted_authserv_ids` (empty by default; without it trust is derived from the chain itself). An `ARC-Seal: cv=pass` is treated as context, never as permission to suppress SPF/DMARC/alignment gates, unless a trusted verifier confirms it with `arc=pass` in its own `Authentication-Results`.

**Analysis quality.** A rule that raises does not abort the analysis, but it is no longer invisible: the report carries `analysisQuality` (`complete`/`degraded`), `failedRules` (the rules that could not *execute* — not the ones that found something) and `detectorVersion` (which rule catalogue produced the result). Losing an authentication or attachment rule prevents a `Legitimate` verdict, because those two families answer questions no other rule answers.

### Aegis — awareness and alerts

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/aegis/generate` | Generate an awareness pill (`{ topicId, tweaks: {...} }`) |
| `GET` | `/aegis/status?id=` | Generation status |
| `GET/PUT` | `/aegis/document` | Read / edit a pill (content + quiz questions) |
| `GET` | `/aegis/documents` · `/aegis/download` | List pills / download the last generated one |
| `DELETE` | `/aegis/document` | Delete a pill |
| `GET/PUT` | `/aegis/org-profile` | Organization profile: manual tracked products and/or Hygeia inventory as the alert source |
| `GET` | `/aegis/topics` · `/aegis/products` | List available topics / search CPE products from the local KB |
| `GET` | `/aegis/export/formats` | Available export formats: Markdown, HTML, JSON |
| `POST/GET` | `/aegis/export/<id>` · `/aegis/export/<id>/download` | Export a pill / download the artifact |
| `GET` | `/aegis/export/md/<id>` | Raw Markdown of a pill |
| `POST/GET/DELETE` | `/aegis/lists[/<id>]` | Distribution lists (owner) |
| `POST/GET/DELETE` | `/aegis/lists/<id>/recipients[/<rid>]` | Recipients within a list (owner) |
| `POST/GET/DELETE` | `/aegis/campaigns[/<id>]` | Create / list / detail / delete a campaign (owner) |
| `POST` | `/aegis/campaigns/<id>/launch` | Launch: snapshots the quiz, mints one opaque token per recipient, queues sending |
| `GET/POST` | `/aegis/quiz?t=<token>` | **Public, no auth** — serve/grade the quiz for one recipient. One-shot: a completed token always 409s on resubmission |

Aegis combines AI-generated awareness content with current alerts from the **INCIBE-CERT RSS feed** and the **local Lybra knowledge base** (NVD/KEV/EPSS), scoped to the products the organization tracks. Each generated pill also gets a multiple-choice quiz; a **campaign** sends the pill + quiz to a distribution list, tracking `sent → opened → completed` per recipient via `herald`.

### Acheron — credential vault

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/acheron/vault` | Retrieve vault (encrypted blob); returns `revision` and an `ETag` |
| `GET` | `/acheron/vault/revision` | Cheap probe: current `revision` only, no ciphertext |
| `POST` | `/acheron/vault` | Create the vault; on an existing one it is a **full replace** and requires `?mode=replace` + `If-Match` |
| `PATCH` | `/acheron/vault` | Partial vault metadata update |
| `GET` | `/acheron/generate-password` | Generate a random password server-side, tunable via query params |
| `POST` | `/acheron/storables` | Add an `Account` or `CreditCard` |
| `PATCH` | `/acheron/storables` | Bulk update only modified fields |
| `DELETE` | `/acheron/storables` | Delete a Storable by `internalId` |

> [!NOTE]
> Encryption happens **client-side**, in [AcheronCoreWeb](https://github.com/ProjectEllysia/AcheronCoreWeb) for the browser and [AcheronCore](https://github.com/ProjectEllysia/AcheronCore) for Android. The server stores only ciphertext. Internal IDs are deterministic SHA-256 hex hashes of encrypted content — collision-free across offline devices.

> [!IMPORTANT]
> **Optimistic concurrency.** `Vault.revision` is bumped on every content mutation and exposed as `ETag` / `revision`. Send it back as `If-Match: "N"` on writes: if it no longer matches, the write is rejected with `409 vault_revision_mismatch` (body carries `currentRevision`) and **nothing is mutated** — a client holding a stale snapshot can no longer wipe another device's edits. `If-Match` is mandatory on the destructive `POST /acheron/vault` replace; on the granular endpoints it is optional for now (transition window for already-deployed apps). Distinct from `metadataVersion`, which only tracks master-password rotation.

### Hygeia — infrastructure monitoring

| Method | Endpoint | Permission | Description |
|---|---|---|---|
| `POST` | `/hygeia/assets` | `HYGEIA_CREATE` | Register a monitored asset; returns the agent key **once** |
| `GET` | `/hygeia/assets` | `HYGEIA_READ` | List the user's assets with presence status |
| `GET` | `/hygeia/assets/<id>` | `HYGEIA_READ` | Asset detail |
| `GET` | `/hygeia/assets/<id>/metrics?from=&to=&bucket=` · `/metrics/latest` | `HYGEIA_READ` | CPU/memory/power time series (raw or bucketed, or last snapshot) for the asset's chart |
| `GET` | `/hygeia/assets/<id>/power-summary` | `HYGEIA_READ` | Current power reading plus energy/cost for 24h/7d/30d and a monthly projection, each tagged `observed`/`observed_partial`/`projected` |
| `GET` | `/hygeia/assets/<id>/inventory` | `HYGEIA_READ` | Last known installed-software inventory |
| `POST` | `/hygeia/inventory/report` | `HYGEIA_UPDATE` | Download the software inventory as a document |
| `POST/GET` | `/hygeia/assets/<id>/analyze` · `/analysis` | `HYGEIA_UPDATE` + `THEMIS_CREATE` | Run/read a Lybra-powered analysis of the asset's software inventory |
| `PATCH` | `/hygeia/assets/<id>` | `HYGEIA_UPDATE` | Set `isPersistent` — `false` marks a host that powers off on purpose, so its downtime opens no anomaly and sends no email |
| `GET/POST/DELETE` | `/hygeia/tags` · `/hygeia/tags/<id>` · `PUT /hygeia/assets/<id>/tags` | `HYGEIA_*` | Manage asset tags and tag assignments |
| `DELETE` | `/hygeia/assets/<id>` | `HYGEIA_DELETE` | Deregister an asset, revoking its agent key |
| `POST` | `/hygeia/assets/<id>/rotate-key` | `HYGEIA_UPDATE` | Rotate the agent key, invalidating the previous one |
| `GET` | `/hygeia/alerts?state=&severity=&assetId=` | `HYGEIA_READ` | List anomalies for the user's assets |
| `POST` | `/hygeia/alerts/<id>/ack` \| `/resolve` | `HYGEIA_UPDATE` | Acknowledge / resolve an anomaly |
| `DELETE` | `/hygeia/alerts/<id>` | `HYGEIA_DELETE` | Delete an anomaly |
| `POST` | `/hygeia/ingest` | agent key | Agent heartbeat (host info, CPU/memory/disk/network/processes, optional power) |

Hygeia has two separate auth surfaces: standard OAuth for the user-facing endpoints above, and a per-asset **agent key** (`@require_agent_key`, not OAuth) for `POST /hygeia/ingest` — the only endpoint an agent calls. A presence-check job marks assets `stale`/`offline` and opens a `host_down` anomaly when heartbeats stop; critical anomalies trigger an async email notification (`hygeia.notify`, via `herald`). The inventory analysis endpoint deliberately requires both a Hygeia and a Themis attribute — it's a Hygeia action that spends a Themis scan.

**Power monitoring.** The ingest contract's `metrics` block accepts an optional `power` object (`watts`, `estimated`, `source`) — an agent that doesn't send it (older agent, or hardware with no compatible sensor) is unaffected, and the three fields land in their own nullable `AssetSnapshot` columns (`power_watts`, `power_estimated`, `power_source`) rather than only in the raw JSONB, so the time series and the power summary never have to parse it back out. `NULL` means "not reported," not zero: a gap in telemetry is never averaged in as 0 W. `features.hygeia.energyPricePerKwh` (plus `energyPriceCurrency`) turns the observed average power into kWh and cost; a period is labeled `observed` only when it fits inside `retentionDays` with high data coverage, `observed_partial` when it fits but coverage is low, and `projected` whenever the requested period exceeds the retention window (a monthly/yearly cost always is, against 30 days of retention).

**Outdated-agent warning.** `GET /hygeia/assets` adds `agentOutdated` to each asset: `true` when the agent's reported `agentVersion` is strictly below `features.hygeia.minAgentVersion` (default `"0.0.0"`, which flags nothing until an operator sets a real floor), `false` when it's at or above it, and `null` whenever the comparison can't be made in good faith — the asset never reported a version, or either version string doesn't parse as strict `X.Y.Z...` (the ingest contract only length-validates `agentVersion`, so a malformed value can't be told apart from outdated-but-well-formed data; the comparator resolves that ambiguity to "unknown" rather than guessing). It's advisory only — never blocks ingestion or changes presence status.

**Virtual-machine awareness.** The ingest contract's `host` block accepts optional `virtualizationSystem`/`virtualizationRole` (populated by the agent's `gopsutil` detection), persisted the same way as `kernel` — nullable columns on `MonitoredAsset`, conserved across a heartbeat that doesn't report them. A guest has no power registers to read (they aren't virtualized), so that's not a hardware defect: when `virtualizationRole` is exactly `"guest"` and the asset has no power reading, the "no sensors" message becomes "this is a virtual machine — its host measures the power draw" instead. Any other role (`"host"`, unset, or a value the server doesn't recognize) falls back to the generic message; the comparison never requires `virtualizationRole` to match a closed list, so a newer `gopsutil` reporting an unfamiliar value can't break ingestion.

### Accounts — plans & organizations

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/plans` | **Public** — the plan catalog with per-plan limits (pricing table) |
| `GET` | `/plans/me` | Effective plan of the authenticated user and its validity |
| `GET` | `/plans/me/usage` | Current usage of the authenticated user, key by key |
| `POST` | `/organizations` | Create the caller's organization (they become the owner) |
| `GET` | `/organizations/mine` | The caller's organization, owner or member — `null` if none |
| `PUT` | `/organizations/<id>` | Rename the organization (owner) |
| `GET/DELETE` | `/organizations/<id>/members[/<userId>]` | List / remove members (owner) |
| `DELETE` | `/organizations/mine` | Leave the organization (a non-owner member) |
| `POST/GET/DELETE` | `/organizations/<id>/invitations[/<id>]` | Send / list / revoke an invitation (owner) |
| `POST` | `/organizations/invitations/accept` | **Public** — accept an invitation by opaque token |
| `GET/PUT` | `/plans/subscriptions/<userId>` | (root) Read / move a user's subscription through its lifecycle |
| `GET/POST/PUT/DELETE` | `/plans/all` · `/plans/limit-keys` · `/plans` · `/plans/<id>[/default\|/limits]` | (root) Full plan-catalog management |

A subscription with no explicit plan falls back to the default plan (seeded by migration: freemium default, plus bronze/silver/gold). Organizations share a **plan and invoice**, never data — membership only grants inherited limits, and every other module's per-user ownership filters are untouched. Usage limits are metered per key (scans, pills, campaigns, mailbox connections, assets, ...) with a configurable period (daily/monthly).

### Users and system

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/oauth/token` | Token (password or refresh_token grant); MFA-enabled users get a challenge |
| `POST` | `/oauth/revoke` · `/oauth/revoke-all` | Revoke current token / all tokens |
| `POST` | `/oauth/mfa/verify` | Resolve a TOTP challenge (code or recovery code) into tokens |
| `POST` | `/users/sign-up` | Registration (username, password, email, alias) |
| `POST` | `/users/verify-email` · `/verify-email/resend` | Confirm an account's email address |
| `POST` | `/users/password-reset/request` | **Public** — request a reset link by username or email; generic response (anti-enumeration); MFA-enabled accounts first get a challenge |
| `POST` | `/users/password-reset/mfa` | **Public** — resolve the reset challenge (TOTP or recovery code); only then is the link emailed to the account's registered address |
| `POST` | `/users/password-reset/check` · `/users/password-reset/reset` | **Public** — validate a reset link / set the new password (single-use, 30-min TTL, revokes all sessions) |
| `POST` | `/users/check-credentials` | Validate credentials without issuing tokens |
| `GET/PUT` | `/users/me` | Read / update the authenticated user's own profile |
| `GET` | `/users/me/deletion-preview` | Preview what account self-deletion would remove |
| `DELETE` | `/users/me` | Self-service account deletion |
| `PUT` | `/users/change-password` | Password change (invalidates all tokens) |
| `GET/POST/DELETE` | `/users/mfa`, `/users/mfa/totp/setup`, `/users/mfa/totp/confirm`, `/users/mfa/totp` | Check status / enroll / confirm / disable TOTP MFA |
| `GET` | `/users` · `GET/PUT/DELETE /users/<id>/attributes` | (admin/root) User list and ABAC attribute management |
| `GET` | `/users/<id>/deletion-preview` | (admin/root) Preview what deleting that user destroys — notably the organization they own |
| `DELETE` | `/users/<id>` | (admin/root) Delete another user's account; same purge as self-deletion, hierarchy enforced (an admin cannot delete an admin or the root), own account excluded |
| `GET` | `/system/say-hello` | **Public** health check, reports the API version |
| `GET` | `/system/info` · `/system/status` | (admin) App metadata / CPU-mem-disk status |
| `GET` | `/system/logs` | (admin) Paginated central log viewer — gzip+base64 page, snapshot-anchored. Windowing with `lastMinutes` (relative, resolved against the **server** clock; mutually exclusive with `from`) or `from`/`to`; severity with `level` (exact) or `minLevel` (that level and above). The response carries `levelCounts` for the window, computed *before* the level filter, plus `windowStart` |
| `GET/PUT` | `/system` | (root) Read / save `SecOpsConfig.json` (`PUT` requires `If-Match` ETag) |
| `GET` | `/system/ai/models` | (root) Models each configured AI provider currently serves — feeds the model dropdown in the config panel. Providers are queried independently: one that cannot be reached reports its error in its own row instead of failing the response |
| `GET` | `/system/tasks` · `/system/tasks/status` · `/system/tasks/<id>` | (admin) List tasks, queue status, task detail |
| `POST` | `/system/tasks/<id>/cancel` | (admin) Cancel a queued/running task |
| `PUT` | `/system/tasks/config` | (admin) Change `max_workers` (applies on worker restart) |

## TaskQueue (RQ + Redis)

Background jobs persist in Redis and survive API restarts. Workers are **isolated OS processes** (not threads), listening on the registered category queues plus `default`.

```python
from src.modules.system.taskqueue import TaskQueue
queue = TaskQueue.get_instance()
queue.submit(func, name="Scan 192.168.1.1", category="themis.scan",
             external_id="scan:42", args=[...], timeout=3600)
```

Each entry point is a `@staticmethod` on the owning module's manager class — picklable by reference, no bound state; it instantiates a fresh manager inside the worker process.

| Category | Module | Entry function | External ID |
|---|---|---|---|
| `themis.scan` | Themis | `NmapScanManager.execute_nmap_scan` (also `NiktoScanManager`, `NucleiScanManager`, `LybraEngineManager`) | `scan:<id>` |
| `themis.report` | Themis | `ThemisReportManager.execute_report_generation` | `themis-doc:<id>` |
| `themis.traceroute` | Themis | `TracerouteManager.execute_traceroute` | `themis-traceroute:<key>` |
| `aegis.generate` | Aegis | `AegisManager.execute_aegis_generation` | `aegis-doc:<id>` |
| `aegis.campaign` | Aegis | `CampaignManager.execute_campaign_send` | `aegis-campaign:<id>` |
| `iris.analyze` | Iris | `IrisManager.execute_iris_analysis` | `iris-analysis:<id>` |
| `iris.ai_summary` | Iris | `IrisManager.execute_ai_summary_generation` | `iris-ai-summary:<id>` |
| `iris.ingest` | Iris | `IrisMailboxManager.execute_sync_connection` (periodic mailbox sync) | `iris-mailbox-sync:<id>` |
| `iris.report` | Iris | `IrisReportManager.execute_report_generation` | `iris-doc:<id>` |
| `iris.notify` | Iris | `IrisPhishingNotifyManager.execute_notify_phishing` | `iris-phishing-notify:<id>` |
| `iris.notify` | Iris | `IrisDigestNotifyManager.execute_notify_digest` (daily digest of non-critical Phishing verdicts) | `iris-digest-notify:<userId>` |
| `iris.notify` | Iris | `IrisReauthNotifyManager.execute_notify_reauth` (mailbox connection needs reauthorization) | `iris-reauth-notify:<connectionId>` |
| `iris.notify` | Iris | `IrisStuckSyncNotifyManager.execute_notify_stuck` (active connection stuck without a clean sync) | `iris-stuck-sync-notify:<connectionId>` |
| `hygeia.notify` | Hygeia | `HygeiaNotifyManager.execute_notify_critical_anomaly` | `hygeia-notify:<id>` |

- **Progress reporting**: workers update `job.meta["progress"]` via `_Task(progress_callback=...)`.
- **Cooperative cancellation**: set Redis key `taskqueue:cancel:{job_id}`; workers check via `_Task.wait(cancel_check=...)` and terminate the subprocess tree.
- The `max_workers` setting is read at worker startup only — changes via `PUT /system/tasks/config` apply on the next worker restart.
- **Transactional outbox** (`system/taskqueue/outbox.py`): the naive "commit the entity, then `submit()` the job" sequence leaves a window where an API restart or a Redis blip strands the entity with no job to process it. `IrisManager.analyze()` closes that window for analysis creation and mailbox ingestion by writing a `TaskDispatch` row in the same transaction as the entity and publishing it right after, falling back to a periodic sweep (`TaskDispatchScheduler`) and a startup reconciliation pass if the immediate publish fails. Not yet applied to the other categories in the table above.
- Admin REST surface: `/system/tasks/*` (status, list, detail, cancel).

> [!WARNING]
> Workers must be running for async tasks: `python -m src.modules.system.taskqueue.worker`. They listen on category-specific queues + `default`.

## Testing

### API (pytest)

```bash
cd API
pytest                    # full suite + coverage (SQLite, external services mocked — no Postgres/Redis needed)
pytest -m unit            # fast unit tests only (no app, no DB)
pytest -m integration     # boots create_app() + test HTTP client
pytest -m oracle          # differential-oracle bench against real Docker containers (skipped in CI by default)
pytest -m postgres        # real-engine matrix (PostgreSQL + Redis); skipped unless POSTGRES_TEST_URL is set
```

The `postgres` matrix (`API/tests/postgres/`) covers the invariants SQLite cannot express — declared column lengths, foreign-key actions, real `JSONB`, races between concurrent transactions, and the Alembic chain applied to an empty database. It skips itself without the env vars, so it neither slows the fast suite nor requires containers to work on the project:

```bash
docker run -d --name pg -e POSTGRES_USER=ellysia -e POSTGRES_PASSWORD=ellysia \
  -e POSTGRES_DB=ellysia_test -p 55432:5432 postgres:15
docker run -d --name rd -p 56379:6379 redis:7
POSTGRES_TEST_URL=postgresql+psycopg2://ellysia:ellysia@localhost:55432/ellysia_test \
  REDIS_TEST_URL=redis://localhost:56379/1 python -m pytest -m postgres
```

Run it in its **own** pytest invocation. The fast suite's SQLite shim rewrites `JSONB` to generic `JSON` in the shared model metadata, so a mixed run would build the wrong schema; the fixtures detect that and skip with an explanatory message rather than assert against an imitation.

CI runs two workflows on push/PR to `main`, the `vX.Y` release branches and the `proyecto/**` integration branches: `.github/workflows/tests.yml` (two jobs — `tests`, running `python -m pytest -q -m "not oracle"` on SQLite, and `SPA suites`, running the SPA's node suites) and `.github/workflows/tests-postgres.yml` (`python -m pytest -q -m postgres`, with ephemeral PostgreSQL and Redis services). They are separate jobs on purpose — the service matrix must not slow down the cycle that runs on every push. Some tests use `xfail(strict=True)` to document real known bugs — when a bug is fixed the test XPASSes and the marker must be removed. A green push to `main` (a merged pull request) additionally triggers the automatic production deploy — see [Continuous deployment](#continuous-deployment-cicd).

A third workflow, `.github/workflows/lybra-bench.yml`, runs the `oracle` bench on a schedule (03:15 UTC) and on demand. It is separate because it brings up around twenty Docker containers and takes tens of minutes, which no per-push job can afford. Its deliverable is the numbers, not the green tick: it publishes the Lybra engine's Phase R precision, its agreement with Nmap and its false-positive rate to the run summary, and uploads the full log as an artifact.

### Web SPA (node, no framework)

```bash
cd web/app
npm test                  # all nine suites — this is what CI runs

npm run test:acheron      # schema/label correspondence + crypto interop + CRUD + sync for the Acheron vault client
npm run test:iris         # file-intake limits (the size threshold comes from GET /iris/capabilities)
npm run test:hygeia       # metric-formatting tests for the Hygeia dashboard
npm run test:polling      # usePolling composable tests
npm run test:element-width # useElementWidth composable tests
npm run test:toast        # toast-store tests
npm run test:quiz         # aegis quiz-shuffle permutation tests
npm run test:logs         # gzip log-payload decoding tests
npm run test:themis       # scan-window tests
```

The suites run on plain `node` — no framework, no browser — and exit non-zero on failure. They run in CI as the `SPA suites` job of `tests.yml`, which installs with **`pnpm install --frozen-lockfile`, exactly as `web/Dockerfile` does in production**, and then builds with Vite.

That match is deliberate and was learnt the hard way. CI used to install with `npm install` and no lockfile while production built with pnpm and a frozen one: two resolvers, two possible dependency trees, and a green CI that did not mean the image would build. It did not — a dependency change left `pnpm-lock.yaml` stale and the production build would have aborted with `ERR_PNPM_OUTDATED_LOCKFILE`. Now a `package.json` that moves without its lockfile turns CI red instead of surfacing at deploy time.

`test:acheron` no longer covers the crypto: that engine left this repository. It now lives in
[AcheronCoreWeb](https://github.com/ProjectEllysia/AcheronCoreWeb), which the SPA consumes as `@projectellysia/acheron-core-web` at an exact
pinned version, and its own CI runs the interop suites against the Java implementation in both
directions. Installing it needs a token with `read:packages` in `NODE_AUTH_TOKEN`; CI uses the
workflow's own `GITHUB_TOKEN`, which works because the package grants this repository read access.

What stays here is the half only the SPA owns: `src/acheron/storableLabels.js` holds the Spanish
labels and form hints, `storableTypes.js` composes them with the schema the package provides, and
`test:acheron` checks the two describe the same fields in both directions.

The storable catalogue itself is a contract shared by four implementations in four languages — this
API's `storable_specs.py`, the package, the Android app and the Java engine — and the exact field
keys *are* the vault JSON. [AcheronSchema](https://github.com/ProjectEllysia/AcheronSchema) holds it as a language-neutral `schema.json`, and
each client verifies its own copy against it; on the API side that is
`API/tests/unit/test_acheron_schema_contract.py`. The field *order* is deliberately not part of the
contract — the vault JSON is an object keyed by field name, not a tuple — so every client compares
sets.

## Continuous deployment (CI/CD)

Every merge to `main` is deployed automatically to the production machine, **after** the CI tests of the merged commit pass. The pipeline lives in `.github/workflows/deploy.yml` and chains to `.github/workflows/tests.yml` via the `workflow_run` trigger: when the "Tests" workflow completes with `success` on a push to `main`, the deploy job connects by SSH to the target host and runs:

```bash
cd <checkout> && \
git fetch origin && \
git reset --hard origin/main && \
docker compose --profile container up -d --build && \
docker image prune -f
```

Then it polls the public health endpoint `https://<host>/system/say-hello` as a smoke test and fails the run if the API does not answer within a few minutes.

> The deploy is strictly *after* the tests: the `workflow_run` trigger fires on the `main`-push run of "Tests", and its `branches: [main]` filter excludes the PR-triggered runs (there `head_branch` is the source branch). If the tests fail, the deploy is skipped. To deploy without waiting for CI, change the trigger to `push: branches: [main]`; nothing else needs to change.

### One-time setup

Before the first automatic deploy works:

1. **On the server** — a checkout of this repo in a fixed path (e.g. `~/ellysia`), a root `.env` with the real credentials (start from `.env.example`), and a SSH user that can run Docker without `sudo` (`usermod -aG docker <user>`). The API applies Alembic migrations automatically on startup, and the existing volumes (`ellysia_caddy_data` included) are reused, so a redeploy never re-issues certificates or drops data.
2. **A `NODE_AUTH_TOKEN` in the server's root `.env`** — the SPA image installs `@projectellysia/acheron-core-web` from GitHub Packages at build time, and that package is private. Use a token with `read:packages`. Without it, `pnpm install` fails with a 403 and the web image never builds, so the deploy dies before the containers start. Docker receives it as a **BuildKit secret**, never as an `ARG`: an `ARG` is baked into the image metadata and `docker history` shows it.
3. **First boot is manual** — a fresh server needs `CREATE_DATABASE=True` in the server's `.env` for the *very first* `docker compose --profile container up -d --build` (it seeds the root user, its ABAC attributes and the awareness topics — it is **destructive**, set it back to `False` afterwards). From then on, deploys are fully automatic.
4. **The checkout that deploy targets** — pin `DEPLOY_PATH` to the checkout the running containers came from:
   ```bash
   docker inspect Ellysia-Web --format '{{index .Config.Labels "com.docker.compose.project.working_dir"}}'
   ```
   The compose file already pins the project name (`name: ellysia`) and names the critical volumes explicitly, so running from a different directory cannot orphan volumes — but `git reset --hard` must run in the checkout you keep as canonical, and `DEPLOY_PATH` must be that one.
4. **Server → GitHub access** — the repository is private, so `git fetch` on the server needs credentials. The least-privilege option is a read-only deploy key:
   ```bash
   ssh-keygen -t ed25519 -f ~/.ssh/ellysia_deploy -N "" -C "server@ellysia"
   # add ~/.ssh/ellysia_deploy.pub to Repo → Settings → Deploy keys (read-only)
   cd ~/ellysia && git config core.sshCommand "ssh -i ~/.ssh/ellysia_deploy"
   ```
5. **CI → server SSH key** — a dedicated key for the deploy job; the public half goes in the deploy user's `authorized_keys`:
   ```bash
   ssh-keygen -t ed25519 -a 100 -f deploy_key -N "" -C "github-actions-deploy@ellysia"
   ```
6. **Repository secrets** — Settings → Secrets and variables → Actions → New repository secret:

   | Secret | Value |
   |---|---|
   | `DEPLOY_HOST` | `www.ellysia.es` — el **dominio**, no la IP del VPS (Caddy no tiene catch-all por IP, el smoke test fallaría contra la IP; la DNS ya apunta el dominio a la IP) |
   | `DEPLOY_USER` | the SSH user on the server |
   | `DEPLOY_PATH` | absolute path to the server checkout (e.g. `/home/deploy/ellysia`) |
   | `DEPLOY_KEY` | the full contents of the private `deploy_key` file |

### Notes

- **The domain is the identity, not the IP.** The workflow connects to `DEPLOY_HOST`, so changing VPS only means pointing the DNS (and `DEPLOY_HOST`) at the new IP. The first connection to the new host key is accepted automatically (`StrictHostKeyChecking=accept-new`); nothing else changes.
- **`git reset --hard origin/main`** makes the tracked files of the checkout exactly match `main`; any local modification to tracked files is discarded. The `.env` is gitignored and never touched.
- **Rollback:** push a revert to `main` (or restore a previous commit) and the next green push deploys it. Data lives in the volumes, only the images are rebuilt.
- **Manual deploy:** the workflow also has a manual trigger (Actions → "Deploy to production" → Run workflow) that deploys `main` on demand without waiting for a push — useful for a rollback or to re-run after fixing the server.
- **Renaming the "Tests" workflow breaks the trigger:** `deploy.yml` references it by name (`workflows: ["Tests"]`), and a mismatch fails silently — the tests go green and no deploy happens. The trigger line carries the same warning inline.

## Database Migrations

Ellysia uses **Alembic** for schema versioning — replacing the previous `Base.metadata.create_all()` approach that could only create new tables.

### How it works

- Every schema change is written as a script in `API/alembic/versions/`.
- The `alembic_version` table records which revision is applied.
- On every startup (`run.py → _run_migrations()`), `alembic upgrade head` runs automatically — a no-op if already up to date.
- The destructive `_init_db()` (for fresh deployments) applies migrations instead of using `create_all`.

### Daily workflow

```bash
# After changing a model (e.g. adding a column)
cd API
alembic revision --autogenerate -m "add column to User"

# Review the generated script, then apply
alembic upgrade head
```

```bash
# Check status
alembic current   # Current revision
alembic history   # Full migration history

# Rollback one step
alembic downgrade -1
```

> [!IMPORTANT]
> The initial deployment on a new host requires `CREATE_DATABASE=True` to seed the root user, its ABAC attributes, and the awareness topics. The plan catalog (freemium + bronze/silver/gold) is seeded by the accounts Alembic migration, not by `_init_db()`. On subsequent deploys, `alembic upgrade head` runs automatically and is non-destructive.

## Docker

### Profiles

| Profile | Services | Use case |
|---|---|---|
| `dev` | PostgreSQL (15432), Redis, Ollama | Local development with API on bare metal |
| `local-ai` | Ollama | Optional add-on: local LLM for any profile |
| `container` | PostgreSQL, Redis, API, worker, web | Full deployment (Caddy on 80/443) |

> [!NOTE]
> Ollama is deliberately **not** part of the `container` profile — the shipped config uses OpenAI by default, and a local LLM reserves 4–8 GB of RAM. Include it explicitly with `--profile local-ai`.

> [!NOTE]
> Production deploys on every merge to `main` are automated — see [Continuous deployment](#continuous-deployment-cicd) for the exact command the pipeline runs and the one-time setup.

```bash
# Infrastructure only (develop locally)
docker compose --profile dev up -d

# Full deployment (API + worker + web behind Caddy)
docker compose --profile container up -d

# With a local LLM inside the full deployment
docker compose --profile container --profile local-ai up -d

# With GPU support for Ollama
docker compose -f docker-compose.yml -f .docker/docker-compose.gpu-nvidia.yml --profile container --profile local-ai up -d
```

### GPU support

Ellysia ships overlay files for GPU-accelerated local AI in `.docker/`:

- `docker-compose.gpu-nvidia.yml`
- `docker-compose.gpu-intel.yml`
- `docker-compose.gpu-amd.yml`

### SSL certificates

The `container` profile serves the web app and API through **Caddy**, which terminates TLS and obtains its own certificates. There is nothing to run, no certbot to invoke, no cron entry to install: Caddy starts without one and gets it itself.

**In development** (`http://localhost`), Caddy serves plain HTTP and never talks to an ACME server. `localhost` / `127.0.0.1` are still treated as secure contexts by browsers, so the WebCrypto that Acheron's vault client depends on works normally. No self-signed certificate to generate.

**In production**, Caddy sees the domain names (`www.ellysia.es`, `api.ellysia.es`) as site addresses in `web/Caddyfile` and turns on [automatic HTTPS](https://caddyserver.com/docs/automatic-https): it requests the certificate on first start, installs it, and renews it in the background. Two prerequisites, both about the outside world rather than this repository:

- Ports **80 and 443** on the host must be reachable from the internet.
- Every name in the `Caddyfile`'s site addresses must resolve via public DNS to that host's public IP. A name that does not resolve does **not** take the others down with it — Caddy manages each name separately.

Caddy tries the challenge types it has available (HTTP-01 on port 80, TLS-ALPN-01 on 443), switches issuer (Let's Encrypt → ZeroSSL) and backs off exponentially, using **Let's Encrypt's staging environment during retries** so failed attempts do not burn the real rate limit. The `email` in the `Caddyfile`'s global block is what the issuer uses to warn about upcoming expiry; it does not have to be a domain address, any inbox someone actually reads works.

> [!WARNING]
> **The one thing that can go wrong: do not delete the `ellysia_caddy_data` volume.** It holds the issued certificates and the ACME account key. If it does not persist, Caddy re-issues on *every* restart and exhausts Let's Encrypt's duplicate-certificate limit (5 per week). It carries an explicit `name:` in `docker-compose.yml` precisely so that running Compose from a differently named directory cannot orphan it.

### Ports

| Service | Port | Note |
|---|---|---|
| Web (Caddy) | 80 / 443 | Automatic HTTPS, HTTP → HTTPS redirect, SPA + API proxy |
| API | 5000 | Container internal; published on the host as `127.0.0.1:15000` (Vite can point there via `VITE_API_TARGET`) |
| PostgreSQL | 15432 | Container maps 5432 → 15432, bound to localhost |
| Redis | 6379 | Password-protected (`REDIS_PASSWORD`), required for TaskQueue |
| Ollama | 11434 | Local LLM, optional |

## AI and Email Configuration

### AI generation (scribe module)

AI generation uses an injectable strategy chosen in `API/SecOpsConfig.json` under `tools.scribe`:

```json
"scribe": {
  "defaultStrategy": "openai",
  "maxInputTokens": 24000,
  "modules": { "themis": "openai", "aegis": "openai", "iris": "openai" },
  "resilience": { "maxRetries": 3, "retryBaseSeconds": 1.5, "breakerThreshold": 3, "breakerTimeoutSeconds": 60 },
  "strategies": {
    "ollama": { "model": "", "timeout": 300 },
    "google": { "model": "", "timeout": 120 },
    "openai": { "model": "gpt-4.1-2025-04-14", "timeout": 120 }
  }
}
```

| Strategy | Model | Use case |
|---|---|---|
| `ollama` | JSON, else env `OLLAMA_MODEL` | Local, GPU-friendly, no API cost |
| `openai` | `gpt-4.1-2025-04-14` (JSON), else env `OPENAI_MODEL` (default `gpt-4o-mini`) | Cloud, for VPS without GPU |
| `google` | JSON, else env `GOOGLE_MODEL` (default `gemini-2.0-flash`) | Cloud alternative to OpenAI |

**Changing the model does not need a redeploy.** `strategies.<provider>.model` wins over the
environment variable, and the JSON is hot-reloadable: `PUT /system` (what the config panel does)
refreshes the API process in place, the RQ worker re-reads the file per job when its mtime changed,
and the generator is built inside the job — so the next background job uses the new model. An
empty `model` means "use this provider's environment variable", which is how it behaved before the
model became configurable from the panel.

`GET /system/ai/models` asks each registered provider what it serves so the panel can offer a
dropdown instead of a free-text field; a provider that cannot be reached (missing credentials,
server down) reports its error in its own row and the field falls back to free text.

`resilience` holds what the generator does when a provider fails: retries with exponential backoff,
and the circuit breaker that stops calling a backend already known to be down. `timeout` is
per-provider because a local model is far slower than a cloud API.

Environment variables (in `API/.env` — credentials, plus the model fallbacks):

```
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=llama3.2        # fallback when the panel leaves the model empty
OPENAI_API_KEY=sk-...        # only needed if a module uses "openai"
OPENAI_MODEL=gpt-4o-mini     # fallback
OPENAI_BASE_URL=             # optional: an OpenAI-compatible endpoint (vLLM, LM Studio, a gateway)
GOOGLE_API_KEY=...           # only needed if a module/strategy uses "google"
GOOGLE_MODEL=gemini-2.0-flash  # fallback
```

### Email sending (herald module)

Transversal module for sending email — same philosophy as `scribe`: any module builds a message and hands it to `herald`, which delegates to an injectable strategy chosen per module in `API/SecOpsConfig.json` under `tools.herald`. `herald` has no knowledge of its consumers (Aegis, Hygeia, Iris, Accounts, ...).

```json
"herald": {
  "defaultStrategy": "smtp",
  "branding": { "productName": "Ellysia", "accentColor": "#d4a04a", "logoUrl": "", "supportEmail": "", "footerNote": "..." },
  "modules": { "aegis": "smtp", "hygeia": "smtp", "accounts": "smtp", "iris": "smtp" },
  "strategies": {
    "smtp": { "host": "smtp-relay.brevo.com", "port": 587, "useTls": true, "fromAddress": "awareness@ellysia.es", "fromName": "Ellysia Awareness" }
  }
}
```

| Strategy | Transport | Use case |
|---|---|---|
| `smtp` | SMTP relay (STARTTLS) | Works with any provider that exposes an SMTP endpoint — Brevo, SES, Postmark, or a self-hosted relay. |

Recommended provider for teams without existing infrastructure: **Brevo** (EU-based, RGPD-friendly, free tier around 300 emails/day) via its SMTP relay (`smtp-relay.brevo.com:587`). Amazon SES is the cheaper option once volume grows, at the cost of AWS account setup and domain verification.

Environment variables (in `API/.env`, credentials only — never in `SecOpsConfig.json`):

```
SMTP_USERNAME=your-smtp-login
SMTP_PASSWORD=your-smtp-key
```

### Mailbox OAuth (Iris connectors)

Connecting Gmail or Microsoft 365 to Iris requires OAuth app credentials, set only via environment variables:

```
GMAIL_CLIENT_ID=...
GMAIL_CLIENT_SECRET=...
GRAPH_CLIENT_ID=...
GRAPH_CLIENT_SECRET=...
GRAPH_TENANT_ID=...             # optional; "common" allows any account
IRIS_MAILBOX_ENCRYPTION_KEY=... # Fernet key that encrypts stored OAuth refresh tokens at rest
```

Iris also needs `IRIS_RAW_MESSAGE_ENCRYPTION_KEY`, which is **not** listed above because it is not a connector setting: it encrypts the raw content of every analysed email, mailbox or not. See [Encryption keys](#encryption-keys).

**What each provider's OAuth scope actually grants (B19):** Gmail uses `gmail.metadata`, a true headers-only scope — when a connection has "full message mode" off, the app never sees the message body at all, not just at the application level. Microsoft Graph has no equivalent: `Mail.Read` grants the full message body regardless of Iris's own headers-only setting, because Graph does not offer a metadata-only delegated permission for mail. With full message mode off, the Microsoft connector still only *requests* headers — it never calls for the body — but the OAuth consent itself grants more than Iris uses. This is a platform limitation, not a gap in this codebase (see `services/mailbox/microsoft.py`'s module docstring). Whichever provider is used, the raw content Iris does fetch is stored encrypted and separately from the analysis result (`IrisRawMessage`), and is purged independently of it by the retention policy — see `GET /iris/retention-policy`.

## Technology stack

| Layer | Technology |
|---|---|
| Backend | Python 3.10+ (3.11 in the container), Flask 3.0, SQLAlchemy 2.0, Flask-Smorest |
| WSGI | Gunicorn (container entrypoint, `run:create_app()`) |
| Schema management | Alembic (versioned migrations) |
| Database | PostgreSQL 16 (via psycopg2) |
| Task queue | RQ + Redis 7 |
| Authentication | OAuth 2.0 + JWT (PyJWT), TOTP MFA (pyotp) + recovery codes |
| Password hashing | Argon2id (argon2-cffi) |
| Scanning | Nmap + python-nmap, Nikto, Nuclei, Lybra (self-built engine), traceroute |
| Vulnerability data | Local Lybra KB: NVD API 2.0 · CISA KEV · FIRST EPSS · distribution advisories in OVAL/CSAF for backport verification (daily sync); INCIBE-CERT RSS for Aegis alerts |
| PDF reports | ReportLab + Pillow |
| AI / LLM | Ollama (local) / OpenAI / Google Gemini (swappable via `scribe`) |
| Mailbox connectors | Gmail API, Microsoft Graph (OAuth 2.0) |
| Email delivery | SMTP via `herald` |
| Frontend web | Vue 3 (Vite + Pinia + Vue Router) |
| Reverse proxy / TLS | Caddy 2 (automatic HTTPS, SPA serving, API proxy) |
| Vault crypto | AcheronCore: AES-256-GCM + Argon2id (fallback PBKDF2) |
| Scheduling | APScheduler (cron / interval triggers) |
| Containerization | Docker + Docker Compose |

> [!NOTE]
> The Android client (Kotlin + Jetpack Compose, Retrofit + OkHttp) lives in [AcheronMobile](https://github.com/ProjectEllysia/AcheronMobile), and the crypto engine it embeds in [AcheronCore](https://github.com/ProjectEllysia/AcheronCore).

## Configuration

Ellysia uses a layered configuration system (`API/src/modules/system/config_reading.py`, imported as `CR`):

1. **`API/SecOpsConfig.json`** — base configuration. Exactly five root entries: `appVersion`, `general` (directories, security, registration), `infrastructure` (database, redis, taskqueue), `tools` (`scribe`, `herald` strategy selection), `features` (`themis`, `aegis`, `iris`, `hygeia` per-module settings). `general.security.mfa.notice_interval_days` controls the periodic email reminder cadence.
2. **`API/.env`** — environment variables that **override** JSON values (required for the JWT secret, DB/Redis/SMTP/AI credentials, `PUBLIC_WEB_URL`).
3. **Root `.env`** — docker-compose only (Postgres, Redis credentials — not read by the API).

Config is read through frozen dataclasses bound to a branch of the tree (`@config_block`, e.g. `CR.nuclei_config().rate_limit`), not one getter per value, and cached — changes to `SecOpsConfig.json` require an app restart unless applied via `PUT /system`. Background jobs pick them up too: the worker re-reads the file per job when its mtime changed (`CR.reload_if_changed()`).

The config panel (`web/app/src/views/ConfigView.vue`) exposes every settable key of the tree — the AI and email layers, the Themis knowledge base and Lybra engine dials, JWT and MFA policy, Hygeia thresholds, limits and report palette. The one branch deliberately left out is `features.iris.data.*`: those are the anti-phishing heuristic corpora (word lists, homoglyph maps, suspicious TLDs), detection content rather than deployment settings. `API/tests/unit/test_config_view_paths.py` pins the panel's paths against the JSON — the literal ones by full path, the ones composed in a `v-for` by their fixed prefix.

### Encryption keys

Some secrets are stored **encrypted at rest**: the row in the database holds Fernet ciphertext, so reading the database directly yields nothing useful, while the application can still decrypt what it needs. (This is not Acheron, which is zero-knowledge — there the user holds the key and the server never sees plaintext.)

There is no single encryption key. Each kind of secret has its own, so compromising one does not compromise the others and each can be rotated separately. The environment variable name is derived from the purpose (`<PURPOSE>_ENCRYPTION_KEY`), so the list is exactly:

| Variable | What it protects | Required |
|---|---|---|
| `MFA_ENCRYPTION_KEY` | Each user's TOTP secret | Only if MFA is used |
| `IRIS_MAILBOX_ENCRYPTION_KEY` | OAuth refresh/access tokens of each connected mailbox | Only if a mailbox is connected |
| `IRIS_RAW_MESSAGE_ENCRYPTION_KEY` | Raw content (headers or full `.eml`) of every analysed email | **Yes, for any use of Iris** — including an email pasted by hand |

All three are Fernet keys, generated the same way, and must be **different from each other**:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

> [!WARNING]
> A missing encryption key fails **late**, not at boot: `get_encryption_key` resolves it lazily on first use, so the API starts fine and the deploy smoke test passes. The error surfaces when someone enables MFA, connects a mailbox, or analyses their first email. Set all three up front even if a feature is unused.

`JWT_SECRET_KEY` is not in this table because it signs tokens rather than encrypting stored data — but unlike these three it is required always, since without it there is no authentication.

> [!WARNING]
> `features.themis.areLocalIpsAllowed` ships as `false`, and a test pins that value (`test_the_anti_ssrf_defence_ships_enabled`): with `true`, a user can point a scan at the server's internal network or the cloud metadata endpoint. Flip it to `true` in your working copy for local development against private IPs, but do not commit it.

> [!TIP]
> Use `python -c "from src.modules.system import config_reading as CR; print(CR.get_db_credentials())"` to verify your configuration.

## Notes

- `.env` files contain credentials — **never commit them**. `API/.env` is in `.gitignore`.
- `API/src/data/` and `docs/` are gitignored (scan outputs, generated PDFs).
- PostgreSQL uses port **15432** locally (not standard 5432).
- There is a single `TaskStatus` enum, in `system/taskqueue/task.py`; `themis/services/tasks.py` imports it rather than defining its own.
- The API version is declared as `appVersion` in `SecOpsConfig.json` (currently `0.5.15`, read by `CR.get_app_version()`).
