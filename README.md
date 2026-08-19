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

[Overview](#overview) · [Features](#features) · [Architecture](#architecture) · [Modules](#modules) · [Quick start](#quick-start) · [Authentication](#authentication) · [API reference](#api-reference) · [TaskQueue](#taskqueue-rq--redis) · [Testing](#testing) · [Database migrations](#database-migrations) · [Docker](#docker) · [AI & email](#ai-and-email-configuration) · [Technology stack](#technology-stack) · [Configuration](#configuration)

---

</div>

## Overview

**Ellysia** is a modular security operations platform that combines vulnerability scanning, anti-phishing email analysis (including live mailbox monitoring), encrypted credential management, infrastructure monitoring, and AI-powered security awareness training into a single server — with a multi-tenant commercial layer (plans, usage limits, organizations) on top, and web and mobile interfaces.

The REST API (Flask) orchestrates asynchronous scans and analysis over **RQ + Redis** queues, while pluggable AI backends (Ollama / OpenAI / Google Gemini) generate reports, awareness pills, and contextual verdicts. All modules share an OAuth 2.0 + JWT authentication layer with TOTP MFA, recovery codes, and fine-grained attribute-based access control.

> [!NOTE]
> The Android companion app lives in a separate repository: [SeQ-AcheronMobile](https://github.com/gamustea/SeQ-AcheronMobile) (Kotlin/Jetpack Compose, with the AcheronCore Java crypto engine). It consumes the `/acheron` endpoints documented below.

> [!IMPORTANT]
> The API assumes a **Linux** environment. Scan tools (Nmap, Nikto, Nuclei, traceroute) are Linux-native. On Windows, use WSL (`wsl` → `cd API && python run.py`) or `docker compose`.

## Features

- **Vulnerability scanning** — Nmap (port/OS detection), Nikto (web vulns), Nuclei (template-based), and **Lybra**, a self-built detection engine with banner fingerprinting, active checks, and CPE→CVE matching against a local NVD/CISA-KEV/FIRST-EPSS knowledge base — with scheduled execution via APScheduler and an authorized-targets registry for scan governance.
- **AI-powered PDF reports** — Scan results enriched by a pluggable LLM backend with "Controls, Not Counts" calibrated risk assessment, plus per-host traceroute.
- **Anti-phishing analysis** — 46 atomic rules across 10 rule families evaluate email headers and content (SPF, DKIM, DMARC, ARC, QR-code/quishing detection, domain impersonation, IOC extraction), producing a calibrated `Legitimate` / `Suspicious` / `Phishing` verdict with optional AI summaries.
- **Automated mailbox monitoring** — Connect Gmail or Microsoft 365 via OAuth; Iris periodically pulls new mail and analyzes it automatically, and emails the user when a connected mailbox receives phishing.
- **Encrypted credential vault** — AES-256-GCM client-side encryption (AcheronCore) with optimistic-concurrency sync, consumed by the web client and the [SeQ-AcheronMobile](https://github.com/gamustea/SeQ-AcheronMobile) Android app.
- **Security awareness training** — AI generates awareness pills across dozens of topics, enriched with current alerts from INCIBE-CERT and the local vulnerability knowledge base, each with an attached quiz; campaigns deliver them to distribution lists with per-recipient tracking.
- **Infrastructure monitoring** — Lightweight agent heartbeats (CPU/memory/disk/network/processes) feed presence detection, software inventory (tagged), Lybra-powered inventory analysis, threshold-based anomaly alerting, and email notification on critical events.
- **Plans, usage limits & organizations** — A commercial layer meters usage per plan (scans, pills, campaigns, mailbox connections, assets, ...) and lets a subscriber invite members into a shared-billing organization.
- **Persistent task queue** — Background jobs survive API restarts (Redis-backed RQ), run in isolated OS processes, and support cooperative cancellation.
- **OAuth 2.0 + JWT + TOTP MFA** — Refresh tokens, token revocation, Argon2id password hashing, TOTP two-factor auth with recovery codes, role-based access with ABAC attributes.
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
| **Themis** | Nmap, Nikto, Nuclei and Lybra (self-built engine) scans with PDF reports, traceroute, scheduled execution, AI enrichment, finding triage, folders, and an authorized-targets registry. | Operational |
| **Iris** | Phishing detection via a 46-rule engine across 10 families, IOC extraction, AI summaries, PDF reports, and automated Gmail/Microsoft 365 mailbox monitoring with phishing email notifications. | Operational |
| **Acheron** | Client-encrypted credential vault with granular sync, optimistic-concurrency updates and a password generator, consumed by the web client and [SeQ-AcheronMobile](https://github.com/gamustea/SeQ-AcheronMobile). | Operational |
| **Aegis** | AI-generated security awareness pills with current alerts from INCIBE-CERT and the Lybra knowledge base, quizzes, multi-format export (Markdown/HTML/JSON), and campaign delivery with per-recipient tracking. | Operational |
| **Hygeia** | Lightweight agent-based monitoring: heartbeat ingestion, presence detection, software inventory with tags, Lybra-powered inventory analysis, and threshold anomaly alerting. | Operational |
| **Accounts** | Commercial layer: plan catalog, per-key usage limits/metering, subscription lifecycle, and shared-billing organizations with invitations. | Operational |
| **Scribe** | Abstraction layer for AI generation — pluggable strategies (Ollama, OpenAI, Google Gemini) per module. | Operational |
| **Herald** | Abstraction layer for email sending — pluggable strategies (SMTP relay) per module, transversal like Scribe. | Operational |
| **Ellysia Web** | Vue 3 SPA with module hubs (Themis, Iris, Aegis, Acheron, Hygeia), scan/analysis workspaces, vault client, asset dashboard, plans & organization management, public quiz, an admin area (config, logs, queue, plans, users), and a single catalog-driven error view for HTTP failures (404 / 403 / 409 / 500 + generic codes, wired into the router, the app error handlers and Caddy's `handle_errors`). | Operational |
| **AcheronMobile** ↗ | Android app with Jetpack Compose UI, Material 3 design, and Java crypto core for offline vault operations. Lives in [SeQ-AcheronMobile](https://github.com/gamustea/SeQ-AcheronMobile), not in this repository — it consumes `/acheron` over HTTP like any other client. | Operational |

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

## API Reference

### Themis — vulnerability scanning

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/themis/nmap` | Port scan (supports CIDR ranges) |
| `POST` | `/themis/nikto` | Web configuration / vulnerability scan |
| `POST` | `/themis/nuclei` | Template-based scan (single host per scan) |
| `POST` | `/themis/lybra` | Self-built engine scan (self-discovery or from a prior Nmap scan) |
| `GET` | `/themis/scan-status?id=` | Scan status / progress: pending · running · done · cancelled |
| `POST` | `/themis/scans/<id>/cancel` | Cancel a running scan |
| `GET` | `/themis/results` · `/themis/results/<id>` | List scans (filterable, paginated) / scan detail |
| `PATCH` | `/themis/findings/<id>` | Mark a finding's triage state (e.g. accept a risk) |
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
| `GET` | `/iris/status?id=` | `IRIS_READ` | Analysis progress and status |
| `GET` | `/iris/results` | `IRIS_READ` | List analyses (paginated) |
| `GET` | `/iris/results/<id>` | `IRIS_READ` | Full report with per-rule scores |
| `GET` | `/iris/results/<id>/path` | `IRIS_READ` | Which rules fired and why |
| `GET` | `/iris/results/<id>/iocs` | `IRIS_READ` | Extracted indicators of compromise |
| `POST` | `/iris/results/<id>/reanalyze` | `IRIS_UPDATE` | Re-run the rules engine against a stored analysis |
| `POST` | `/iris/results/<id>/ai-summary` | `IRIS_UPDATE` | Generate an AI plain-language summary (background task) |
| `POST` | `/iris/analyze/<id>/cancel` | `IRIS_UPDATE` | Cancel a running analysis |
| `DELETE` | `/iris/results/<id>` | `IRIS_DELETE` | Delete an analysis |
| `POST` | `/iris/results/<id>/document` | `IRIS_UPDATE` | Generate a PDF report for an analysis |
| `GET/DELETE` | `/iris/document-status` · `/iris/documents` · `/iris/document/<id>/download` · `/iris/document/<id>` | Report status, listing, download, delete |
| `GET` | `/iris/mailbox/providers` | `IRIS_READ` | Supported mailbox providers (Gmail, Microsoft 365) |
| `POST` | `/iris/mailbox/connect` | `IRIS_CREATE` | Start OAuth connection to an external mailbox |
| `GET` | `/iris/mailbox/callback` | — (public) | OAuth redirect target; CSRF-protected by a signed `state` |
| `GET/PATCH/DELETE` | `/iris/mailbox/connections[/<id>]` | `IRIS_*` | List, pause/resume, or disconnect a monitored mailbox |
| `POST` | `/iris/mailbox/connections/<id>/sync` | `IRIS_UPDATE` | Trigger an out-of-cycle mailbox poll |

Iris applies rules across authentication (SPF, DKIM, DMARC, ARC), header anomalies, reply-chain/thread attacks, content heuristics (including QR-code/quishing detection), and domain spoofing, producing verdicts `Legitimate` / `Suspicious` / `Phishing`. Connected mailboxes are polled periodically by the scheduler and analyzed automatically; when a monitored mailbox receives mail judged `Phishing`, the user is notified by email (`iris.notify`). Thresholds are configured in `SecOpsConfig.json`.

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
> Encryption happens **client-side** (AcheronCore — see [SeQ-AcheronMobile](https://github.com/gamustea/SeQ-AcheronMobile) for the Android implementation). The server stores only ciphertext. Internal IDs are deterministic SHA-256 hex hashes of encrypted content — collision-free across offline devices.

> [!IMPORTANT]
> **Optimistic concurrency.** `Vault.revision` is bumped on every content mutation and exposed as `ETag` / `revision`. Send it back as `If-Match: "N"` on writes: if it no longer matches, the write is rejected with `409 vault_revision_mismatch` (body carries `currentRevision`) and **nothing is mutated** — a client holding a stale snapshot can no longer wipe another device's edits. `If-Match` is mandatory on the destructive `POST /acheron/vault` replace; on the granular endpoints it is optional for now (transition window for already-deployed apps). Distinct from `metadataVersion`, which only tracks master-password rotation.

### Hygeia — infrastructure monitoring

| Method | Endpoint | Permission | Description |
|---|---|---|---|
| `POST` | `/hygeia/assets` | `HYGEIA_CREATE` | Register a monitored asset; returns the agent key **once** |
| `GET` | `/hygeia/assets` | `HYGEIA_READ` | List the user's assets with presence status |
| `GET` | `/hygeia/assets/<id>` | `HYGEIA_READ` | Asset detail |
| `GET` | `/hygeia/assets/<id>/metrics?from=&to=` · `/metrics/latest` | `HYGEIA_READ` | CPU/memory time series (or last snapshot) for the asset's chart |
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
| `POST` | `/hygeia/ingest` | agent key | Agent heartbeat (host info, CPU/memory/disk/network/processes) |

Hygeia has two separate auth surfaces: standard OAuth for the user-facing endpoints above, and a per-asset **agent key** (`@require_agent_key`, not OAuth) for `POST /hygeia/ingest` — the only endpoint an agent calls. A presence-check job marks assets `stale`/`offline` and opens a `host_down` anomaly when heartbeats stop; critical anomalies trigger an async email notification (`hygeia.notify`, via `herald`). The inventory analysis endpoint deliberately requires both a Hygeia and a Themis attribute — it's a Hygeia action that spends a Themis scan.

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
| `POST` | `/users/check-credentials` | Validate credentials without issuing tokens |
| `GET/PUT` | `/users/me` | Read / update the authenticated user's own profile |
| `GET` | `/users/me/deletion-preview` | Preview what account self-deletion would remove |
| `DELETE` | `/users/me` | Self-service account deletion |
| `PUT` | `/users/change-password` | Password change (invalidates all tokens) |
| `GET/POST/DELETE` | `/users/mfa`, `/users/mfa/totp/setup`, `/users/mfa/totp/confirm`, `/users/mfa/totp` | Check status / enroll / confirm / disable TOTP MFA |
| `GET` | `/users` · `GET/PUT/DELETE /users/<id>/attributes` | (admin/root) User list and ABAC attribute management |
| `GET` | `/system/say-hello` | **Public** health check, reports the API version |
| `GET` | `/system/info` · `/system/status` | (admin) App metadata / CPU-mem-disk status |
| `GET` | `/system/logs` | (admin) Paginated central log viewer |
| `GET/PUT` | `/system` | (root) Read / save `SecOpsConfig.json` (`PUT` requires `If-Match` ETag) |
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
| `hygeia.notify` | Hygeia | `HygeiaNotifyManager.execute_notify_critical_anomaly` | `hygeia-notify:<id>` |

> [!NOTE]
> `iris.ai_summary` has no registered queue, so its jobs run on `default` (the TaskQueue logs a warning for it).

- **Progress reporting**: workers update `job.meta["progress"]` via `_Task(progress_callback=...)`.
- **Cooperative cancellation**: set Redis key `taskqueue:cancel:{job_id}`; workers check via `_Task.wait(cancel_check=...)` and terminate the subprocess tree.
- The `max_workers` setting is read at worker startup only — changes via `PUT /system/tasks/config` apply on the next worker restart.
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
```

CI (`.github/workflows/tests.yml`) runs `python -m pytest -q -m "not oracle"` on push/PR to `main`. Some tests use `xfail(strict=True)` to document real known bugs — when a bug is fixed the test XPASSes and the marker must be removed.

### Web SPA (node, no framework)

```bash
cd web/app
npm run test:acheron      # crypto interop + CRUD + sync tests for the Acheron vault client
npm run test:hygeia       # metric-formatting tests for the Hygeia dashboard
npm run test:polling      # usePolling composable tests
npm run test:quiz         # aegis quiz-shuffle permutation tests
npm run test:logs         # gzip log-payload decoding tests
```

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
  "modules": { "themis": "openai", "aegis": "openai" },
  "strategies": {
    "google": { "model": "" },
    "openai": { "model": "gpt-4.1-2025-04-14" }
  }
}
```

| Strategy | Model | Use case |
|---|---|---|
| `ollama` | `llama3.2` (env default) | Local, GPU-friendly, no API cost |
| `openai` | `gpt-4.1-2025-04-14` (JSON default; env `OPENAI_MODEL` overrides, default `gpt-4o-mini`) | Cloud, for VPS without GPU |
| `google` | `gemini-2.0-flash` (env default) | Cloud alternative to OpenAI |

Environment variables (in `API/.env`):

```
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=llama3.2
OPENAI_API_KEY=sk-...        # only needed if a module uses "openai"
OPENAI_MODEL=gpt-4o-mini
GOOGLE_API_KEY=...           # only needed if a module/strategy uses "google"
GOOGLE_MODEL=gemini-2.0-flash
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
| Vulnerability data | Local Lybra KB: NVD API 2.0 · CISA KEV · FIRST EPSS (daily sync); INCIBE-CERT RSS for Aegis alerts |
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
> The Android client (Kotlin + Jetpack Compose, Retrofit + OkHttp) and the AcheronCore engine it embeds now live in [SeQ-AcheronMobile](https://github.com/gamustea/SeQ-AcheronMobile).

## Configuration

Ellysia uses a layered configuration system (`API/src/modules/system/config_reading.py`, imported as `CR`):

1. **`API/SecOpsConfig.json`** — base configuration. Exactly five root entries: `appVersion`, `general` (directories, security, registration), `infrastructure` (database, redis, taskqueue), `tools` (`scribe`, `herald` strategy selection), `features` (`themis`, `aegis`, `iris`, `hygeia` per-module settings).
2. **`API/.env`** — environment variables that **override** JSON values (required for the JWT secret, DB/Redis/SMTP/AI credentials, `PUBLIC_WEB_URL`).
3. **Root `.env`** — docker-compose only (Postgres, Redis credentials — not read by the API).

Config is read through frozen dataclasses bound to a branch of the tree (`@config_block`, e.g. `CR.nuclei_config().rate_limit`), not one getter per value, and cached — changes to `SecOpsConfig.json` require an app restart unless applied via `PUT /system`. Background jobs pick them up too: the worker re-reads the file per job when its mtime changed (`CR.reload_if_changed()`).

> [!WARNING]
> `features.themis.areLocalIpsAllowed` is set to `true` in the shipped `SecOpsConfig.json` so local development against private IPs works. **Revert it to `false` before any real deployment**, or the anti-SSRF defense stays disabled in production.

> [!TIP]
> Use `python -c "from src.modules.system import config_reading as CR; print(CR.get_db_credentials())"` to verify your configuration.

## Notes

- `.env` files contain credentials — **never commit them**. `API/.env` is in `.gitignore`.
- `API/src/data/` and `docs/` are gitignored (scan outputs, generated PDFs).
- PostgreSQL uses port **15432** locally (not standard 5432).
- `themis/services/tasks.py` defines its own `TaskStatus` enum — distinct from `taskqueue.TaskStatus`. Don't conflate them.
- The API version is declared as `appVersion` in `SecOpsConfig.json` (currently `0.5.6`, read by `CR.get_app_version()`).
