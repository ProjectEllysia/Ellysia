<!-- prettier-ignore -->
<div align="center">

<img src="./web/app/src/assets/images/ellysia/Ellysia-BgN.png" alt="Ellysia" height="110" />

# Ellysia — Security Operations Platform

[![Python 3.10+](https://img.shields.io/badge/Python-3.10-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org)
[![Flask 3.0](https://img.shields.io/badge/Flask-3.0-000?style=flat-square&logo=flask)](https://flask.palletsprojects.com)
[![Vue 3](https://img.shields.io/badge/Vue-3-42b883?style=flat-square&logo=vuedotjs&logoColor=white)](https://vuejs.org)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1?style=flat-square&logo=postgresql&logoColor=white)](https://www.postgresql.org)
[![Ollama](https://img.shields.io/badge/Ollama-llama3.2-ff7000?style=flat-square&logo=ollama)](https://ollama.com)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker&logoColor=white)](https://www.docker.com)

[Overview](#overview) · [Features](#features) · [Architecture](#architecture) · [Modules](#modules) · [Quick start](#quick-start) · [Testing](#testing) · [API reference](#api-reference) · [TaskQueue](#taskqueue-rq--redis) · [Docker](#docker) · [Stack](#technology-stack) · [Configuration](#configuration)

---

</div>

## Overview

**Ellysia** is a modular security operations platform that combines vulnerability scanning, anti-phishing email analysis (including live mailbox monitoring), encrypted credential management, infrastructure monitoring, and AI-powered security awareness training into a single server — with a multi-tenant commercial layer (plans, usage limits, organizations) on top, and web and mobile interfaces.

The REST API (Flask) orchestrates asynchronous scans and analysis over **RQ + Redis** queues, while pluggable AI backends (Ollama / OpenAI / Google Gemini) generate reports, awareness pills, and contextual verdicts. All modules share an OAuth 2.0 + TOTP MFA authentication layer with fine-grained attribute-based access control.

> [!NOTE]
> The Android companion app lives in a separate repository: [SeQ-AcheronMobile](https://github.com/gamustea/SeQ-AcheronMobile) (Kotlin/Jetpack Compose, with the AcheronCore Java crypto engine). It consumes the `/acheron` endpoints documented below.

> [!IMPORTANT]
> The API assumes a **Linux** environment. Scan tools (Nmap, Nikto, Nuclei) are Linux-native. On Windows, use WSL (`wsl` → `cd API && python run.py`) or `docker compose`.

## Features

- **Vulnerability scanning** — Nmap (port/OS detection), Nikto (web vulns), Nuclei (template-based), and Lybra, a self-built detection engine (own CPE→CVE matcher, active checks, finding lifecycle/triage), with scheduled execution via APScheduler and an authorized-targets registry for scan governance.
- **AI-powered PDF reports** — Scan results enriched by a pluggable LLM backend with "Controls, Not Counts" risk assessment.
- **Anti-phishing analysis** — 37+ atomic rules evaluate email headers and content (SPF, DKIM, DMARC, QR-code/quishing detection, domain impersonation, IOC extraction), plus optional AI summaries, producing a calibrated verdict.
- **Automated mailbox monitoring** — Connect Gmail or Microsoft 365 via OAuth; Iris periodically pulls new mail from a chosen folder and analyzes it without manual header submission.
- **Encrypted credential vault** — AES-256-GCM client-side encryption (AcheronCore), with optimistic-concurrency sync consumed by the web client and the [SeQ-AcheronMobile](https://github.com/gamustea/SeQ-AcheronMobile) Android app.
- **Security awareness training** — AI generates awareness pills across dozens of topics with current CVE alerts from INCIBE-CERT / CIRCL / NVD, each with an attached quiz, and campaign delivery with per-recipient tracking.
- **Infrastructure monitoring** — Lightweight agent heartbeats (CPU/memory/disk/network/processes) feed presence detection, software inventory, threshold-based anomaly alerting, and email notification on critical events.
- **Plans, usage limits & organizations** — A commercial layer meters usage per plan (scans, pills, campaigns, mailbox connections, ...), and lets a subscriber invite members into a shared-billing organization.
- **Persistent task queue** — Background jobs survive API restarts (Redis-backed RQ), run in isolated OS processes, and support cooperative cancellation.
- **OAuth 2.0 + JWT + TOTP MFA** — Refresh tokens, global revocation, Argon2id password hashing, role-based access with ABAC attributes, optional time-based one-time-password two-factor auth.
- **Database migrations** — Schema changes are versioned, reversible, and applied automatically on startup via Alembic.

## Architecture

```
                ┌───────────────────────────────────────────────────────────┐
                │                    Ellysia API (Flask)                    │
                │  system · oauth · users · accounts · themis · acheron ·   │
                │       iris · aegis · hygeia · scribe · herald             │
                │  ┌──────────────────────────────────────────────────┐     │
                │  │  APScheduler ──► TaskQueue (RQ + Redis)          │     │
   Web SPA ────►│  │               ┌────────────────────────────┤     │     │
  (Vue 3)       │  │               │ RQ Workers (isolated procs)│     │──►  Nmap / Nikto / Nuclei / Lybra
                │  │               │   themis.scan/report/...  │     │──►  Ollama / OpenAI / Gemini
  Android  ────►│  │               │   aegis.generate/campaign │     │──►  INCIBE-CERT · CIRCL · NVD
  (Kotlin)      │  │               │   iris.analyze/ingest/... │     │──►  Gmail / Microsoft Graph
  Hygeia agent─►│  │               │   hygeia.notify             │     │──►  SMTP relay (herald)
                │  │               └────────────────────────────┘     │     │
                │  └──────────────────────────────────────────────────┘     │
                │  PostgreSQL (15432)  ·  Alembic migrations                │
                └───────────────────────────────────────────────────────────┘
```

```
Ellysia/
├── API/        # Flask backend (run.py → create_app())
│   ├── alembic/                 # Schema migrations (versioned)
│   ├── src/modules/
│   │   ├── system/              # Config, logging, task queue admin
│   │   ├── users/               # OAuth 2.0 + JWT, TOTP MFA, user CRUD, ABAC
│   │   ├── accounts/             # Plans, usage limits, subscriptions, organizations
│   │   ├── features/            # Feature modules (themis, iris, aegis, acheron, hygeia)
│   │   │   ├── themis/          # Scan orchestration (Nmap/Nikto/Nuclei/Lybra)
│   │   │   ├── iris/            # Email analysis (rules engine + mailbox connectors)
│   │   │   ├── aegis/           # Awareness pills + CVE alerts + campaigns
│   │   │   ├── acheron/         # Encrypted credential vault
│   │   │   └── hygeia/          # Asset monitoring (agent heartbeats, anomalies)
│   │   ├── tools/               # Cross-cutting strategy layers
│   │   │   ├── scribe/          # AI generation abstraction layer
│   │   │   └── herald/          # Email sending abstraction layer
│   │   ├── infrastructure/      # ORM plumbing (UnitOfWork, repos)
│   │   └── shared/               # Base models, exceptions, schemas
│   └── tests/
├── web/
│   └── app/    # Vue 3 SPA (Vite + Pinia + Vue Router)
├── landing/    # Static marketing site (standalone, not proxied by the API)
└── docker-compose.yml
```

> [!NOTE]
> The Android client (`AcheronMobile`, Kotlin/Jetpack Compose) and its `AcheronCore` Java crypto engine were split out into [SeQ-AcheronMobile](https://github.com/gamustea/SeQ-AcheronMobile).

## Modules

| Module | Description | Status |
|---|---|---|
| **Themis** | Nmap, Nikto, Nuclei and Lybra (self-built engine) scans with PDF reports, scheduled execution, AI enrichment, finding triage, and an authorized-targets registry. | Operational |
| **Iris** | Phishing detection via a multi-family email analysis rules engine, IOC extraction, AI summaries, and automated Gmail/Microsoft 365 mailbox monitoring. | Operational |
| **Acheron** | Client-encrypted credential vault with granular sync, optimistic-concurrency updates and a password generator, consumed by the web client and [SeQ-AcheronMobile](https://github.com/gamustea/SeQ-AcheronMobile). | Operational |
| **Aegis** | AI-generated security awareness pills with real-time CVE alerts, multi-format export, and campaign delivery to distribution lists with per-recipient quiz tracking. | Operational |
| **Hygeia** | Lightweight agent-based monitoring: heartbeat ingestion, presence detection, software inventory, Lybra-powered inventory analysis, and threshold anomaly alerting. | Operational |
| **Accounts** | Commercial layer: plan catalog, per-key usage limits/metering, subscription lifecycle, and shared-billing organizations with invitations. | Operational |
| **Scribe** | Abstraction layer for AI generation — pluggable strategies (Ollama, OpenAI, Google Gemini) per module. | Operational |
| **Herald** | Abstraction layer for email sending — pluggable strategies (SMTP relay) per module, transversal like Scribe. | Operational |
| **Ellysia Web** | Vue 3 SPA with hub dashboard, scan management, analysis viewer, vault client, asset monitoring dashboard, plans/organization management, and admin panel. | Operational |
| **AcheronMobile** ↗ | Android app with Jetpack Compose UI, Material 3 design, and Java crypto core for offline vault operations. Lives in [SeQ-AcheronMobile](https://github.com/gamustea/SeQ-AcheronMobile), not in this repository — it consumes `/acheron` over HTTP like any other client. | Operational |

## Quick start

> [!NOTE]
> Requires: Python 3.10+, Docker, PostgreSQL, Redis, Ollama (for local AI), and scan tools (Nmap, Nikto, Nuclei).

```bash
# 1. Clone
git clone https://github.com/ProjectEllysia/Ellysia.git
cd Ellysia

# 2. Start infrastructure (PostgreSQL 15432, Redis, Ollama)
docker compose --profile dev up -d

# 3. Configure the API
cd API
cat > .env <<EOF
JWT_SECRET_KEY=your-secret-key
JWT_ALGORITHM=HS256
POSTGRES_USER=SecOps
POSTGRES_PASSWORD=<from .env root>
POSTGRES_HOST=localhost
POSTGRES_PORT=15432
POSTGRES_DB=Ellysia
CREATE_DATABASE=True
EOF

pip install -r requirements.txt
python run.py          # → http://0.0.0.0:5000

# 4. Start a background worker for async tasks
python -m src.modules.system.taskqueue.worker
```

> [!TIP]
> After first boot, set `CREATE_DATABASE=False` to avoid dropping your data on the next restart. The schema is kept up-to-date automatically via Alembic migrations. `.env.example` at the repo root documents every available variable, including the optional Google Gemini and Gmail/Microsoft Graph OAuth credentials.

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
> All protected endpoints require `Authorization: Bearer <access_token>`. `POST /oauth/revoke-all` invalidates all tokens for the authenticated user. If the user has TOTP MFA enabled, `/oauth/token` returns a challenge instead of tokens, resolved via `POST /oauth/mfa/verify`.

## Testing

### API (pytest)

```bash
cd API
pytest                    # full suite + coverage (SQLite, external services mocked — no Postgres/Redis needed)
pytest -m unit             # fast unit tests only (no app, no DB)
pytest -m integration      # boots create_app() + test HTTP client
pytest -m oracle           # differential-oracle bench against real Docker containers (skipped in CI by default)
```

### Web SPA (node)

```bash
cd web/app
npm run test:acheron      # crypto interop + CRUD tests for the Acheron vault client
npm run test:hygeia       # metric-formatting tests for the Hygeia dashboard
npm run test:polling      # usePolling composable tests
```

## API Reference

### Themis — vulnerability scanning

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/themis/nmap` | Port scan (supports CIDR ranges) |
| `POST` | `/themis/nikto` | Web configuration / vulnerability scan |
| `POST` | `/themis/nuclei` | Template-based scan (single host per scan) |
| `POST` | `/themis/lybra` | Self-built engine scan (self-discovery or from a prior Nmap scan) |
| `GET` | `/themis/results` | List scans (filterable, paginated) |
| `GET` | `/themis/results/<id>` | Scan detail |
| `PATCH` | `/themis/findings/<id>` | Mark a finding's triage state (e.g. accept a risk) |
| `GET` | `/themis/scan-status?id=` | Status: pending / running / done / cancelled |
| `POST` | `/themis/scans/<id>/cancel` | Cancel a running scan |
| `DELETE` | `/themis/<id>` | Delete a scan |
| `GET` | `/themis/stats` / `/themis/history/hosts` / `/themis/history/stats` | Scan counters and per-host historical trends |
| `POST/GET/DELETE` | `/themis/authorized-targets[/<id>]` | Registry of IP/CIDR targets a user has authorized for deeper checks |
| `POST` | `/themis/generate-pdf` | Generate PDF report (`{ "id": <scanId>, "aiReport": true }`) |
| `GET` | `/themis/document/<id>/download` | Download PDF |
| `POST/GET/DELETE` | `/themis/scheduled-scans[/<id>]` | Scheduled scan (cron/interval) |
| `GET/POST/PUT/DELETE` | `/themis/folders[/<id>]` | Organize scans in folders |

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
| `GET` | `/iris/results/<id>` | `IRIS_READ` | Full report with per-rule scores |
| `GET` | `/iris/results/<id>/iocs` | `IRIS_READ` | Extracted indicators of compromise |
| `POST` | `/iris/results/<id>/reanalyze` | `IRIS_UPDATE` | Re-run the rules engine against a stored analysis |
| `POST` | `/iris/results/<id>/ai-summary` | `IRIS_UPDATE` | Generate an AI plain-language summary of the verdict |
| `POST` | `/iris/analyze/<id>/cancel` | `IRIS_UPDATE` | Cancel a running analysis |
| `DELETE` | `/iris/results/<id>` | `IRIS_DELETE` | Delete an analysis |
| `GET` | `/iris/mailbox/providers` | `IRIS_READ` | Supported mailbox providers (Gmail, Microsoft 365) |
| `POST` | `/iris/mailbox/connect` | `IRIS_CREATE` | Start OAuth connection to an external mailbox |
| `GET` | `/iris/mailbox/callback` | — (public) | OAuth redirect target; CSRF-protected by a signed `state` |
| `GET/PATCH/DELETE` | `/iris/mailbox/connections[/<id>]` | `IRIS_*` | List, pause/resume, or disconnect a monitored mailbox |
| `POST` | `/iris/mailbox/connections/<id>/sync` | `IRIS_UPDATE` | Trigger an out-of-cycle mailbox poll |

Iris applies dozens of rules across authentication (SPF, DKIM, DMARC, ARC), header anomalies, reply-chain/thread attacks, content heuristics (including QR-code/quishing detection), and domain spoofing, producing verdicts `Legitimate` / `Suspicious` / `Phishing`. Connected mailboxes are polled periodically by the scheduler and analyzed automatically, with no manual header paste required. Thresholds are configured in `SecOpsConfig.json`.

### Aegis — awareness and alerts

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/aegis/generate` | Generate an awareness pill (`{ topicId, twecks: {...} }`) |
| `GET` | `/aegis/status?id=` | Generation status |
| `GET/PUT` | `/aegis/org-profile` | Organization profile used to personalize generated content |
| `GET` | `/aegis/export/formats` | Available export formats (Markdown, JSON today; PDF/HTML planned) |
| `POST` | `/aegis/export/<id>` | Export a pill in the given format |
| `GET` | `/aegis/topics` / `/aegis/products` | List available topics / tracked technology brands |
| `GET/DELETE` | `/aegis/documents[/<id>]` | List / detail / delete |
| `POST/GET/DELETE` | `/aegis/lists[/<id>]` | Distribution lists (owner) |
| `POST/GET/DELETE` | `/aegis/lists/<id>/recipients[/<id>]` | Recipients within a list (owner) |
| `POST/GET/DELETE` | `/aegis/campaigns[/<id>]` | Create/list/detail/delete a campaign (owner) |
| `POST` | `/aegis/campaigns/<id>/launch` | Launch: snapshots the quiz, mints one opaque token per recipient, queues sending |
| `GET/POST` | `/aegis/quiz?t=<token>` | **Public, no auth** — serve/grade the quiz for one recipient. One-shot: a completed token always 409s on resubmission |

Aegis combines AI-generated awareness content with current CVE alerts from INCIBE-CERT and CIRCL/NVD across a set of tracked technology brands. Each generated pill also gets a multiple-choice quiz; a **campaign** sends the pill + quiz to a distribution list, tracking `sent → opened → completed` per recipient via `herald`.

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
| `GET` | `/hygeia/assets/<id>/metrics?from=&to=` | `HYGEIA_READ` | CPU/memory time series for the asset's chart |
| `GET` | `/hygeia/assets/<id>/inventory` | `HYGEIA_READ` | Last known installed-software inventory |
| `POST/GET` | `/hygeia/assets/<id>/analyze` / `/analysis` | `HYGEIA_UPDATE` + `THEMIS_CREATE` | Run/read a Lybra-powered analysis of the asset's software inventory |
| `PATCH` | `/hygeia/assets/<id>` | `HYGEIA_UPDATE` | Set `isPersistent` — `false` marks a host that powers off on purpose, so its downtime opens no anomaly and sends no email |
| `DELETE` | `/hygeia/assets/<id>` | `HYGEIA_DELETE` | Deregister an asset, revoking its agent key |
| `POST` | `/hygeia/assets/<id>/rotate-key` | `HYGEIA_UPDATE` | Rotate the agent key, invalidating the previous one |
| `GET` | `/hygeia/alerts?state=&severity=&assetId=` | `HYGEIA_READ` | List anomalies for the user's assets |
| `POST` | `/hygeia/alerts/<id>/ack` \| `/resolve` | `HYGEIA_UPDATE` | Acknowledge / resolve an anomaly |
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
| `GET/POST/PUT/DELETE` | `/plans/all`, `/plans`, `/plans/<id>[/default\|/limits]` | (root) Full plan-catalog management |

A subscription with no explicit plan falls back to the default plan. Organizations share a **plan and invoice**, never data — membership only grants inherited limits, and every other module's per-user ownership filters are untouched. Usage limits are metered per key (scans, pills, campaigns, mailbox connections, assets, ...) with a configurable period (daily/monthly), catalogued via `/plans/limit-keys`.

### Users and system

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/users/sign-up` | Registration (username, password, email, alias) |
| `POST` | `/users/verify-email` / `/verify-email/resend` | Confirm an account's email address |
| `GET/PUT` | `/users/me` | Read / update the authenticated user's own profile |
| `GET` | `/users/me/deletion-preview` | Preview what account self-deletion would remove |
| `DELETE` | `/users/me` | Self-service account deletion |
| `PUT` | `/users/change-password` | Password change (invalidates all tokens) |
| `GET/POST/DELETE` | `/users/mfa`, `/users/mfa/totp/setup`, `/users/mfa/totp/confirm`, `/users/mfa/totp` | Check status / enroll / confirm / disable TOTP MFA |
| `GET` | `/system/tasks` | (admin) List tasks in the RQ queue |
| `POST` | `/system/tasks/<id>/cancel` | (admin) Cancel a queued task |

## TaskQueue (RQ + Redis)

Background jobs persist in Redis and survive API restarts. Workers are **isolated OS processes** (not threads).

```python
from src.modules.system.taskqueue import TaskQueue
queue = TaskQueue.get_instance()
queue.submit(func, name="Scan 192.168.1.1", category="themis.scan", external_id="scan:42", args=[...])
```

**Categories and entry points:**

Each entry point is a `@staticmethod` on the owning module's manager class — picklable by reference, no bound state; it instantiates a fresh manager inside the worker process.

| Category | Module | Entry function |
|---|---|---|
| `themis.scan` | Themis | `managers.NmapScanManager.execute_nmap_scan` (also `NiktoScanManager`, `NucleiScanManager`, `LybraEngineManager`) |
| `themis.report` | Themis | `managers.ThemisReportManager.execute_report_generation` |
| `themis.traceroute` | Themis | `managers.TracerouteManager.execute_traceroute` |
| `aegis.generate` | Aegis | `managers.AegisManager.execute_aegis_generation` |
| `aegis.campaign` | Aegis | `managers.CampaignManager.execute_campaign_send` |
| `iris.analyze` | Iris | `managers.IrisManager.execute_iris_analysis` |
| `iris.report` | Iris | `managers.IrisReportManager.execute_report_generation` |
| `iris.ingest` | Iris | `managers.IrisMailboxManager` — periodic mailbox sync |
| `hygeia.notify` | Hygeia | `managers.HygeiaNotifyManager.execute_notify_critical_anomaly` |

- **Progress reporting**: workers update `job.meta["progress"]` via `_Task(progress_callback=...)`.
- **Cooperative cancellation**: set Redis key `taskqueue:cancel:{job_id}`; workers check via `_Task.wait(cancel_check=...)`.
- **External IDs** follow the pattern `scan:<id>`, `themis-doc:<id>`, `aegis-doc:<id>`, `aegis-campaign:<id>`, `iris-analysis:<id>`, `hygeia-notify:<id>`.

> [!WARNING]
> Workers must be running for async tasks: `python -m src.modules.system.taskqueue.worker`. They listen on category-specific queues + `default`.

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
> The initial deployment on a new host requires `CREATE_DATABASE=True` to seed the root user, topics, and the default plan. On subsequent deploys, `alembic upgrade head` runs automatically and is non-destructive.

## Docker

### Profiles

| Profile | Services | Use case |
|---|---|---|
| `dev` | PostgreSQL (15432), Redis, Ollama | Local development with API on bare metal |
| `container` | Infrastructure + API, worker, web | Full deployment |

```bash
# Infrastructure only (develop locally)
docker compose --profile dev up -d

# Full deployment
docker compose --profile container up -d

# With GPU support for Ollama
docker compose -f docker-compose.yml -f docker-compose.gpu-nvidia.yml --profile container up -d
```

### GPU support

Ellysia ships overlay files for GPU-accelerated local AI:

- `docker-compose.gpu-nvidia.yml`
- `docker-compose.gpu-intel.yml`
- `docker-compose.gpu-amd.yml`

### SSL certificates

The `container` profile serves the web app and API through **Caddy**, which
terminates TLS and obtains its own certificates. There is nothing to run, no
certbot to invoke, no cron entry to install, and no certificate to copy
anywhere: Caddy starts without one and gets it itself.

**In development** (`http://localhost`), Caddy serves plain HTTP and never
talks to an ACME server at all. `localhost` and `127.0.0.1` are still treated
as secure contexts by browsers, so the WebCrypto that Acheron's vault client
depends on works normally. No self-signed certificate to generate.

**In production**, Caddy sees the domain names as site addresses in
`web/Caddyfile` and turns on
[automatic HTTPS](https://caddyserver.com/docs/automatic-https): it requests
the certificate on first start, installs it, and renews it in the background
for the rest of its life. Two prerequisites, both of them about the outside
world rather than about this repository:

- Ports **80 and 443** on the host must be reachable from the internet (check
  the cloud provider's security group / any NAT rule in front of the VM, not
  just the local firewall).
- Every name in the `Caddyfile`'s site addresses must resolve via public DNS to
  that host's public IP. Unlike certbot, a name that does not resolve does
  **not** take the others down with it — Caddy manages each name separately.

Caddy tries the challenge types it has available (HTTP-01 on port 80,
TLS-ALPN-01 on 443, which needs no port 80 at all) and learns which one works
in that environment. On failure it retries, switches challenge type, switches
issuer (Let's Encrypt → ZeroSSL) and backs off exponentially, **using Let's
Encrypt's staging environment during the retries** so failed attempts do not
burn the real rate limit.

The `email` in the `Caddyfile`'s global block is what Let's Encrypt uses to
warn about upcoming expiry if renewal ever silently fails. It does not have to
be a domain address; any inbox someone actually reads works.

> [!WARNING]
> **The one thing that can go wrong: do not delete the `ellysia_caddy_data`
> volume.** It holds the issued certificates and the ACME account key. If it
> does not persist, Caddy re-issues on *every* restart and exhausts Let's
> Encrypt's duplicate-certificate limit (5 per week), leaving the site without
> valid TLS until the window rolls over. It carries an explicit `name:` in
> `docker-compose.yml` precisely so that running Compose from a differently
> named directory cannot orphan it.

### Ports

| Service | Port | Note |
|---|---|---|
| Web (Caddy) | 80 / 443 | Automatic HTTPS, HTTP → HTTPS redirect, SPA + API proxy |
| API | 5000 | `0.0.0.0:5000` (HTTP internally) |
| PostgreSQL | 15432 | Container maps 5432 → 15432 |
| Redis | 6379 | Required for TaskQueue |
| Ollama | 11434 | Local LLM |

### AI configuration (scribe module)

AI generation uses an injectable strategy chosen in `API/SecOpsConfig.json` under `tools.scribe`:

```json
"scribe": {
  "defaultStrategy": "openai",
  "modules": { "themis": "openai", "aegis": "openai" },
  "strategies": { "google": { "model": "" } }
}
```

| Strategy | Model | Use case |
|---|---|---|
| `ollama` | `llama3.2` (default) | Local, GPU-friendly, no API cost |
| `openai` | `gpt-4o-mini` | Cloud, for VPS without GPU |
| `google` | `gemini-2.0-flash` | Cloud alternative to OpenAI |

Environment variables (in `API/.env`):

```
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=llama3.2
OPENAI_API_KEY=sk-...        # only needed if a module uses "openai"
OPENAI_MODEL=gpt-4o-mini
GOOGLE_API_KEY=...           # only needed if a module/strategy uses "google"
GOOGLE_MODEL=gemini-2.0-flash
```

### Email configuration (herald module)

Transversal module for sending email — same philosophy as `scribe`: any module builds a message
and hands it to `herald`, which delegates to an injectable strategy chosen per module in
`API/SecOpsConfig.json` under `tools.herald`. `herald` has no knowledge of its consumers (Aegis, Hygeia, Accounts, …).

```json
"herald": {
  "defaultStrategy": "smtp",
  "branding": { "productName": "Ellysia", "accentColor": "#d4a04a" },
  "modules": { "aegis": "smtp", "hygeia": "smtp", "accounts": "smtp" },
  "strategies": {
    "smtp": { "host": "smtp-relay.brevo.com", "port": 587, "useTls": true, "fromAddress": "noreply@tudominio.com" }
  }
}
```

| Strategy | Transport | Use case |
|---|---|---|
| `smtp` | SMTP relay (TLS) | Works with any provider that exposes an SMTP endpoint — Brevo, SES, Postmark, or a self-hosted relay. |

Recommended provider for teams without existing infrastructure: **Brevo** (EU-based, RGPD-friendly,
free tier around 300 emails/day, allows list/broadcast sending) via its SMTP relay
(`smtp-relay.brevo.com:587`). Amazon SES is the cheaper option once volume grows, at the cost of
AWS account setup and domain verification.

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
GRAPH_TENANT_ID=...
IRIS_MAILBOX_ENCRYPTION_KEY=...   # encrypts stored OAuth refresh tokens at rest
```

## Technology stack

| Layer | Technology |
|---|---|
| Backend | Python 3, Flask 3.0, SQLAlchemy 2.0, Flask-Smorest |
| Schema management | Alembic (versioned migrations) |
| Database | PostgreSQL 16 (via psycopg2) |
| Task queue | RQ + Redis 7 |
| Authentication | OAuth 2.0 + JWT (PyJWT, claim `jti`), TOTP MFA (pyotp) |
| Password hashing | Argon2id (argon2-cffi) |
| Scanning | Nmap + python-nmap, Nikto, Nuclei, Lybra (self-built engine) |
| PDF reports | ReportLab + Pillow |
| AI / LLM | Ollama (local) / OpenAI / Google Gemini (swappable via `scribe`) |
| Mailbox connectors | Gmail API, Microsoft Graph (OAuth 2.0) |
| Vulnerability feeds | INCIBE-CERT, CIRCL / NVD |
| Frontend web | Vue 3 (Vite + Pinia + Vue Router) |
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

Config is read through frozen dataclasses bound to a branch of the tree (`@config_block`, e.g. `CR.nuclei_config().rate_limit`), not one getter per value, and cached — changes to `SecOpsConfig.json` require an app restart unless applied via `PUT /system`. Background jobs pick them up too: the worker re-reads the file per job when its mtime changed.

> [!TIP]
> Use `python -c "from src.modules.system import config_reading as CR; print(CR.get_db_credentials())"` to verify your configuration.

## Notes

- `.env` files contain credentials — **never commit them**. `API/.env` is in `.gitignore`.
- `API/src/data/` and `docs/` are gitignored (scan outputs, generated PDFs).
- PostgreSQL uses port **15432** locally (not standard 5432).
- `themis/services/tasks.py` defines its own `TaskStatus` enum — distinct from `taskqueue.TaskStatus`.
- API version is declared as `appVersion` in `SecOpsConfig.json` (read by `CR.get_app_version()`).
