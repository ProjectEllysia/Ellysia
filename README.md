<!-- prettier-ignore -->
<div align="center">

<img src="./API/resources/images/ellysia/Ellysia-BgN.png" alt="Ellysia" height="110" />

# Ellysia — Security Operations Platform

[![Python 3.10+](https://img.shields.io/badge/Python-3.10-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org)
[![Flask 3.0](https://img.shields.io/badge/Flask-3.0-000?style=flat-square&logo=flask)](https://flask.palletsprojects.com)
[![Vue 3](https://img.shields.io/badge/Vue-3-42b883?style=flat-square&logo=vuedotjs&logoColor=white)](https://vuejs.org)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1?style=flat-square&logo=postgresql&logoColor=white)](https://www.postgresql.org)
[![Ollama](https://img.shields.io/badge/Ollama-llama3.2-ff7000?style=flat-square&logo=ollama)](https://ollama.com)
[![Android](https://img.shields.io/badge/Android-Kotlin-7F52FF?style=flat-square&logo=kotlin&logoColor=white)](https://kotlinlang.org)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker&logoColor=white)](https://www.docker.com)

[Overview](#overview) · [Features](#features) · [Architecture](#architecture) · [Modules](#modules) · [Quick start](#quick-start) · [API reference](#api-reference) · [TaskQueue](#taskqueue-rq--redis) · [Docker](#docker) · [Stack](#technology-stack) · [Configuration](#configuration)

---

</div>

## Overview

**Ellysia** is a modular security operations platform that combines vulnerability scanning, anti-phishing email analysis, encrypted credential management, and AI-powered security awareness training into a single server — with web and mobile interfaces.

The REST API (Flask) orchestrates asynchronous scans and analysis over **RQ + Redis** queues, while local AI (Ollama) generates reports, awareness pills, and contextual verdicts. All modules share an OAuth 2.0 authentication layer with fine-grained attribute-based access control.

> [!IMPORTANT]
> The API assumes a **Linux** environment. Scan tools (Nmap, Nikto, OpenVAS/Greenbone) are Linux-native. On Windows, use WSL (`wsl` → `cd API && python run.py`) or `docker compose`.

## Features

- **Vulnerability scanning** — Nmap (port/OS detection), Nikto (web vulns), and OpenVAS/GVM (full NVT scans), with scheduled execution via APScheduler.
- **AI-powered PDF reports** — Scan results enriched by local LLM (Ollama) with "Controls, Not Counts" risk assessment.
- **Anti-phishing analysis** — 37 atomic rules evaluate email headers (SPF, DKIM, DMARC, content heuristics, domain impersonation) and produce a calibrated verdict.
- **Encrypted credential vault** — AES-256-GCM client-side encryption via AcheronCore (Java), with sync API and Android companion app.
- **Security awareness training** — AI generates 73-topic awareness pills with current CVE alerts from INCIBE-CERT / CIRCL / NVD.
- **Persistent task queue** — Background jobs survive API restarts (Redis-backed RQ), run in isolated OS processes, and support cooperative cancellation.
- **OAuth 2.0 + JWT** — Refresh tokens, global revocation, Argon2id password hashing, role-based access with ABAC attributes.
- **Database migrations** — Schema changes are versioned, reversible, and applied automatically on startup via Alembic.

## Architecture

```
                ┌─────────────────────────────────────────────────────────┐
                │                    Ellysia API (Flask)                  │
                │  system · oauth · users · sentinel · acheron · iris ·   │
                │              aegis · scribe · herald · pages            │
                │  ┌──────────────────────────────────────────────────┐   │
                │  │  APScheduler ──► TaskQueue (RQ + Redis)          │   │
   Web SPA ────►│  │               ┌────────────────────────────┤     │   │
  (Vue 3)       │  │               │ RQ Workers (isolated procs)│     │──►  Nmap / Nikto / OpenVAS
                │  │               │   sentinel.scan            │     │──►  Ollama / OpenAI
  Android  ────►│  │               │   sentinel.report          │     │──►  INCIBE-CERT · CIRCL · NVD
  (Kotlin)      │  │               │   aegis.generate           │     │
                │  │               │   iris.analyze             │     │
                │  │               └────────────────────────────┘     │   │
                │  └──────────────────────────────────────────────────┘   │
                │  PostgreSQL (15432)  ·  Alembic migrations              │
                └─────────────────────────────────────────────────────────┘
```

```
Ellysia/
├── API/        # Flask backend (run.py → create_app())
│   ├── alembic/                 # Schema migrations (versioned)
│   ├── src/modules/
│   │   ├── system/              # Config, logging, task queue admin
│   │   ├── users/               # OAuth 2.0 + JWT, user CRUD, ABAC
│   │   ├── sentinel/            # Scan orchestration (Nmap/Nikto/OpenVAS)
│   │   ├── iris/                # Email header analysis (37 rules)
│   │   ├── aegis/               # Awareness pills + CVE alerts
│   │   ├── acheron/             # Encrypted credential vault
│   │   ├── scribe/              # AI generation abstraction layer
│   │   ├── herald/              # Email sending abstraction layer
│   │   ├── infrastructure/      # ORM plumbing (UnitOfWork, repos)
│   │   ├── shared/              # Base models, exceptions, schemas
│   │   └── pages/               # Legacy static pages
│   └── tests/
├── web/
│   ├── app/    # Vue 3 SPA (Vite + Pinia + Vue Router)
│   └── legacy/ # Legacy static HTML
├── mobile/
│   └── AcheronMobile/  # Android (Kotlin + Jetpack Compose)
│       └── AcheronCore/        # Java crypto engine
└── docker-compose.yml
```

## Modules

| Module | Description | Status |
|---|---|---|
| **Sentinel** | Nmap, Nikto, and OpenVAS scans with PDF reports, scheduled execution, AI enrichment, and traceroute tracing. | Operational |
| **Iris** | Phishing detection via 37 atomic email header analysis rules with subtractive risk scoring. | Operational |
| **Acheron** | Client-encrypted credential vault with granular sync, export/import, and Android app. | Operational |
| **Aegis** | AI-generated security awareness pills across 73 topics with real-time CVE alerts from 19 tracked brands. | Operational |
| **Scribe** | Abstraction layer for AI generation — pluggable strategies (Ollama, OpenAI) per module. | Operational |
| **Herald** | Abstraction layer for email sending — pluggable strategies (SMTP relay) per module, transversal like Scribe. | Operational |
| **Ellysia Web** | Vue 3 SPA with hub dashboard, scan management, analysis viewer, vault client, and admin panel. | Operational |
| **AcheronMobile** | Android app with Jetpack Compose UI, Material 3 design, and Java crypto core for offline vault operations. | Operational |

## Quick start

> [!NOTE]
> Requires: Python 3.10+, Docker, PostgreSQL, Redis, Ollama (for AI features), and scan tools (Nmap, Nikto, OpenVAS).

```bash
# 1. Clone
git clone https://github.com/ProjectEllysia/Ellysia.git
cd Ellysia

# 2. Start infrastructure (PostgreSQL 15432, Redis, Ollama, OpenVAS)
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
> After first boot, set `CREATE_DATABASE=False` to avoid dropping your data on the next restart. The schema is kept up-to-date automatically via Alembic migrations.

### Authentication

Ellysia uses OAuth 2.0 with `grant_type: password` and refresh tokens (JWT signed with PyJWT). JSON keys use **camelCase**.

```http
POST /oauth/token
Content-Type: application/json

{ "grantType": "password", "username": "root", "password": "admin" }
```

**Response:**
```json
{ "access_token": "<jwt>", "token_type": "Bearer", "expires_in": 1800, "refresh_token": "<token>" }
```

> [!WARNING]
> All protected endpoints require `Authorization: Bearer <access_token>`. `POST /oauth/revoke-all` invalidates all tokens for the authenticated user.

## API Reference

### Sentinel — vulnerability scanning

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/sentinel/nmap` | Port scan (supports CIDR ranges) |
| `POST` | `/sentinel/nikto` | Web configuration / vulnerability scan |
| `POST` | `/sentinel/openvas` | Full NVT scan (single host per scan) |
| `GET` | `/sentinel/results` | List scans (filterable, paginated) |
| `GET` | `/sentinel/results/<id>` | Scan detail |
| `GET` | `/sentinel/scan-status?id=` | Status: pending / running / done / cancelled |
| `POST` | `/sentinel/scans/<id>/cancel` | Cancel a running scan |
| `DELETE` | `/sentinel/<id>` | Delete a scan |
| `POST` | `/sentinel/generate-pdf` | Generate PDF report (`{ "id": <scanId>, "aiReport": true }`) |
| `GET` | `/sentinel/document/<id>/download` | Download PDF |
| `POST` | `/sentinel/scheduled-scans` | Create scheduled scan (cron/interval) |
| `GET/DELETE` | `/sentinel/folders[/<id>]` | Organize scans in folders |

**Nmap scan example:**

```http
POST /sentinel/nmap
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
| `POST` | `/iris/analyze` | `IRIS_CREATE` | Submit email headers (optional: `title`) |
| `GET` | `/iris/status?id=` | `IRIS_READ` | Analysis progress and status |
| `GET` | `/iris/results/<id>` | `IRIS_READ` | Full report with per-rule scores |
| `POST` | `/iris/analyze/<id>/cancel` | `IRIS_UPDATE` | Cancel a running analysis |
| `DELETE` | `/iris/results/<id>` | `IRIS_DELETE` | Delete an analysis |

Iris applies 37 rules across authentication (SPF, DKIM, DMARC), header anomalies, content heuristics, reply-chain attacks, and domain spoofing. Verdicts: `Legitimate` / `Suspicious` / `Phishing`. Thresholds configured in `SecOpsConfig.json`.

### Aegis — awareness and alerts

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/aegis/generate` | Generate an awareness pill (`{ topicId, twecks: {...} }`) |
| `GET` | `/aegis/status?id=` | Generation status |
| `GET` | `/aegis/download_as_md?id=` | Export as Markdown |
| `GET` | `/aegis/download_as_html?id=` | Export as HTML |
| `GET` | `/aegis/download_as_pdf?id=` | Export as PDF |
| `GET` | `/aegis/topics` | List available topics |
| `GET/DELETE` | `/aegis/documents[/<id>]` | List / detail / delete |
| `POST/GET/DELETE` | `/aegis/lists[/<id>]` | Distribution lists (owner) |
| `POST/GET/DELETE` | `/aegis/lists/<id>/recipients[/<id>]` | Recipients within a list (owner) |
| `POST/GET` | `/aegis/campaigns[/<id>]` | Create/list/detail a campaign (owner) |
| `POST` | `/aegis/campaigns/<id>/launch` | Launch: snapshots the quiz, mints one opaque token per recipient, queues sending |
| `GET/POST` | `/aegis/quiz?t=<token>` | **Public, no auth** — serve/grade the quiz for one recipient. One-shot: a completed token always 409s on resubmission |

Aegis combines AI-generated awareness content with current CVE alerts from INCIBE-CERT and CIRCL/NVD, tracking 19 major technology brands. Each generated pill also gets a 2-3 question multiple-choice quiz; a **campaign** sends the pill + quiz to a distribution list, tracking `sent → opened → completed` per recipient via `herald`.

### Acheron — credential vault

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/acheron/vault` | Retrieve vault (encrypted blob) |
| `POST` | `/acheron/vault` | Create or replace entire vault |
| `POST` | `/acheron/storables` | Add an `Account` or `CreditCard` |
| `PATCH` | `/acheron/storables` | Bulk update only modified fields |
| `DELETE` | `/acheron/storables` | Delete a Storable by `internalId` |

> [!NOTE]
> Encryption happens **client-side** (AcheronCore, Java). The server stores only ciphertext. Internal IDs are deterministic SHA-256 hex hashes of encrypted content — collision-free across offline devices.

### Users and system

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/users/sign-up` | Registration (username, password, email, alias) |
| `PUT` | `/users/change-password` | Password change (invalidates all tokens) |
| `GET` | `/system/tasks` | (admin) List tasks in the RQ queue |
| `POST` | `/system/tasks/<id>/cancel` | (admin) Cancel a queued task |

## TaskQueue (RQ + Redis)

Background jobs persist in Redis and survive API restarts. Workers are **isolated OS processes** (not threads).

```python
from src.modules.system.taskqueue import TaskQueue
queue = TaskQueue.get_instance()
queue.submit(func, name="Scan 192.168.1.1", category="sentinel.scan", external_id="scan:42", args=[...])
```

**Categories and entry points:**

| Category | Module | Entry function |
|---|---|---|
| `sentinel.scan` | Sentinel | `services/rq_tasks.execute_nmap_scan` |
| `sentinel.report` | Sentinel | `services/rq_tasks.execute_report_generation` |
| `aegis.generate` | Aegis | `services/rq_tasks.execute_aegis_generation` |
| `aegis.campaign` | Aegis | `campaign_managers.CampaignManager.execute_campaign_send` |
| `iris.analyze` | Iris | `services/rq_tasks.execute_iris_analysis` |

- **Progress reporting**: workers update `job.meta["progress"]` via `_Task(progress_callback=...)`.
- **Cooperative cancellation**: set Redis key `taskqueue:cancel:{job_id}`; workers check via `_Task.wait(cancel_check=...)`.
- **External IDs** follow the pattern `scan:<id>`, `sentinel-doc:<id>`, `aegis-doc:<id>`, `aegis-campaign:<id>`, `iris-analysis:<id>`.

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
> The initial deployment on a new host requires `CREATE_DATABASE=True` to seed the root user and topics. On subsequent deploys, `alembic upgrade head` runs automatically and is non-destructive.

## Docker

### Profiles

| Profile | Services | Use case |
|---|---|---|
| `dev` | PostgreSQL (15432), Redis, Ollama, OpenVAS | Local development with API on bare metal |
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

### Ports

| Service | Port | Note |
|---|---|---|
| API | 5000 | `0.0.0.0:5000` |
| PostgreSQL | 15432 | Container maps 5432 → 15432 |
| Redis | 6379 | Required for TaskQueue |
| OpenVAS | 9390 / 9392 | ~15 min first start (NVT feed initialization) |
| Ollama | 11434 | Local LLM |

### AI configuration (scribe module)

AI generation uses an injectable strategy chosen in `API/SecOpsConfig.json`:

```json
"ai": {
  "defaultStrategy": "ollama",
  "strategies": { "ollama": {}, "openai": {} },
  "modules": { "sentinel": "ollama", "aegis": "openai" }
}
```

| Strategy | Model | Use case |
|---|---|---|
| `ollama` | `llama3.2` (default) | Local, GPU-friendly, no API cost |
| `openai` | `gpt-4o-mini` | Cloud, for VPS without GPU |

Environment variables (in `API/.env`):

```
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=llama3.2
OPENAI_API_KEY=sk-...        # only needed if a module uses "openai"
OPENAI_MODEL=gpt-4o-mini
```

### Email configuration (herald module)

Transversal module for sending email — same philosophy as `scribe`: any module builds a message
and hands it to `herald`, which delegates to an injectable strategy chosen per module in
`API/SecOpsConfig.json`. `herald` has no knowledge of its consumers (Aegis, …).

```json
"email": {
  "defaultStrategy": "smtp",
  "strategies": {
    "smtp": {
      "host": "smtp-relay.brevo.com",
      "port": 587,
      "useTls": true,
      "fromAddress": "noreply@tudominio.com",
      "fromName": "Ellysia Awareness"
    }
  },
  "modules": { "aegis": "smtp" }
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

## Technology stack

| Layer | Technology |
|---|---|
| Backend | Python 3, Flask 3.0, SQLAlchemy 2.0, Flask-Smorest |
| Schema management | Alembic (versioned migrations) |
| Database | PostgreSQL 16 (via psycopg2) |
| Task queue | RQ + Redis 7 |
| Authentication | OAuth 2.0 + JWT (PyJWT, claim `jti`) |
| Password hashing | Argon2id (argon2-cffi) |
| Scanning | Nmap + python-nmap, Nikto, OpenVAS/GVM (python-gvm) |
| PDF reports | ReportLab + Pillow |
| AI / LLM | Ollama (local) / OpenAI (swappable via `scribe`) |
| Vulnerability feeds | INCIBE-CERT, CIRCL / NVD |
| Frontend web | Vue 3 (Vite + Pinia + Vue Router) |
| Mobile | Android / Kotlin + Jetpack Compose, Retrofit + OkHttp |
| Vault crypto | AcheronCore (Java): AES-256-GCM + Argon2id (fallback PBKDF2) |
| Mobile session | EncryptedSharedPreferences (Android Keystore, AES-256-GCM/SIV) |
| Scheduling | APScheduler (cron / interval triggers) |
| Containerization | Docker + Docker Compose |

## Configuration

Ellysia uses a layered configuration system (`API/src/modules/system/config_reading.py`):

1. **`API/SecOpsConfig.json`** — base configuration (prompts, directories, task queue defaults)
2. **`API/.env`** — environment variables that **override** JSON values (required for JWT secret, DB credentials, API keys)
3. **Root `.env`** — docker-compose only (Postgres, Redis, OpenVAS credentials — not for the API)

All values are lazily loaded via `@_lazy_load`. Changes to `SecOpsConfig.json` require an app restart unless applied via `PUT /system`.

> [!TIP]
> Use `python -c "from src.modules.system import config_reading as CR; print(CR.get_db_credentials())"` to verify your configuration.

## Notes

- `.env` files contain credentials — **never commit them**. `API/.env` is in `.gitignore`.
- `API/src/data/` and `docs/` are gitignored (scan outputs, generated PDFs).
- OpenVAS accepts **one host per scan** (no CIDR ranges) and takes ~15 min for initial NVT feed setup.
- PostgreSQL uses port **15432** locally (not standard 5432).
- `sentinel/services/tasks.py` defines its own `TaskStatus` enum — distinct from `taskqueue.TaskStatus`.
- API version is declared as `appVersion` in `SecOpsConfig.json` (read by `CR.get_app_version()`).
