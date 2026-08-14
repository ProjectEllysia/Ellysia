# Ellysia — Agent Guide

## Architecture

Monorepo:
- **API** (`API/`) — Python/Flask REST backend (primary work area)
- **web** (`web/`) — Vue 3 SPA in `web/app/` (Vite + Pinia + Vue Router), plus the
  nginx that serves it and proxies the API (`nginx.conf`, `api-locations.conf`)
- **landing** (`landing/`) — static marketing site, published to `gh-pages` by
  `.github/workflows/landing.yml`. No build step, no coupling to the other two.

The Android client and its `AcheronCore` Java engine live in a separate repo
([SeQ-AcheronMobile](https://github.com/gamustea/SeQ-AcheronMobile)); they consume
`/acheron` over HTTP.

**API and web stay in the same repository on purpose.** They share a deployment
(one `docker-compose.yml`, one nginx that proxies to `Ellysia-API:5000` by container
name) and a contract that only a single repo can verify: `web/api-locations.conf`
has to track both `run.py:_register_blueprints` and the SPA router.
`API/tests/unit/test_nginx_api_locations.py` enforces it — a test in `API/` that
reads files from `web/`, impossible once split.

**Brand assets: the SPA is the source of truth** (`web/app/src/assets/images/`).
When an API report needs an image, copy that one file into the module that uses it
(`API/src/modules/features/hygeia/resources/hygeia-logo.png` is the pattern —
downscaled for its actual use, with a comment saying why). Do not mirror the whole
asset tree into `API/`; that copy existed, was 18 MB, was byte-identical, was baked
into the Docker image, and was referenced by nothing.

## Platform

The API assumes **Linux** (native, WSL, or Docker). The scan tools (Nmap, Nikto,
Nuclei) are Linux-native — there is no Windows/WSL bridge in the code. On Windows,
run the entrypoint inside WSL or use `docker compose`. Scan subprocesses are launched with
`start_new_session=True` so cancellation kills the full descendant tree via `psutil`.

## Entry Point

`API/run.py` → `create_app()` factory. Does this in order:
1. Register CORS, rate limiter, FlaskSmorest API
2. Register blueprints (system, oauth, users, themis, acheron, aegis, iris, pages)
3. Init DB engine + create tables
4. **Start APScheduler** (`Scheduler.start()`) (API only, not workers)
5. **Ping Redis** — health check (worker tasks require Redis to be available)
6. Signal handlers (SIGTERM/SIGINT) → cancel TaskQueue → stop Scheduler → close DB

```bash
docker compose --profile dev up -d   # postgres(15432), redis(6379), ollama
cd API && python run.py               # 0.0.0.0:5000
python -m src.modules.system.taskqueue.worker  # RQ worker (separate terminal)
```

## TaskQueue — Background Task System (RQ + Redis)

Replaces the legacy in-process SeQueue. Uses **RQ** (Redis Queue) for persistence,
scalability, and process isolation.

Key files: **`task.py`** (Task dataclass + TaskStatus enum), **`queue.py`** (TaskQueue
singleton with RQ + Redis backend), **`worker.py`** (RQ worker entry point).

Facts:
- Jobs persist in Redis → survive API crashes
- Workers are **separate OS processes** (not threads) — isolated from the API
- `TaskQueue.get_instance().submit(func, name=, category=, external_id=, args=, timeout=)`
- **No callback parameters** — `on_cancel`, `on_complete`, `on_error` were removed
- Cancellation: sets a Redis key `taskqueue:cancel:{job_id}` checked cooperatively by workers
- Entry points are `@staticmethod` on each module's manager class (inline in `managers.py`, not separate `services/rq_tasks.py` files) — picklable by reference with no bound instance state; they instantiate a fresh manager inside the worker:
  - `themis/managers/` → `TracerouteManager.execute_traceroute`, `NmapScanManager.execute_nmap_scan`, `NiktoScanManager.execute_nikto_scan`, `NucleiScanManager.execute_nuclei_scan`, `ThemisReportManager.execute_report_generation`, `LybraEngineManager.execute_lybra_scan` (own-engine, `themis/managers/lybra_engine.py`)
  - `aegis/managers.py` → `AegisManager.execute_aegis_generation`
  - `aegis/campaign_managers.py` → `CampaignManager.execute_campaign_send` (sends via `herald`, not scribe)
  - `iris/managers.py` → `IrisManager.execute_iris_analysis`, `IrisReportManager.execute_report_generation`
- Categories: `"themis.scan"`, `"themis.report"`, `"themis.traceroute"`, `"aegis.generate"`, `"aegis.campaign"`, `"iris.analyze"`, `"iris.report"`
- External IDs: `f"scan:{scan_id}"`, `f"themis-doc:{doc_id}"`, `f"themis-traceroute:{key}"`, `f"aegis-doc:{doc_id}"`, `f"aegis-campaign:{campaign_id}"`, `f"iris-analysis:{analysis_id}"`, `f"iris-doc:{doc_id}"`
- REST API (admin-only, `/system/tasks/*`): status, list tasks, detail, cancel
- Workers listen on category-specific queues: `themis.scan`, `themis.report`, `themis.traceroute`, `aegis.generate`, `aegis.campaign`, `iris.analyze`, `iris.report`, `default`
- Separate `TaskStatus` enum exists in `themis/services/tasks.py` — not the same as `taskqueue.TaskStatus`

### RQ Task Execution Pattern

Standalone `@staticmethod` entry points on the manager classes (e.g. `NmapScanManager.execute_nmap_scan`), submitted by reference — picklable with no bound instance state. These:
1. Are picklable by attribute reference (`Manager.execute_*`) with simple positional args
2. Instantiate a fresh manager inside the worker and call its instance method (the `execute_*` seam → `_run_*` body pattern)
3. Periodically check `TaskQueue.is_cancelled(job_id)` via `_Task.wait(cancel_check=...)` / `job.cancelled()`
4. Report progress via `_Task(progress_callback=...)` / `job.progress(...)` → `job.meta["progress"]`
5. Workers run with Flask app context pushed at startup (DB sessions work)

## Config System

`API/src/modules/system/config_reading.py` (imported as `CR`):
1. `API/SecOpsConfig.json` — JSON config (DB fallback, prompts, directories, taskqueue)
2. `API/.env` — env vars override JSON. Required for secrets (JWT_SECRET_KEY, DB / Redis / SMTP / OpenAI credentials) and ambient URLs (`PUBLIC_WEB_URL`). Non-secret tuning (algorithm, expirations, timeouts) lives in JSON under `general.security.jwt`, with optional env override for 12-factor.
3. Root `.env` — for docker-compose only (Postgres, Redis creds). Not for the API.

All config keys lazily loaded via `@_lazy_load` decorator.

## Auth

OAuth 2.0 + JWT. **JSON keys use camelCase** (`grantType`, `refresh_token`).

```
POST /oauth/token  {"grantType": "password", "username": "root", "password": "root"}
```

Protected endpoints require `Authorization: Bearer <access_token>`. Roles checked via `require_role()`.

## Database

- PostgreSQL port **15432** (container maps 15432→5432)
- Init: set `CREATE_DATABASE=True` in `API/.env`, then run the app. `_init_db()` in `run.py` is destructive (drops + recreates DB + inserts root user and Topic rows).
- Models: SQLAlchemy, each module has `model.py`, base from `src.modules.shared`.
- All DB ops use `UnitOfWork` + repository pattern. No direct session management outside repos.

## Scan System (themis)

- `themis/services/tasks.py`: `_Task` base class → `NmapScanTask`, `NiktoScanTask`, `NucleiScanTask`
- Each scan manager (NmapScanManager, NiktoScanManager, NucleiScanManager) submits to TaskQueue with `category="themis.scan"` and `external_id=f"scan:{scan_id}"`
- Cancellation: RQ sets Redis key `taskqueue:cancel:{job_id}` → worker checks `_Task.wait(cancel_check=...)` → triggers `task.cancel()` (subprocess.terminate)
- Scheduled scans via APScheduler (`themis/services/scheduling.py`). `Scheduler` class with interval/cron triggers. Synced from DB.

## Aegis

- `aegis/managers.py`: `AegisManager` submits to TaskQueue with `category="aegis.generate"`, `external_id=f"aegis-doc:{doc_id}"`
- Uses Ollama (`llama3.2` default, override via `OLLAMA_MODEL` env var)
- Each generated pill (`AegisDocument`) also gets 2-3 quiz questions (`AegisQuizQuestion`), generated by the same `AegisAIWriter` call and editable via `PUT /aegis/document` (`questions` field).
- **Campaigns** (`aegis/campaign_managers.py`, `CampaignManager`): send a pill+quiz to a `DistributionList` via email. `launch_campaign()` snapshots the quiz into `Campaign.questions_snapshot` (so later pill edits don't affect a running campaign) and mints one `secrets.token_urlsafe(32)` per recipient (`CampaignRecipient.token`) — **never derived from the email**, and never repeat-usable once `status="completed"` (enforced both by a status check and by `CampaignAnswer`'s `UniqueConstraint(campaign_recipient_id, question_position)` for the concurrent-request race). Sends run in the background via `category="aegis.campaign"`, `external_id=f"aegis-campaign:{campaign_id}"`, using `herald` (`build_mailer("aegis")`) — not `scribe`.
- `GET/POST /aegis/quiz?t=<token>` are the **only unauthenticated endpoints in the whole API** — no `@require_oauth_token`. The token is the sole identity. Don't add auth here; don't add anything to their response that leaks data beyond the single campaign/recipient the token belongs to.

## Ports

| Service | Port | Note |
|---|---|---|---|
| API | 5000 | `0.0.0.0:5000` |
| PostgreSQL | 15432 | Container maps 5432→15432 |
| Redis | 6379 | Container maps 6379→6379 |
| Ollama | 11434 | |

## Docker

Two profiles:
- `dev` — infrastructure only (postgres, redis, ollama)
- `container` — everything including API, worker, and web containers

GPU: `-f docker-compose.gpu-nvidia.yml / .gpu-intel.yml / .gpu-amd.yml`

## Things That Bite

- `.env` files contain credentials — never commit. `API/.env` is gitignored.
- `API/src/data/` and `docs/` are gitignored.
- `_init_db()` is destructive — drops and recreates everything.
- `SecOpsConfig.json` values are lazily cached — changes require app restart unless written via `PUT /system` endpoint. The worker process is separate and re-reads the file per job when its mtime changed (`CR.reload_if_changed()` in `_ThreadSafeWorker.perform_job`), so config edits reach background jobs too; `max_workers` still only applies at worker startup.
- `themis/services/tasks.py` has its own `TaskStatus` enum separate from `taskqueue.TaskStatus`.
- RQ workers must be running for background tasks to execute. Launch with `python -m src.modules.system.taskqueue.worker`.
- API version is read from config (`appVersion` in `SecOpsConfig.json`, currently `4.2`) via `CR.get_app_version()` in `create_app()` — not hardcoded.
