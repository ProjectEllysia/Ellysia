# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Read these first

A detailed agent guide already exists — **`AGENTS.md`** (architecture, TaskQueue internals, "things that bite") and **`README.md`** (full API reference, endpoints, config). This file is the concise operational layer; consult those two for depth. Comments and docstrings in the codebase are written in **Spanish**; match the surrounding language when editing.

## Platform note

The API assumes **Linux** — scan tools (Nmap, Nikto, Nuclei) are Linux-native with no Windows bridge in the code. On Windows, run the entrypoint inside **WSL** (`wsl` → `cd API && python run.py`) or use `docker compose`. The repo checkout itself is on Windows; tests and the web build run fine natively, but running the API server does not.

## Common commands

### API (Python / Flask) — run from `API/`
```bash
pip install -r requirements.txt -r requirements-dev.txt

python run.py                                    # API on 0.0.0.0:5000 (Linux/WSL/Docker)
python -m src.modules.system.taskqueue.worker    # RQ worker — REQUIRED for any async task; separate terminal

pytest                                           # full suite + coverage (SQLite, external services mocked — no Postgres/Redis needed)
pytest -m unit                                   # fast unit tests only (no app, no DB)
pytest -m integration                            # integration tests (boots create_app + test HTTP client)
pytest tests/integration/test_oauth.py -q        # a single file
pytest tests/integration/test_oauth.py::TestX::test_y   # a single test

pylint src                                        # lint (config in API/.pylintrc)
```
CI (`.github/workflows/tests.yml`) runs `python -m pytest -q` on push/PR to `main`.

Some tests use `xfail(strict=True)` to document real known bugs — when a bug is fixed the test becomes XPASS and the marker must be removed. SQLite adaptation and mocks live **only** in `tests/`; never modify `src/` to accommodate tests.

### Database migrations (Alembic) — from `API/`
```bash
alembic revision --autogenerate -m "describe change"   # after editing a model.py
alembic upgrade head        # apply (also runs automatically on every run.py startup)
alembic downgrade -1        # roll back one step
alembic current / history
```

### Web SPA (Vue 3 + Vite) — run from `web/app/`
```bash
npm install
npm run dev            # dev server on :5173, proxies /oauth,/themis,/aegis,... to Flask :5000
npm run build
npm run test:acheron   # crypto interop + CRUD tests for the Acheron vault client (node)
```

### Docker (from repo root)
```bash
docker compose --profile dev up -d        # infra only: postgres(15432), redis(6379), ollama
docker compose --profile container up -d  # full stack incl. API, worker, web
# GPU: add -f docker-compose.gpu-nvidia.yml (or .gpu-intel.yml / .gpu-amd.yml)
```

## Architecture

Monorepo with three deliverables:
- **`API/`** — Flask REST backend (primary work area). Entry: `run.py` → `create_app()`.
- **`web/app/`** — Vue 3 SPA (Vite + Pinia + Vue Router).
- **`mobile/AcheronMobile/`** — Android/Kotlin + `AcheronCore` (Java crypto engine).

### Backend module layout (`API/src/modules/`)
Each feature module (`themis`, `iris`, `aegis`, `acheron`, `hygeia`, `users`, `system`) follows the same layering — respect it when adding code:

```
endpoints.py      # Flask-Smorest Blueprint; auth + schema validation only, no business logic
managers.py       # business logic + orchestration; DB access ONLY via UnitOfWork + repository
repositories.py   # data access (extends infrastructure/base_repository)
model.py          # SQLAlchemy models (base from shared/_model.py)
schemas.py        # Marshmallow request/response schemas — JSON keys are camelCase
services/         # module-internal helpers (scanners, parsers, scheduling, reports)
```
Blueprints are registered in `run.py` (`/system`, `/oauth`, `/users`, `/themis`, `/acheron`, `/aegis`, `/iris`, `/hygeia`).

**Cross-cutting modules:**
- `infrastructure/` — `UnitOfWork` (transaction boundary), `base_repository`, engine/session singletons. UnitOfWork does **not** own sessions: lifecycle lives at the two edges — `teardown_request` for HTTP, `job_context`/`Scheduler.execute` for background work. In a request `__exit__` is a no-op (teardown commits, one atomic transaction); in a background context it commits on clean exit / rolls back on error. Never manage sessions directly outside repositories.
- `shared/` — base model, exceptions, `handle_exceptions`, rate limiter, `Document` base.
- `tools/scribe/` — pluggable **AI generation** strategy layer (Ollama / OpenAI). Consumers hand it inputs; it knows nothing about them. Strategy chosen per-module in `SecOpsConfig.json` → `tools.scribe.modules`.
- `tools/herald/` — pluggable **email sending** strategy layer (SMTP relay), same philosophy as `scribe`. Chosen per-module in `SecOpsConfig.json` → `tools.herald.modules`. Used by Aegis campaigns.

### TaskQueue (RQ + Redis) — `system/taskqueue/`
Replaces the legacy in-process queue. Jobs persist in Redis (survive API restarts) and run in **isolated OS worker processes**, not threads.
- Submit: `TaskQueue.get_instance().submit(func, name=, category=, external_id=, args=, timeout=)`.
- Entry points are `@staticmethod` on each module's manager class (e.g. `NmapScanManager.execute_nmap_scan`) — picklable by reference with no bound state; they instantiate a fresh manager inside the worker (`execute_*` seam → `_run_*` body).
- Categories: `themis.scan`, `themis.report`, `themis.traceroute`, `aegis.generate`, `aegis.campaign`, `iris.analyze`, `iris.report`, `hygeia.notify` (+ `default`). Workers listen on category-specific queues.
- **Cancellation** is cooperative: sets Redis key `taskqueue:cancel:{job_id}`; workers poll it. **Progress** via `job.meta["progress"]`. No `on_cancel`/`on_complete`/`on_error` callbacks (removed).
- Admin REST surface at `/system/tasks/*`.

### Auth
OAuth 2.0 + JWT (PyJWT). `POST /oauth/token` with `{"grantType":"password", ...}`. Protected endpoints require `Authorization: Bearer <token>`; roles/attributes enforced via `require_oauth_token` / `require_attributes`. **JSON keys are camelCase.** Passwords hashed with Argon2id.

> The **only** unauthenticated endpoints in the entire API are `GET/POST /aegis/quiz?t=<token>` (public awareness quiz). The opaque token is the sole identity — do not add auth there, and do not leak data beyond the single recipient the token belongs to.

## Configuration

Layered, read via `system/config_reading.py` (imported as `CR`, lazily cached with `@_lazy_load`):
1. **`API/SecOpsConfig.json`** — base config: prompts, directories, taskqueue defaults, `tools.scribe`/`tools.herald` strategy selection, non-secret JWT tuning (`general.security.jwt`), `appVersion` (→ `CR.get_app_version()`).
2. **`API/.env`** — env vars that **override** JSON. Required for secrets: `JWT_SECRET_KEY`, DB / Redis / SMTP / OpenAI credentials, `PUBLIC_WEB_URL`.
3. **Root `.env`** — docker-compose only (Postgres/Redis creds), not read by the API.

Changes to `SecOpsConfig.json` require an app restart (values are cached) unless applied via `PUT /system`.

`SecOpsConfig.json` has exactly five root entries — put new keys under the right one rather than at the root:

```
appVersion                      # required at the root; read by create_app()
general/       publicUrl, directories (tempdir/logdir), security (argon2/jwt/mfa)
infrastructure/ database, redis, taskqueue
tools/         scribe (AI), herald (email)   # names match src/modules/tools/
features/      themis, aegis, iris, hygeia   # one per feature module
```

Themis' four scanners each get their own block under `features.themis.scanners.<tool>` (`nmap`, `nikto`, `lybra`, `nuclei`), all with `prompts` + `colorPalette`. The tuple `CR.THEMIS_SCANNERS` must stay in sync with them — `tests/unit/test_config_shape.py` enforces it.

### Reading config: blocks, not getters

Values are read through **frozen dataclasses bound to a branch of the tree** with `@config_block`, not one getter per value:

```python
CR.nuclei_config().rate_limit          # features.themis.scanners.nuclei.rateLimit
CR.hygeia_limits().max_body_bytes      # features.hygeia.limits.maxBodyBytes
```

- Field names are `snake_case` and map to the JSON's `camelCase` automatically (`max_body_bytes` → `maxBodyBytes`). For keys that must keep another shape — the ones passed straight as kwargs to argon2/SQLAlchemy/redis-py — declare it: `field(default=10, metadata={"key": "pool_size"})`.
- **Defaults live only in the field.** They used to be written twice (getter + JSON) and drifted.
- Values with an env override or their own resolution are a `@property` over a `configured_*` field: `CR.general_config().public_url` prefers `PUBLIC_WEB_URL`, `CR.jwt_config().secret` raises if `JWT_SECRET_KEY` is missing (lazily — so a deploy without OpenAI credentials still boots).
- Blocks are cached and rebuilt automatically when `_configs` changes (`reload()`, `PUT /system`, a monkeypatched config in tests) — nothing has to invalidate by hand.
- Adding a block: define it, add an accessor, and register it in `CONFIG_BLOCKS` in `tests/unit/test_config_shape.py`.

A few things stay plain functions on purpose: env-only credentials (`get_*_environment`), and lookups parameterized by key rather than by field (`get_iris_data`, `get_iris_scoring_weight`, `get_tool_prompts`) — declaring those as fields would mean editing `config_reading.py` every time a rule is added.

**Beware the silent failure**: `_cfg()` returns the *default* when a path doesn't resolve, so a mistyped prefix disables a whole config block without raising. Any key you move must be updated in three places — the `@config_block` path (or `_cfg()` call) in `config_reading.py`, the literal path in `web/app/src/views/ConfigView.vue`, and `test_config_shape.py`.

## Naming conventions

- **Variable names**: Always use full words; never abbreviate to single letters or cryptic short forms. `message` not `msg`, `count` not `cnt`. Exception: common diminutives are fine (`repo` for repository, `config` for configuration).
- **Type clarity**: Variable names must clarify what data they hold. Don't use generic names that obscure the type: use `critical_threshold` not `critical`, `scan_repository` not `scan_repo` (though `repo` alone is fine). A name like `critical` reads as a boolean; `critical_threshold` correctly implies an integer threshold.

## Things that bite

- `.env` files hold credentials — never commit. `API/.env`, `API/src/data/`, and `docs/` are gitignored.
- **First deploy only**: `CREATE_DATABASE=True` runs the destructive `_init_db()` (drops + recreates DB, seeds root user + Topic rows). Set it back to `False` afterward or you lose data on next restart. Subsequent schema changes go through Alembic (auto-applied on startup, non-destructive).
- **Do not run `CREATE_DATABASE=True` / reset the local dev DB.** As of 2026-07-29 it holds a real NVD/KEV/EPSS knowledge-base backfill (`CveEntry`/`CpeMatch`/`KevEntry`/`EpssScore`, ~350k CVEs — the full historical catalog, not just a window) that took over an hour to pull under NVD's unauthenticated rate limit (see `lybra-engine-roadmap.md`, Fase I-b). Re-running it is pure lost time, not a correctness issue — but there's no reason to pay that cost twice.
- PostgreSQL is on port **15432** locally (container maps 5432→15432), not the standard 5432.
- Async tasks silently never run if no RQ **worker** is up.
- `themis/services/tasks.py` defines its **own** `TaskStatus` enum — distinct from `taskqueue.TaskStatus`. Don't conflate them.
- API version is config-driven: `create_app()` reads it via `CR.get_app_version()` from `appVersion` in `SecOpsConfig.json` (currently `4.2`) — it is not hardcoded.
- `features.themis.areLocalIpsAllowed` is set to `true` in `SecOpsConfig.json` (intentional, for local dev against private IPs) — with it `true`, 3 SSRF tests don't trigger (`test_nikto_rejects_loopback_target`, `test_nikto_rejects_cloud_metadata_target`, `test_nmap_rejects_private_ip_target`; not a regression). **Must be reverted to `false` before any real deployment**, or the anti-SSRF defense stays disabled in production.
- OpenVAS was removed from the product (roadmap `plans/feature/themis/lybra-engine-roadmap.md` §7/§6.3, Ronda 2). Its scheduled-flow SSRF fix (`run_scan()` self-validating via `ScanManager.reject_private_ip`) set the pattern the surviving scanners now all follow: each of Nmap, Nikto, Nuclei and Lybra self-validates inside its own `run_scan()` (`thirdparty_scans_managers.py`, `lybra_sources.py`), not just at the HTTP endpoint — so the scheduled flow (`scheduling.py` calling `run_scan()` directly) is covered. The one mode that is *not* validated by design is Lybra's `ExternalPayload` source (`lybra_sources.py`, `probes_target_network = False`): it analyses a services list the caller already resolved without touching the network, so there is no target to reject — deep corroborators from that mode require an explicit authorized-targets entry instead (`deep_requires_authorization = True`).
