# CLAUDE.md — API

Flask REST backend. **This is the primary work area.** See the root [`../CLAUDE.md`](../CLAUDE.md) for the full architecture, and [`../AGENTS.md`](../AGENTS.md) for TaskQueue internals and gotchas. Docstrings/comments are in **Spanish** — match them.

## Commands (run from this directory)
```bash
pip install -r requirements.txt -r requirements-dev.txt

python run.py                                    # API on 0.0.0.0:5000 (needs Linux/WSL/Docker — scan tools are Linux-native)
python -m src.modules.system.taskqueue.worker    # RQ worker — REQUIRED for async tasks; separate terminal

pytest                                           # full suite + coverage (SQLite, external services mocked)
pytest -m unit                                   # fast, no app/DB
pytest -m integration                            # boots create_app + test HTTP client
pytest tests/integration/test_oauth.py -q        # single file
pytest tests/integration/test_oauth.py::TestX::test_y   # single test
pylint src                                        # .pylintrc

alembic revision --autogenerate -m "msg"         # after editing a model.py
alembic upgrade head                             # apply (also auto-runs on run.py startup)
```

## Module convention (`src/modules/<feature>/`)
`endpoints.py` (Blueprint: auth + schema only) → `managers.py` (business logic; DB access **only** via `UnitOfWork` + repository) → `repositories.py` → `model.py` / `schemas.py` (JSON keys **camelCase**). Module-internal helpers live under `services/`.

Cross-cutting: `infrastructure/` (UnitOfWork, base repo, sessions), `shared/` (base model/exceptions/limiter), `scribe/` (AI-gen strategy layer), `herald/` (email strategy layer), `system/taskqueue/` (RQ + Redis). Blueprints are registered in `run.py`.

## Watch out
- `CREATE_DATABASE=True` triggers a **destructive** `_init_db()` — first deploy only, then set to `False`.
- Postgres is on port **15432** locally.
- `sentinel/services/tasks.py` has its own `TaskStatus` enum, distinct from `taskqueue.TaskStatus`.
- SQLite adaptation + mocks live only in `tests/`; never modify `src/` to accommodate tests. `xfail(strict=True)` marks known real bugs — remove the marker when it XPASSes.
