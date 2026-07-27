"""
Unit tests for the database resilience helpers.

Covers the pieces that make the data-access layer resistant to session and
transaction failures, without needing a live database:

- ``retry.is_transient_error`` / ``retry.retry_on_transient`` — classify and
  retry only genuinely transient DB errors.
- The background job choke-points that remove the thread-scoped session after
  every job (RQ worker ``perform_job`` and the APScheduler ``Scheduler.execute``
  ``finally``), so an aborted transaction cannot poison the next job.
"""

from __future__ import annotations

import pytest
from sqlalchemy.exc import IntegrityError, OperationalError

from src.modules.infrastructure.retry import is_transient_error, retry_on_transient

pytestmark = pytest.mark.unit


class _FakeOrig(Exception):
    """Stand-in for a psycopg2 error carrying a SQLSTATE ``pgcode``."""

    def __init__(self, pgcode=None):
        super().__init__("orig")
        self.pgcode = pgcode


def _op_error(pgcode=None, disconnect=False) -> OperationalError:
    err = OperationalError("SELECT 1", {}, _FakeOrig(pgcode))
    err.connection_invalidated = disconnect
    return err


def _integrity_error(pgcode="23505") -> IntegrityError:
    return IntegrityError("INSERT", {}, _FakeOrig(pgcode))


# ---------------------------------------------------------------------------
# is_transient_error
# ---------------------------------------------------------------------------

def test_disconnect_is_transient():
    assert is_transient_error(_op_error(disconnect=True)) is True


def test_deadlock_is_transient():
    assert is_transient_error(_op_error(pgcode="40P01")) is True


def test_serialization_failure_is_transient():
    assert is_transient_error(_op_error(pgcode="40001")) is True


def test_plain_operational_error_is_transient():
    # A connectivity hiccup without a recognised pgcode still counts.
    assert is_transient_error(_op_error()) is True


def test_integrity_error_is_not_transient():
    assert is_transient_error(_integrity_error()) is False


def test_non_dbapi_error_is_not_transient():
    assert is_transient_error(ValueError("nope")) is False


# ---------------------------------------------------------------------------
# retry_on_transient
# ---------------------------------------------------------------------------

def test_retries_then_succeeds():
    calls = {"n": 0}

    @retry_on_transient(attempts=3, base_delay=0)
    def flaky():
        calls["n"] += 1
        if calls["n"] < 3:
            raise _op_error(pgcode="40P01")
        return "ok"

    assert flaky() == "ok"
    assert calls["n"] == 3


def test_exhausts_and_reraises():
    calls = {"n": 0}

    @retry_on_transient(attempts=2, base_delay=0)
    def always_deadlock():
        calls["n"] += 1
        raise _op_error(pgcode="40001")

    with pytest.raises(OperationalError):
        always_deadlock()
    assert calls["n"] == 2


def test_non_transient_is_not_retried():
    calls = {"n": 0}

    @retry_on_transient(attempts=5, base_delay=0)
    def integrity():
        calls["n"] += 1
        raise _integrity_error()

    with pytest.raises(IntegrityError):
        integrity()
    assert calls["n"] == 1  # raised immediately, no retry


# ---------------------------------------------------------------------------
# Background job choke-points clean the scoped session
# ---------------------------------------------------------------------------

def test_worker_perform_job_removes_session_on_success(monkeypatch):
    from src.modules.system.taskqueue import worker as wk
    from src.modules.infrastructure import unit_of_work

    worker = wk._ThreadSafeWorker.__new__(wk._ThreadSafeWorker)
    monkeypatch.setattr(wk.SimpleWorker, "perform_job", lambda self, job, queue: "done")

    calls = {"n": 0}
    monkeypatch.setattr(unit_of_work, "close_all", lambda: calls.__setitem__("n", calls["n"] + 1))

    assert worker.perform_job(object(), object()) == "done"
    assert calls["n"] == 1


def test_worker_perform_job_removes_session_on_error(monkeypatch):
    from src.modules.system.taskqueue import worker as wk
    from src.modules.infrastructure import unit_of_work

    worker = wk._ThreadSafeWorker.__new__(wk._ThreadSafeWorker)

    def _boom(self, job, queue):
        raise RuntimeError("job crashed")

    monkeypatch.setattr(wk.SimpleWorker, "perform_job", _boom)

    calls = {"n": 0}
    monkeypatch.setattr(unit_of_work, "close_all", lambda: calls.__setitem__("n", calls["n"] + 1))

    with pytest.raises(RuntimeError):
        worker.perform_job(object(), object())
    assert calls["n"] == 1  # cleaned up despite the crash


def test_scheduler_execute_removes_session(monkeypatch):
    from src.modules.features.themis.services import scheduling

    calls = {"n": 0}
    monkeypatch.setattr(scheduling, "close_all", lambda: calls.__setitem__("n", calls["n"] + 1))
    # Skip the launch entirely: load phase returns None.
    monkeypatch.setattr(
        scheduling.ThemisScheduler, "_load_and_guard", classmethod(lambda cls, ps_id: None)
    )

    scheduling.ThemisScheduler.execute(999)
    assert calls["n"] == 1
