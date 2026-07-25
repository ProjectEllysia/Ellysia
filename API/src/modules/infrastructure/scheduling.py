"""
Helpers shared by the module-owned APScheduler instances (Themis, Hygeia,
Iris mailbox). There is no Strategy here on purpose — all three schedulers
use the same APScheduler backend, they just each own a different set of
jobs. This only factors out the two bits that were duplicated verbatim:
the ``BackgroundScheduler`` construction and the per-job session cleanup.

Functions:
    make_background_scheduler:  Build a UTC BackgroundScheduler with the
                                 misfire grace period every job entry point
                                 in this codebase relies on.
    scheduler_job:               Decorator for job entry points: isolates
                                 exceptions and releases the thread-scoped
                                 session afterwards.
"""

from __future__ import annotations

import functools
import logging
from datetime import timezone
from typing import Callable, TypeVar

from apscheduler.schedulers.background import BackgroundScheduler

from .unit_of_work import close_all

T = TypeVar("T")


def make_background_scheduler(misfire_grace_time: int = 60) -> BackgroundScheduler:
    """Build a ``BackgroundScheduler`` pinned to UTC.

    ``timezone=UTC`` keeps APScheduler's internal clock (including
    ``job.next_run_time``) aligned with the naive-UTC ``DateTime`` columns
    used across the schema. ``misfire_grace_time`` defaults to 60s because
    APScheduler's own default (1s) discards a trigger the moment the
    scheduler thread is briefly busy (another job running, GIL contention)
    instead of just running it a little late.
    """
    return BackgroundScheduler(
        timezone=timezone.utc,
        job_defaults={"misfire_grace_time": misfire_grace_time},
    )


def scheduler_job(logger: logging.Logger, error_message: str) -> Callable[[Callable[..., T]], Callable[..., None]]:
    """Wrap a scheduler job entry point: log-and-swallow, then release the session.

    APScheduler runs jobs on a long-lived thread and ``scoped_session`` is
    keyed by thread: without releasing it here, the session used by this
    firing would stay pinned to the thread and an aborted state would
    poison the next firing. Exceptions are logged, never re-raised, so one
    bad firing doesn't kill the scheduler thread.

    ``error_message`` may contain ``%``-style placeholders for the job's own
    positional args (e.g. ``"Scheduled scan %d failed"`` for a job called as
    ``execute(ps_id)``), same as any other ``logging`` call.
    """

    def decorator(func: Callable[..., T]) -> Callable[..., None]:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> None:
            try:
                func(*args, **kwargs)
            except Exception:
                logger.exception(error_message, *args)
            finally:
                close_all()

        return wrapper

    return decorator
