"""
Retry helper for transient database failures.

Wraps a callable that performs its own database work (typically opening a
``UnitOfWork``) and retries it when the failure is *transient* — a dropped
connection, a deadlock, or a serialization failure — rather than a genuine
logic or integrity error.

Only idempotent operations should be retried: re-running the callable must be
safe. In Ellysia this is applied to the background DB phases of the scheduler
(load + record run timestamps), never to the request path where a handler may
have non-idempotent side effects.

Between attempts the thread-scoped session is removed (``close_all``) so the
next attempt starts from a clean session instead of inheriting an aborted
transaction — the same resilience guarantee the request teardown provides.

Functions:
    is_transient_error:  Classify a SQLAlchemy exception as transient or not.
    retry_on_transient:  Decorator that retries on transient errors with backoff.
"""

from __future__ import annotations

import functools
import logging
import time
from typing import Callable, TypeVar

from sqlalchemy.exc import DBAPIError, OperationalError

from .unit_of_work import close_all

logger = logging.getLogger(__name__)

T = TypeVar("T")

# PostgreSQL SQLSTATE codes worth retrying.
#   40001 — serialization_failure
#   40P01 — deadlock_detected
_RETRYABLE_PGCODES = {"40001", "40P01"}


def is_transient_error(exc: Exception) -> bool:
    """Return True if ``exc`` is a transient DB error safe to retry.

    Covers driver-level disconnects (``is_disconnect``) and PostgreSQL
    deadlock / serialization failures. Integrity errors, programming errors
    and the like are deliberately *not* transient.
    """
    if not isinstance(exc, DBAPIError):
        return False

    if getattr(exc, "connection_invalidated", False) or getattr(exc, "is_disconnect", False):
        return True

    pgcode = getattr(getattr(exc, "orig", None), "pgcode", None)
    if pgcode in _RETRYABLE_PGCODES:
        return True

    # A plain OperationalError without a recognised pgcode is usually a
    # connectivity hiccup; treat it as transient.
    return isinstance(exc, OperationalError)


def retry_on_transient(
    attempts: int = 3,
    base_delay: float = 0.1,
    max_delay: float = 2.0,
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """Retry the wrapped callable on transient DB errors with capped backoff.

    Args:
        attempts:    Total number of attempts (>= 1).
        base_delay:  Initial backoff in seconds; doubles each retry.
        max_delay:   Upper bound for the per-attempt backoff.

    The thread-scoped session is removed between attempts so each retry runs
    on a fresh session. The original exception is re-raised once attempts are
    exhausted or when the error is not transient.
    """
    attempts = max(attempts, 1)

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> T:
            delay = base_delay
            for attempt in range(1, attempts + 1):
                try:
                    return func(*args, **kwargs)
                except DBAPIError as exc:
                    if not is_transient_error(exc) or attempt == attempts:
                        raise
                    logger.warning(
                        "Transient DB error in %s (attempt %d/%d): %s; retrying in %.2fs",
                        func.__name__, attempt, attempts, exc, delay,
                    )
                    # Drop the (possibly aborted) thread-scoped session so the
                    # next attempt gets a clean one.
                    close_all()
                    time.sleep(delay)
                    delay = min(delay * 2, max_delay)
            # Unreachable: loop either returns or raises.
            raise RuntimeError(f"{func.__name__} exhausted retries")

        return wrapper

    return decorator
