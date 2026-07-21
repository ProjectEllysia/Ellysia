"""
Unit of Work — transaction boundary over the ambient database session.

``UnitOfWork`` marks a transaction. It does **not** create, own, or close
sessions: the session lifecycle is managed at the two edges of the system —
``teardown_request`` for HTTP requests and the job boundary (``job_context``
for RQ workers, ``Scheduler.execute`` for the scheduler) for background work.
This keeps the request/background distinction in exactly two places instead of
scattered across every call site.

What ``__exit__`` does depends only on where it runs:

- **In a request**: no-op. The shared request session is committed/closed by
  ``teardown_request``, keeping the whole request in one atomic transaction
  and the session alive for lazy loading.
- **In a background context**: commits on clean exit, rolls back on error —
  the per-block transaction boundary that worker jobs rely on.
- **With an explicitly injected session** (tests): no-op; the caller owns the
  transaction.

The engine and session-factory singletons that were once defined here now live
in ``engine.py`` (``initialize``, ``get_session``, ``warmup``, ``close_all`` and
the ``ENGINE`` / ``SESSION_FACTORY`` globals). They are re-exported below so the
many callers doing ``from ...unit_of_work import get_session`` keep working
unchanged. Test code that needs to swap the engine must reassign
``engine.ENGINE`` / ``engine.SESSION_FACTORY`` directly, not the re-exported
copies here (see ``engine.py`` for why).

Classes:
    UnitOfWork: Transaction boundary over the ambient session.

Usage:
    with UnitOfWork() as uow:
        ScanRepository(uow).save(scan)
        # In background: commits on clean exit. In a request: deferred to
        # teardown_request.
"""

from __future__ import annotations

import logging
from typing import Optional

from flask import has_request_context
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

# Re-exported for backward compatibility with the ~20 modules that import the
# engine/session helpers from here. The definitions live in engine.py now.
from .engine import (  # noqa: F401
    ENGINE,
    SESSION_FACTORY,
    initialize,
    get_session,
    warmup,
    close_all,
)
from .session import get_db_session

logger = logging.getLogger(__name__)


class UnitOfWork:
    """
    Transaction boundary over the *ambient* database session.

    UnitOfWork no longer creates, owns, or closes sessions — the session
    lifecycle is owned by the request edge (``teardown_request``) and the job
    edge (``job_context`` / ``Scheduler.execute``). This class only demarcates
    a transaction over whatever session ``get_db_session()`` resolves for the
    current context.

    The public surface is unchanged: ``with UnitOfWork() as uow`` and
    ``uow.session`` work exactly as before.

    Attributes:
        session:  The ambient SQLAlchemy session this transaction runs on.
        _manage:  True only in a background context with an ambient session —
                  i.e. when this block is responsible for commit/rollback.
                  False in a request (teardown commits) or when a session was
                  injected explicitly (the caller commits).

    Example:
    >>> with UnitOfWork() as uow:
    ...     ScanRepository(uow).save(NmapScan(target="10.0.0.1", user_id=1))
    """

    def __init__(self, session: Optional[Session] = None) -> None:
        """
        Bind the Unit of Work to the ambient session (or an explicit one).

        Args:
            session: Optional existing SQLAlchemy session. When provided, the
                     caller owns the transaction and ``__exit__`` is a no-op.
                     When omitted, the session is resolved via
                     ``get_db_session()`` and this block manages the
                     transaction only in a background context.
        """
        if session is not None:
            # Explicitly injected session — the caller owns the transaction.
            self.session = session
            self._manage = False
        else:
            # Resolve the ambient session (request-scoped or thread-local).
            self.session = get_db_session()
            # Manage the transaction only outside a request: in a request the
            # teardown hook commits/closes, so committing here would break
            # request-level atomicity and lazy loading.
            self._manage = not has_request_context()

    # =========================================================================
    # CONTEXT MANAGER
    # =========================================================================

    def __enter__(self) -> UnitOfWork:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        """
        Commit/rollback only when this block manages the transaction.

        In a request (``_manage`` is False) this is a no-op — the request
        teardown owns commit/close. Never suppresses exceptions.

        Returns:
            False — exceptions are never suppressed.
        """
        if self._manage:
            if exc_type is None:
                self.commit()
            else:
                self.rollback()
        return False

    # =========================================================================
    # TRANSACTION OPERATIONS
    # =========================================================================

    def commit(self) -> None:
        """
        Commit the current transaction.

        Raises:
            SQLAlchemyError: If the commit fails. A rollback is performed
                             automatically before re-raising.
        """
        try:
            self.session.commit()
        except SQLAlchemyError as e:
            self.rollback()
            logger.error("Commit failed", exc_info=True)
            raise SQLAlchemyError(f"Commit failed: {e}") from e

    def commit_for_handoff(self) -> None:
        """
        Commit *now* so a separate process can see the rows just written.

        In a request the commit is normally deferred to ``teardown_request``,
        so the whole request is a single transaction (that's why ``__exit__``
        is a no-op there). But when the rows written in this block are about to
        be handed to a background worker — the manager enqueues a TaskQueue job
        whose worker runs in **another process with its own session** — they
        must be durable *before* the job is enqueued. Otherwise the worker can
        dequeue and query them before the request teardown commits (an
        "enqueue-before-commit" race), or find they never committed at all if
        the teardown later rolls back.

        Use this right before ``TaskQueue.submit(...)`` in the create-then-
        enqueue flows (report/scan/analysis/campaign creation). It is safe in a
        background context too: the surrounding block would commit on exit
        anyway, so this only moves that commit slightly earlier.
        """
        self.commit()

    def rollback(self) -> None:
        """
        Roll back the current transaction.

        If the rollback itself fails the session is poisoned; recovery is the
        job boundary's responsibility (``close_all()`` removes the thread-local
        session so the next job starts clean). We log and re-raise rather than
        recreate a session this object no longer owns.
        """
        try:
            if self.session is not None:
                self.session.rollback()
        except Exception as rollback_err:
            logger.error("Rollback failed", exc_info=True)
            raise RuntimeError(f"Rollback failed: {rollback_err}") from rollback_err

    def close(self) -> None:
        """
        No-op, kept for backward compatibility.

        The session is owned and closed by the request/job boundary, never by
        UnitOfWork. Safe to call; does nothing.
        """
        return None