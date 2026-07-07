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

This module also owns the engine/session-factory singletons used everywhere:
``initialize``, ``get_session``, ``warmup`` and ``close_all``.

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

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


import time
import urllib.parse

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import scoped_session, sessionmaker


ENGINE: Optional[Engine] = None
SESSION_FACTORY: Optional[scoped_session] = None


def initialize(database_url: Optional[str] = None) -> Engine:
    """
    Initialize the SQLAlchemy engine and session factory (idempotent).

    Creates a singleton engine with connection pooling configuration and a
    scoped session factory for thread-safe session management. Safe to call
    multiple times — subsequent calls are no-ops if already initialized.

    Args:
        database_url:   Optional database URL. If not provided, credentials
                        are read from the config_reading module (CR).

    Returns:
        The active SQLAlchemy engine instance.
    """
    global ENGINE, SESSION_FACTORY

    if ENGINE is not None:
        return ENGINE

    t0 = time.perf_counter()

    if database_url is None:
        from src.modules.system import config_reading as CR
        db_creds = CR.get_db_credentials()
        database_url = (
            f"{db_creds['dialect']}://"
            f"{db_creds['username']}:{urllib.parse.quote(db_creds['password'])}"
            f"@{db_creds['host']}:{db_creds['port']}/{db_creds['dbname']}"
        )

    from src.modules.system import config_reading as CR
    isolation_level = CR.get_db_isolation_level()

    engine_kwargs = dict(
        pool_pre_ping=True,
        pool_recycle=3600,
        echo=False,
        isolation_level=isolation_level,
    )

    # Pool sizing applies to QueuePool (PostgreSQL etc.). SQLite uses a
    # different pool implementation where these args are invalid, so skip them.
    if not database_url.startswith("sqlite"):
        pool_cfg = CR.get_db_pool_config()
        engine_kwargs.update(
            pool_size=pool_cfg["pool_size"],
            max_overflow=pool_cfg["max_overflow"],
            pool_timeout=pool_cfg["pool_timeout"],
        )

    ENGINE = create_engine(database_url, **engine_kwargs)

    SESSION_FACTORY = scoped_session(
        sessionmaker(
            bind=ENGINE,
            expire_on_commit=False,
            autoflush=True,
            autocommit=False,
        )
    )

    elapsed = time.perf_counter() - t0
    # Logger not injected here intentionally — this is infrastructure-level code.
    # Callers can log the elapsed time if needed.
    _ = elapsed

    return ENGINE


def get_session() -> Session:
    """
    Return a new (or existing scoped) session from the factory.

    Calls initialize() automatically if the factory has not been set up yet.

    Returns:
        A SQLAlchemy Session bound to the current thread/scope.
    """
    global SESSION_FACTORY

    if SESSION_FACTORY is None:
        initialize()

    return SESSION_FACTORY()


def warmup() -> None:
    """
    Pre-warm the connection pool by executing a trivial query.

    Ensures the first real database operation does not pay the cost of
    establishing a new connection. Safe to call at application startup.
    """
    global SESSION_FACTORY

    if SESSION_FACTORY is None:
        initialize()

    session = SESSION_FACTORY()
    session.execute(text("SELECT 1"))
    session.close()
    SESSION_FACTORY.remove()


def close_all() -> None:
    """
    Remove all active sessions from the scoped session factory.

    Useful during application shutdown or between tests to ensure no
    sessions are left open.
    """
    global SESSION_FACTORY

    if SESSION_FACTORY is not None:
        SESSION_FACTORY.remove()


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
        from flask import has_request_context

        if session is not None:
            # Explicitly injected session — the caller owns the transaction.
            self.session = session
            self._manage = False
        else:
            # Resolve the ambient session (request-scoped or thread-local).
            # Lazy import avoids a circular import with session.py.
            from .session import get_db_session

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