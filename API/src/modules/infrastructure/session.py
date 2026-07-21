"""
Request-scoped session management for Flask.

Provides a session that lives for the duration of a single HTTP request,
eliminating the need for eager-loading workarounds. Within a request,
lazy loading of SQLAlchemy relationships works transparently because
the session is not closed until the response is sent.

Functions:
    get_db_session:             Return (or create) the request-scoped session.
    build_repository:                  Build a repository bound to the ambient session,
                                for reads (the explicit counterpart to UnitOfWork
                                on the write side — see its docstring).
    init_request_session:       Flask before_request hook that opens the session.
    shutdown_request_session:   Flask teardown_request hook that commits/rolls
                                back and closes the session.

Usage:
    Add the following to your Flask app factory::

        from src.modules.infrastructure.session import (
            init_request_session, shutdown_request_session
        )
        app.before_request(init_request_session)
        app.teardown_request(shutdown_request_session)

    Reads, in repositories or managers::

        from src.modules.infrastructure.session import build_repository

        scan = build_repository(ScanRepository).get_by_id(42)
        print(scan.host.hostname)  # lazy load works

    Writes go through ``UnitOfWork`` instead — see its module for the pattern.
"""

from __future__ import annotations

import logging
from typing import Type, TypeVar

from flask import g, has_request_context

from .engine import get_session, close_all

logger = logging.getLogger(__name__)

R = TypeVar("R")


def get_db_session():
    """
    Return the database session for the current execution context.

    This is the single session accessor for the whole codebase — it behaves
    correctly both in an HTTP request and in a background job:

    - **In a Flask request**: returns the request-scoped session cached in
      ``g.db_session`` (opened by ``init_request_session`` and committed/closed
      by ``shutdown_request_session``). Subsequent calls return the same one,
      so lazy loading works for the whole request.
    - **In a background context** (RQ worker / scheduler thread, no request):
      returns the thread-local scoped session directly. It is deliberately
      **not** cached in ``g``: a worker's application context lives as long as
      the worker, so caching there would pin one session across every job. The
      job boundary (``job_context`` / ``Scheduler.execute``) calls
      ``close_all()`` to reset it per job.

    Returns:
        SQLAlchemy Session bound to the current request or worker thread.
    """
    if has_request_context():
        if "db_session" not in g:
            g.db_session = get_session()
        return g.db_session
    return get_session()


def build_repository(repo_cls: Type[R]) -> R:
    """
    Build a repository bound to the ambient session, for the read path.

    This is the explicit counterpart to ``with UnitOfWork() as uow: Repo(uow)``
    on the write side. Where the implicit convention used to be "pass
    ``session=get_db_session()`` directly when you only mean to read", this
    makes that intent visible at the call site — a reviewer sees ``build_repository``
    and knows no transaction is being demarcated here, so writing through the
    returned repository would not be a deliberate choice.

    The repository is bound to the same session ``UnitOfWork`` itself would
    resolve (request-scoped or thread-local), but **this helper does not
    demarcate a transaction**: any write made through the returned repository
    is only as durable as whatever already governs the ambient session (the
    request's ``teardown_request`` in a request, nothing in particular in a
    background thread outside a ``UnitOfWork`` block). Writes must go through
    ``UnitOfWork``.

    Args:
        repo_cls: A repository class whose constructor accepts a ``session``
            keyword argument — every repository in this codebase does.

    Returns:
        An instance of ``repo_cls`` bound to the ambient session.

    Example:
    >>> scan = build_repository(ScanRepository).get_by_id(42)
    """
    return repo_cls(session=get_db_session())


def init_request_session() -> None:
    """
    Flask ``before_request`` hook — eagerly open the DB session.

    Calling ``get_db_session()`` ensures the session is created before
    any endpoint handler runs, so that ``g.db_session`` is always
    available.
    """
    get_db_session()

def shutdown_request_session(exception=None) -> None:
    """
    Flask ``teardown_request`` hook — finalize the DB session.

    - If an exception was raised during the request, performs a rollback.
    - Otherwise, attempts to commit the transaction.
    - Always closes the session and removes the scoped session from the
      registry, preventing session leaks.

    Note:
        A failed commit is rolled back and logged but **not** re-raised. This
        hook runs after the response has already been produced, so propagating
        here cannot change what the client receives; integrity is already
        protected by the rollback, and re-raising would only surface as an
        unhandled error in a post-response hook.

    Args:
        exception: The exception raised during the request, if any.
                   Supplied automatically by Flask.
    """
    session = g.pop("db_session", None)
    if session is None:
        return

    try:
        if exception is not None:
            session.rollback()
        else:
            try:
                session.commit()
            except Exception:
                logger.error("Commit failed during request teardown", exc_info=True)
                session.rollback()
    finally:
        session.close()
        close_all()
