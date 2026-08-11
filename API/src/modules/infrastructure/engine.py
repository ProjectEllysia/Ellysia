"""
SQLAlchemy engine and session-factory singletons.

This module owns the process-wide database engine and the scoped session
factory, and the small set of functions that manage them: ``initialize`` to
build them, ``get_session`` to hand out a session, ``warmup`` to pre-open a
connection, and ``close_all`` to reset the scoped registry.

It has no internal dependencies, which is what keeps the infrastructure import
chain acyclic::

    engine.py            (this module — no internal imports)
      └── session.py     (request-scoped session, imports from engine)
            └── unit_of_work.py  (transaction boundary, imports from session)

``unit_of_work`` re-exports these names, so the many callers that still do
``from ...unit_of_work import get_session`` (etc.) keep working unchanged.

Note on the singletons: ``ENGINE`` and ``SESSION_FACTORY`` are module-level
globals. Reassigning them (as the test suite does to inject a SQLite engine)
must target *this* module — ``engine.ENGINE`` / ``engine.SESSION_FACTORY`` —
because the functions here read the globals from this module's namespace.
Reassigning a re-exported copy on another module would not be seen here.

Functions:
    initialize:  Build the engine and session factory (idempotent).
    get_session: Return a session from the scoped factory.
    warmup:      Pre-open a pooled connection at startup.
    close_all:   Remove all sessions from the scoped registry.
"""

from __future__ import annotations

import logging
import urllib.parse
from typing import Optional

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, scoped_session, sessionmaker

logger = logging.getLogger(__name__)


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

    if database_url is None:
        from src.modules.system import config_reading as CR
        db_creds = CR.get_db_credentials()
        database_url = (
            f"{db_creds['dialect']}://"
            f"{db_creds['username']}:{urllib.parse.quote(db_creds['password'])}"
            f"@{db_creds['host']}:{db_creds['port']}/{db_creds['dbname']}"
        )

    from src.modules.system import config_reading as CR
    isolation_level = CR.database_config().isolation_level

    engine_kwargs = dict(
        pool_pre_ping=True,
        pool_recycle=3600,
        echo=False,
        isolation_level=isolation_level,
    )

    # Pool sizing applies to QueuePool (PostgreSQL etc.). SQLite uses a
    # different pool implementation where these args are invalid, so skip them.
    if not database_url.startswith("sqlite"):
        engine_kwargs.update(CR.database_config().pool_kwargs())

    ENGINE = create_engine(database_url, **engine_kwargs)

    SESSION_FACTORY = scoped_session(
        sessionmaker(
            bind=ENGINE,
            expire_on_commit=False,
            autoflush=True,
            autocommit=False,
        )
    )

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
