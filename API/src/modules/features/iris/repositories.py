"""
Repository classes for Iris data access.

Extends BaseRepository for type-safe CRUD on IrisAnalysis and
IrisRuleResult models.
"""

from __future__ import annotations

from datetime import timedelta
from typing import List, Optional, Tuple

from sqlalchemy import asc, desc, nullslast
from sqlalchemy.orm import joinedload

from src.modules.infrastructure import BaseRepository, UnitOfWork
from src.modules.shared import utcnow_naive

from .model import IrisAnalysis, IrisMailboxConnection, IrisRuleResult, IrisDocument


class IrisAnalysisRepository(BaseRepository[IrisAnalysis]):
    """Data-access layer for IrisAnalysis records.

    Inherits generic CRUD (get_by_id, save, delete) from BaseRepository
    and adds analysis-specific query methods.
    """

    def __init__(self, uow: UnitOfWork | None = None, session=None) -> None:
        super().__init__(IrisAnalysis, uow=uow, session=session)

    def get_by_user(self, user_id: int) -> List[IrisAnalysis]:
        """Return all analyses belonging to a user, newest first."""
        return (
            self._session.query(IrisAnalysis)
            .filter(IrisAnalysis.user_id == user_id)
            .order_by(IrisAnalysis.created_at.desc())
            .all()
        )

    def get_active_analyses(self) -> List[IrisAnalysis]:
        """Analyses still pending/running — used to detect orphans after a restart."""
        return (
            self._session.query(IrisAnalysis)
            .filter(IrisAnalysis.status.in_(["pending", "running"]))
            .order_by(IrisAnalysis.started_at.asc())
            .all()
        )

    #: Columnas ordenables expuestas por ``sort_by`` — nunca se acepta el
    #: nombre de columna directamente desde la query string.
    _SORTABLE_COLUMNS = {
        "date": IrisAnalysis.created_at,
        "score": IrisAnalysis.total_score,
        "verdict": IrisAnalysis.verdict,
        "title": IrisAnalysis.title,
        "status": IrisAnalysis.status,
    }

    def get_by_user_paginated(
        self, user_id: int, page: int, per_page: int, *,
        search: str | None = None, verdict: str | None = None,
        status: str | None = None, source: str | None = None,
        sort_by: str = "date", sort_dir: str = "desc",
    ) -> Tuple[List[IrisAnalysis], int]:
        """Return a page of analyses for a user plus the total count.

        Args:
            user_id: Owner of the analyses.
            page: 1‑based page number.
            per_page: Maximum items per page.
            search: Optional case-insensitive substring match on ``title``.
            verdict: Optional exact match on ``verdict``.
            status: Optional exact match on ``status``.
            source: "manual" (``connection_id IS NULL``) or "mailbox"
                (``connection_id IS NOT NULL``); ``None`` = no filter.
            sort_by: One of ``_SORTABLE_COLUMNS`` — validated upstream by
                ``ResultsQuerySchema``.
            sort_dir: "asc" or "desc".

        Returns:
            Tuple of (items, total_count).
        """
        query = (
            self._session.query(IrisAnalysis)
            .options(joinedload(IrisAnalysis.connection))
            .filter(IrisAnalysis.user_id == user_id)
        )
        if search:
            query = query.filter(IrisAnalysis.title.ilike(f"%{search}%"))
        if verdict:
            query = query.filter(IrisAnalysis.verdict == verdict)
        if status:
            query = query.filter(IrisAnalysis.status == status)
        if source == "manual":
            query = query.filter(IrisAnalysis.connection_id.is_(None))
        elif source == "mailbox":
            query = query.filter(IrisAnalysis.connection_id.isnot(None))

        total = query.count()

        column = self._SORTABLE_COLUMNS.get(sort_by, IrisAnalysis.created_at)
        direction = asc if sort_dir == "asc" else desc
        # nullslast en todos los campos ordenables salvo la fecha (nunca nula):
        # un análisis pendiente sin score/verdict aún no debe contaminar la
        # rampa de riesgo del extremo "peor" ni "mejor" del orden por score.
        order_clause = nullslast(direction(column)) if column is not IrisAnalysis.created_at else direction(column)
        items = (
            query.order_by(order_clause, IrisAnalysis.created_at.desc())
            .limit(per_page)
            .offset((page - 1) * per_page)
            .all()
        )
        return items, total


class IrisMailboxConnectionRepository(BaseRepository[IrisMailboxConnection]):
    """Data-access layer for IrisMailboxConnection records."""

    def __init__(self, uow: UnitOfWork | None = None, session=None) -> None:
        super().__init__(IrisMailboxConnection, uow=uow, session=session)

    def get_by_user(self, user_id: int) -> List[IrisMailboxConnection]:
        """Return all connections belonging to a user, newest first."""
        return (
            self._session.query(IrisMailboxConnection)
            .filter(IrisMailboxConnection.user_id == user_id)
            .order_by(IrisMailboxConnection.created_at.desc())
            .all()
        )

    def count_for_user(self, user_id: int) -> int:
        """Number of connections a user already has (for the quota check)."""
        return (
            self._session.query(IrisMailboxConnection)
            .filter(IrisMailboxConnection.user_id == user_id)
            .count()
        )

    def get_by_user_provider_email(
        self, user_id: int, provider: str, account_email: str
    ) -> Optional[IrisMailboxConnection]:
        """Look up an existing connection for the same (user, provider, account)."""
        return (
            self._session.query(IrisMailboxConnection)
            .filter(
                IrisMailboxConnection.user_id == user_id,
                IrisMailboxConnection.provider == provider,
                IrisMailboxConnection.account_email == account_email,
            )
            .first()
        )

    def get_due_for_sync(self, older_than_minutes: int) -> List[IrisMailboxConnection]:
        """Active connections whose last sync is stale enough to poll again.

        Includes connections that have never synced (``last_sync_at`` is
        NULL) — the scheduler must give every new connection its bootstrap
        sync.
        """
        cutoff = utcnow_naive() - timedelta(minutes=older_than_minutes)
        return (
            self._session.query(IrisMailboxConnection)
            .filter(
                IrisMailboxConnection.status == "active",
                (IrisMailboxConnection.last_sync_at.is_(None))
                | (IrisMailboxConnection.last_sync_at < cutoff),
            )
            .all()
        )


class IrisRuleResultRepository(BaseRepository[IrisRuleResult]):
    """Data-access layer for IrisRuleResult records."""

    def __init__(self, uow: UnitOfWork | None = None, session=None) -> None:
        super().__init__(IrisRuleResult, uow=uow, session=session)

    def get_by_analysis(self, analysis_id: int) -> List[IrisRuleResult]:
        """Return all rule results for an analysis, ordered by position."""
        return (
            self._session.query(IrisRuleResult)
            .filter(IrisRuleResult.analysis_id == analysis_id)
            .order_by(IrisRuleResult.position)
            .all()
        )

    def delete_by_analysis(self, analysis_id: int) -> None:
        """Delete all rule results belonging to an analysis."""
        self._session.query(IrisRuleResult).filter(
            IrisRuleResult.analysis_id == analysis_id
        ).delete()


class IrisReportRepository(BaseRepository[IrisDocument]):
    """Data-access layer for IrisDocument records (generated PDF reports)."""

    def __init__(self, uow: UnitOfWork | None = None, session=None) -> None:
        super().__init__(IrisDocument, uow=uow, session=session)

    def get_latest_document(self, analysis_id: int) -> IrisDocument | None:
        """Return the most recently created document for an analysis."""
        return (
            self._session.query(IrisDocument)
            .filter(IrisDocument.analysis_id == analysis_id)
            .order_by(IrisDocument.created_at.desc())
            .first()
        )

    def get_documents_by_user(self, user_id: int) -> List[IrisDocument]:
        """Return all documents belonging to a user, newest first."""
        return (
            self._session.query(IrisDocument)
            .filter(IrisDocument.user_id == user_id)
            .order_by(IrisDocument.created_at.desc())
            .all()
        )

    def get_documents_by_analysis(self, analysis_id: int) -> List[IrisDocument]:
        """Return all documents generated for a specific analysis, newest first."""
        return (
            self._session.query(IrisDocument)
            .filter(IrisDocument.analysis_id == analysis_id)
            .order_by(IrisDocument.created_at.desc())
            .all()
        )
