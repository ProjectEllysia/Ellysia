"""
Repository classes for Iris data access.

Extends BaseRepository for type-safe CRUD on IrisAnalysis and
IrisRuleResult models.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, List, Optional, Tuple

from sqlalchemy import and_, asc, desc, nullslast, update
from sqlalchemy.orm import joinedload

from src.modules.infrastructure import BaseRepository, DocumentRepository
from src.modules.shared import utcnow_naive

from .model import (
    IrisAnalysis, IrisMailboxConnection, IrisMailboxInbox, IrisRuleResult, IrisDocument,
)


class IrisAnalysisRepository(BaseRepository[IrisAnalysis]):
    """Data-access layer for IrisAnalysis records.

    Inherits generic CRUD (get_by_id, save, delete) from BaseRepository
    and adds analysis-specific query methods.
    """

    _MODEL = IrisAnalysis

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

    def get_by_source(self, connection_id: int, source_message_uid: str) -> Optional[IrisAnalysis]:
        """El análisis ya aceptado para este (connection_id, source_message_uid),
        si existe.

        Usado tanto por la cola de checkpoint del sync de buzón (B01, que
        solo necesita saber si existe) como por ``IrisManager.analyze()``
        (B09, que necesita el id para devolverlo sin cobrar cuota de nuevo)
        -- reconocer un mensaje ya aceptado en un intento anterior, p.ej.
        tras un fallo entre el commit de ``IrisAnalysis`` y el borrado de su
        entrada en ``IrisMailboxInbox``, de forma que un reintento nunca
        confunda la ``UniqueConstraint`` de idempotencia con un fallo real.
        """
        return (
            self._session.query(IrisAnalysis)
            .filter(
                IrisAnalysis.connection_id == connection_id,
                IrisAnalysis.source_message_uid == source_message_uid,
            )
            .first()
        )

    def exists_by_source(self, connection_id: int, source_message_uid: str) -> bool:
        """Si ya existe un análisis para este (connection_id, source_message_uid)."""
        return self.get_by_source(connection_id, source_message_uid) is not None

    def count_by_connection(self, connection_id: int) -> int:
        """Cuántos análisis ha aceptado en total esta conexión (M10).

        Es la cuenta real de "mensajes aceptados" -- no hace falta un
        contador aparte, porque cada mensaje aceptado por el checkpoint de
        buzón (B01) deja exactamente una fila ``IrisAnalysis`` con este
        ``connection_id`` y nunca se borra al resolverse (a diferencia de su
        entrada en ``IrisMailboxInbox``, que sí desaparece).
        """
        return (
            self._session.query(IrisAnalysis.id)
            .filter(IrisAnalysis.connection_id == connection_id)
            .count()
        )

    def transition_if_state(self, analysis_id: int, from_states: list[str], **fields: Any) -> bool:
        """Aplica ``fields`` sobre un análisis solo si su ``status`` actual
        está en ``from_states`` -- transición SQL condicionada, no un
        leer-decidir-escribir (B07).

        El caso real: el usuario cancela un análisis a la vez que el worker
        termina de procesarlo. Sin esta condición dentro del propio UPDATE,
        cancel_analysis() y _persist_analysis_results() compiten por
        escribir la misma fila -- running->cancelled uno, running->finished
        el otro -- y gana quien confirme último en vez de ganar quien tenga
        razón. Con la condición en el ``WHERE``, la base de datos serializa
        los dos UPDATE: solo el primero en llegar afecta a la fila (y su
        ``rowcount`` es 1); el segundo no cambia nada (``rowcount`` 0), y
        quien lo invoque sabe por el valor de retorno que perdió la carrera
        y no debe fiarse de que su transición se aplicó. Mismo patrón que
        ``_claim_ai_summary()`` (B10), generalizado a cualquier conjunto de
        campos en vez de una sola columna.

        Args:
            analysis_id: Primary key del ``IrisAnalysis`` a transicionar.
            from_states: Estados de ``status`` en los que debe estar la fila
                para que la transición se aplique (p.ej. ``["running"]``, o
                los dos estados no terminales `_CANCELLABLE_STATES`). Una
                lista vacía nunca coincide con nada.
            **fields: Columnas a escribir si la condición se cumple --
                normalmente incluye ``status`` con el nuevo valor, más
                cualquier otro campo que deba cambiar en el mismo commit
                (``finished_at``, ``total_score``, ``verdict``...).

        Returns:
            bool: ``True`` si la fila estaba en uno de ``from_states`` y la
                transición se aplicó (``fields`` ya están escritos). ``False``
                si el análisis no existe, o si su ``status`` ya había
                cambiado a otra cosa -- en ese caso ningún campo de
                ``fields`` se ha tocado.
        """
        result = self._session.execute(
            update(IrisAnalysis)
            .where(and_(IrisAnalysis.id == analysis_id, IrisAnalysis.status.in_(from_states)))
            .values(**fields)
        )
        return bool(result.rowcount)


class IrisMailboxConnectionRepository(BaseRepository[IrisMailboxConnection]):
    """Data-access layer for IrisMailboxConnection records."""

    _MODEL = IrisMailboxConnection

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


class IrisMailboxInboxRepository(BaseRepository[IrisMailboxInbox]):
    """Data-access layer for IrisMailboxInbox -- la cola de checkpoint por
    mensaje que B01 introduce delante del cursor del proveedor."""

    _MODEL = IrisMailboxInbox

    def get_pending(self, connection_id: int) -> List[IrisMailboxInbox]:
        """Referencias sin resolver de una conexión, en orden de llegada
        (FIFO) -- el orden importa porque es el mismo en que el proveedor
        las devolvió."""
        return (
            self._session.query(IrisMailboxInbox)
            .filter(
                IrisMailboxInbox.connection_id == connection_id,
                IrisMailboxInbox.status == "pending",
            )
            .order_by(IrisMailboxInbox.id.asc())
            .all()
        )

    def has_pending(self, connection_id: int) -> bool:
        """Si quedan referencias sin resolver.

        Mientras esto sea True, ``_finish_sync`` no puede confirmar el
        cursor del proveedor (B01) -- avanzarlo perdería esas referencias
        para siempre, porque el proveedor no las vuelve a listar.
        """
        return (
            self._session.query(IrisMailboxInbox.id)
            .filter(
                IrisMailboxInbox.connection_id == connection_id,
                IrisMailboxInbox.status == "pending",
            )
            .first()
        ) is not None

    def get_existing_provider_ids(self, connection_id: int, provider_message_ids: List[str]) -> set:
        """De una lista de ids candidatos, cuáles ya están en la cola
        (pendientes o ya marcados ``dead``) -- evita volver a encolar una
        fila que un sync anterior ya conoce."""
        if not provider_message_ids:
            return set()
        rows = (
            self._session.query(IrisMailboxInbox.provider_message_id)
            .filter(
                IrisMailboxInbox.connection_id == connection_id,
                IrisMailboxInbox.provider_message_id.in_(provider_message_ids),
            )
            .all()
        )
        return {row[0] for row in rows}

    def count_pending(self, connection_id: int) -> int:
        """Cuántas referencias siguen sin resolver ahora mismo (M10) --
        contadas en vivo sobre la tabla real, no un contador aparte que
        pudiera desincronizarse de ella."""
        return (
            self._session.query(IrisMailboxInbox.id)
            .filter(
                IrisMailboxInbox.connection_id == connection_id,
                IrisMailboxInbox.status == "pending",
            )
            .count()
        )

    def count_retrying(self, connection_id: int) -> int:
        """Cuántas referencias pendientes ya han fallado al menos una vez
        (M10) -- distingue "recién descubierto, primer intento" de "se le
        está costando, va por el segundo o más"."""
        return (
            self._session.query(IrisMailboxInbox.id)
            .filter(
                IrisMailboxInbox.connection_id == connection_id,
                IrisMailboxInbox.status == "pending",
                IrisMailboxInbox.attempts >= 1,
            )
            .count()
        )

    def count_dead(self, connection_id: int) -> int:
        """Cuántas referencias agotaron ``iris.maxInboxAttempts`` y quedaron
        ``dead`` (B01/M10) -- mensajes que Iris ha dejado de intentar
        procesar, visibles pero ya sin bloquear el cursor."""
        return (
            self._session.query(IrisMailboxInbox.id)
            .filter(
                IrisMailboxInbox.connection_id == connection_id,
                IrisMailboxInbox.status == "dead",
            )
            .count()
        )

    def oldest_pending_created_at(self, connection_id: int) -> Optional[datetime]:
        """Cuándo se encoló la referencia pendiente más antigua de esta
        conexión, o ``None`` si no queda ninguna (M10).

        La edad de esa fecha es la señal de "cuánto lleva atascado el
        mensaje más viejo" -- más útil para un administrador que un simple
        recuento de pendientes, que no dice si llevan segundos o días ahí.
        """
        row = (
            self._session.query(IrisMailboxInbox.created_at)
            .filter(
                IrisMailboxInbox.connection_id == connection_id,
                IrisMailboxInbox.status == "pending",
            )
            .order_by(IrisMailboxInbox.id.asc())
            .first()
        )
        return row[0] if row is not None else None


class IrisRuleResultRepository(BaseRepository[IrisRuleResult]):
    """Data-access layer for IrisRuleResult records."""

    _MODEL = IrisRuleResult

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


class IrisReportRepository(DocumentRepository[IrisDocument]):
    """Data-access layer for IrisDocument records (generated PDF reports).

    Las tres consultas de documentos las aporta ``DocumentRepository`` (A9).
    """

    _MODEL = IrisDocument
    _PARENT_FK = "analysis_id"
