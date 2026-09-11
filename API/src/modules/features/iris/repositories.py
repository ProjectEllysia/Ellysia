"""
Repository classes for Iris data access.

Extends BaseRepository for type-safe CRUD on IrisAnalysis and
IrisRuleResult models.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, List, Optional, Tuple

from sqlalchemy import and_, asc, delete, desc, func, nullslast, select, update
from sqlalchemy.orm import joinedload, selectinload

from src.modules.infrastructure import BaseRepository, DocumentRepository
from src.modules.shared import utcnow_naive

from .model import (
    IrisAnalystFeedback,
    IrisAnalysis, IrisMailboxConnection, IrisMailboxInbox, IrisNotificationPreference,
    IrisRawMessage, IrisRuleResult, IrisDocument, IrisTrustedSender,
    IrisAnalysisTag, IrisIndicator, IrisSavedView,
    IrisCase, IrisCaseAnalysis, IrisCaseEvent,
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
        tag: str | None = None, ioc: str | None = None, review: str | None = None,
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
            tag: Solo los análisis con esta etiqueta exacta; ``None`` = sin filtro.
            ioc: Solo los análisis cuyo índice de IOCs contiene este texto
                (ya normalizado por el llamante); ``None`` = sin filtro.
            review: ``pending`` (terminados y sin ninguna corrección del
                analista) o ``reviewed`` (con al menos una); ``None`` = sin filtro.
            sort_by: One of ``_SORTABLE_COLUMNS`` — validated upstream by
                ``ResultsQuerySchema``.
            sort_dir: "asc" or "desc".

        Returns:
            Tuple of (items, total_count).
        """
        query = (
            self._session.query(IrisAnalysis)
            .options(joinedload(IrisAnalysis.connection), selectinload(IrisAnalysis.tags))
            .filter(IrisAnalysis.user_id == user_id)
        )
        if tag:
            query = query.filter(IrisAnalysis.id.in_(
                select(IrisAnalysisTag.analysis_id).where(IrisAnalysisTag.name == tag)
            ))
        if ioc:
            query = query.filter(IrisAnalysis.id.in_(
                select(IrisIndicator.analysis_id).where(IrisIndicator.value.contains(ioc, autoescape=True))
            ))
        reviewed_ids = select(IrisAnalystFeedback.analysis_id)
        if review == "pending":
            query = query.filter(IrisAnalysis.status == "finished", IrisAnalysis.id.notin_(reviewed_ids))
        elif review == "reviewed":
            query = query.filter(IrisAnalysis.id.in_(reviewed_ids))
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

        Usado tanto por la cola de checkpoint del sync de buzón (que
        solo necesita saber si existe) como por ``IrisManager.analyze()``
        (que necesita el id para devolverlo sin cobrar cuota de nuevo)
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
        """Cuántos análisis ha aceptado en total esta conexión.

        Es la cuenta real de "mensajes aceptados" -- no hace falta un
        contador aparte, porque cada mensaje aceptado por el checkpoint de
        buzón deja exactamente una fila ``IrisAnalysis`` con este
        ``connection_id`` y nunca se borra al resolverse (a diferencia de su
        entrada en ``IrisMailboxInbox``, que sí desaparece).
        """
        return (
            self._session.query(IrisAnalysis.id)
            .filter(IrisAnalysis.connection_id == connection_id)
            .count()
        )

    def get_non_critical_phishing_since(
        self, user_id: int, since: datetime, critical_threshold: float,
    ) -> List[IrisAnalysis]:
        """Veredictos Phishing de buzón que el digest diario todavía no ha
        resumido.

        Solo entran los que ``_enqueue_phishing_notification`` ya habría
        notificado si no fuera por el digest -- ``connection_id`` no nulo
        (un análisis manual ya lo está viendo el usuario en el panel) y
        ``total_score`` por encima de ``critical_threshold`` (los de alta
        confianza se envían siempre al momento, nunca esperan al digest;
        ver ``IrisPhishingNotifyManager._run_notify``).

        Args:
            user_id: Dueño de los análisis.
            since: Solo análisis terminados después de este instante --
                normalmente ``IrisNotificationPreference.digest_last_sent_at``
                (o su fecha de creación, si nunca se envió un digest).
            critical_threshold: ``iris.criticalPhishingScoreThreshold``; se
                pasa como argumento en vez de leerlo aquí para que el
                repositorio no dependa de ``config_reading``.

        Returns:
            List[IrisAnalysis]: En orden cronológico ascendente.
        """
        return (
            self._session.query(IrisAnalysis)
            .filter(
                IrisAnalysis.user_id == user_id,
                IrisAnalysis.connection_id.isnot(None),
                IrisAnalysis.verdict == "Phishing",
                IrisAnalysis.total_score > critical_threshold,
                IrisAnalysis.finished_at.isnot(None),
                IrisAnalysis.finished_at > since,
            )
            .order_by(IrisAnalysis.finished_at.asc())
            .all()
        )

    def count_by_user(self, user_id: int) -> int:
        """Cuántos análisis tiene este usuario en total -- para el informe
        de retención, que necesita el denominador."""
        return self._session.query(IrisAnalysis.id).filter(IrisAnalysis.user_id == user_id).count()

    def count_finished_by_user(self, user_id: int) -> int:
        """Cuántos análisis terminados tiene un usuario.

        Es el denominador de la cobertura de feedback: solo un análisis
        terminado tiene un veredicto que el analista pueda corregir.

        Args:
            user_id: Dueño de los análisis.

        Returns:
            int: Número de análisis en estado ``finished``.
        """
        return (
            self._session.query(IrisAnalysis.id)
            .filter(IrisAnalysis.user_id == user_id, IrisAnalysis.status == "finished")
            .count()
        )

    def count_with_raw_retained_by_user(self, user_id: int) -> int:
        """De los análisis de este usuario, cuántos conservan todavía su
        raw -- el complemento de cuántos ya se purgaron."""
        return (
            self._session.query(IrisAnalysis.id)
            .join(IrisRawMessage, IrisRawMessage.analysis_id == IrisAnalysis.id)
            .filter(IrisAnalysis.user_id == user_id)
            .count()
        )

    def purge_raw_messages_older_than(self, cutoff: datetime) -> int:
        """Purga (borra) el ``IrisRawMessage`` de cada análisis creado antes
        de ``cutoff``, conservando el análisis y sus resultados.

        DELETE masivo en vez de cargar cada fila por el ORM: ``IrisRawMessage``
        no tiene ninguna tabla que dependa de ella (a diferencia de borrar un
        ``IrisAnalysis`` entero, que si se hiciera igual dejaría huérfanas
        las filas de ``IrisRuleResult``, que solo cascadan a nivel de ORM,
        no de base de datos -- ver ``delete_analyses_older_than``), así que
        aquí no hay riesgo de huérfanos que evitar yendo fila a fila.
        """
        result = self._session.execute(
            delete(IrisRawMessage).where(
                IrisRawMessage.analysis_id.in_(
                    select(IrisAnalysis.id).where(IrisAnalysis.created_at < cutoff)
                )
            )
        )
        return result.rowcount

    def get_analyses_older_than(self, cutoff: datetime) -> List[IrisAnalysis]:
        """Análisis creados antes de ``cutoff`` -- candidatos a borrado
        completo cuando ``iris.analysisRetentionDays`` está activo.

        Devuelve instancias ORM (no un ``DELETE`` masivo): borrarlas una a
        una vía ``BaseRepository.delete`` es lo que dispara el cascade real
        hacia ``IrisRuleResult`` (``cascade="all, delete-orphan"`` es un
        mecanismo del ORM, no de la base de datos -- un ``DELETE`` en SQL
        directo sobre ``IrisAnalysis`` dejaría esas filas huérfanas), y la
        retención no puede dejar huérfanos.
        """
        return (
            self._session.query(IrisAnalysis)
            .filter(IrisAnalysis.created_at < cutoff)
            .all()
        )

    def transition_if_state(self, analysis_id: int, from_states: list[str], **fields: Any) -> bool:
        """Aplica ``fields`` sobre un análisis solo si su ``status`` actual
        está en ``from_states`` -- transición SQL condicionada, no un
        leer-decidir-escribir.

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
        ``_claim_ai_summary()``, generalizado a cualquier conjunto de
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

    def get_newly_stuck_connections(self, stuck_after_minutes: int) -> List[IrisMailboxConnection]:
        """Conexiones activas que siguen intentando sincronizar pero llevan
        atascadas sin un sync limpio, y todavía no se ha avisado de ello.

        "Sigue intentando" (``last_sync_at`` no nulo) las distingue de una
        conexión recién creada que aún no ha tenido su primer sondeo -- esa
        no está atascada, solo no ha empezado. Una conexión que **nunca**
        ha tenido un sync limpio (``last_success_at`` nulo) se mide contra
        su propia fecha de creación en vez de contra un ``last_success_at``
        inexistente -- si no, toda conexión recién creada se marcaría
        atascada en la primera pasada del scheduler, antes incluso de que
        el sondeo periódico (``iris.pollIntervalMinutes``) tenga ocasión de
        intentarlo. ``stuck_alert_sent_at IS NULL`` evita reencolar un aviso
        en cada pasada mientras el problema sigue sin resolverse -- se
        limpia en cuanto un sync vuelve a dejar la cola vacía (ver
        ``_finish_sync``), así que una recaída posterior sí vuelve a avisar.
        """
        cutoff = utcnow_naive() - timedelta(minutes=stuck_after_minutes)
        never_succeeded_and_stale = and_(
            IrisMailboxConnection.last_success_at.is_(None),
            IrisMailboxConnection.created_at < cutoff,
        )
        succeeded_but_stale = IrisMailboxConnection.last_success_at < cutoff
        return (
            self._session.query(IrisMailboxConnection)
            .filter(
                IrisMailboxConnection.status == "active",
                IrisMailboxConnection.last_sync_at.isnot(None),
                IrisMailboxConnection.stuck_alert_sent_at.is_(None),
                never_succeeded_and_stale | succeeded_but_stale,
            )
            .all()
        )


class IrisMailboxInboxRepository(BaseRepository[IrisMailboxInbox]):
    """Data-access layer for IrisMailboxInbox -- la cola de checkpoint por
    mensaje que va delante del cursor del proveedor."""

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
        cursor del proveedor -- avanzarlo perdería esas referencias
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
        """Cuántas referencias siguen sin resolver ahora mismo --
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
        -- distingue "recién descubierto, primer intento" de "se le
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
        ``dead`` -- mensajes que Iris ha dejado de intentar
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
        conexión, o ``None`` si no queda ninguna.

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

    def get_by_analysis(self, analysis_id: int,
                        context_type: Optional[str] = None) -> List[IrisRuleResult]:
        """Filas de regla de un análisis, ordenadas por posición.

        Args:
            analysis_id: Primary key del ``IrisAnalysis``.
            context_type: Si se da (``"inner"`` o ``"wrapper"``), solo las
                filas de ese contexto del reenvío. Por defecto ``None``:
                todas las filas, de cualquier contexto.

        Returns:
            List[IrisRuleResult]: Las filas pedidas; lista vacía si no hay.
        """
        query = self._session.query(IrisRuleResult).filter(
            IrisRuleResult.analysis_id == analysis_id
        )
        if context_type is not None:
            query = query.filter(IrisRuleResult.context_type == context_type)
        return query.order_by(IrisRuleResult.position).all()

    def delete_by_analysis(self, analysis_id: int) -> None:
        """Delete all rule results belonging to an analysis."""
        self._session.query(IrisRuleResult).filter(
            IrisRuleResult.analysis_id == analysis_id
        ).delete()


class IrisAnalystFeedbackRepository(BaseRepository[IrisAnalystFeedback]):
    """Acceso a las correcciones del analista (``IrisAnalystFeedback``).

    Cada corrección es una fila nueva; la vigente de un análisis es la de
    ``id`` más alto, que crece junto con ``created_at``.
    """

    _MODEL = IrisAnalystFeedback

    def get_by_analysis(self, analysis_id: int) -> List[IrisAnalystFeedback]:
        """Historial de correcciones de un análisis, de la más reciente a la más antigua.

        Args:
            analysis_id: Primary key del ``IrisAnalysis``.

        Returns:
            List[IrisAnalystFeedback]: Las correcciones; lista vacía si no hay.
        """
        return (
            self._session.query(IrisAnalystFeedback)
            .filter(IrisAnalystFeedback.analysis_id == analysis_id)
            .order_by(IrisAnalystFeedback.id.desc())
            .all()
        )

    def latest_for_analysis(self, analysis_id: int) -> Optional[IrisAnalystFeedback]:
        """Corrección vigente de un análisis.

        Args:
            analysis_id: Primary key del ``IrisAnalysis``.

        Returns:
            Optional[IrisAnalystFeedback]: La más reciente, o ``None`` si
                nadie lo ha revisado.
        """
        return (
            self._session.query(IrisAnalystFeedback)
            .filter(IrisAnalystFeedback.analysis_id == analysis_id)
            .order_by(IrisAnalystFeedback.id.desc())
            .first()
        )

    def get_reviewed_ids(self, analysis_ids: List[int]) -> set[int]:
        """De una lista de análisis, cuáles tienen al menos una corrección.

        Args:
            analysis_ids: Primary keys de los análisis a mirar.

        Returns:
            set[int]: Los que un analista ha revisado; vacío si ninguno.
        """
        if not analysis_ids:
            return set()
        rows = (
            self._session.query(IrisAnalystFeedback.analysis_id)
            .filter(IrisAnalystFeedback.analysis_id.in_(analysis_ids))
            .distinct()
            .all()
        )
        return {row[0] for row in rows}

    def latest_per_analysis_for_user(self, user_id: int) -> List[IrisAnalystFeedback]:
        """La corrección vigente de cada análisis revisado de un usuario.

        Es la entrada de las métricas: una etiqueta por análisis (la última),
        no una por corrección, para que cambiar de opinión no cuente dos veces.

        Args:
            user_id: Dueño de los análisis.

        Returns:
            List[IrisAnalystFeedback]: Una fila por análisis revisado, con su
                ``analysis`` ya cargado.
        """
        latest_ids = (
            select(func.max(IrisAnalystFeedback.id))
            .join(IrisAnalysis, IrisAnalysis.id == IrisAnalystFeedback.analysis_id)
            .where(IrisAnalysis.user_id == user_id)
            .group_by(IrisAnalystFeedback.analysis_id)
        )
        return (
            self._session.query(IrisAnalystFeedback)
            .options(joinedload(IrisAnalystFeedback.analysis))
            .filter(IrisAnalystFeedback.id.in_(latest_ids))
            .all()
        )


class IrisNotificationPreferenceRepository(BaseRepository[IrisNotificationPreference]):
    """Data-access layer for IrisNotificationPreference -- una fila
    por usuario, ver ``IrisNotificationPreference`` en ``model.py``."""

    _MODEL = IrisNotificationPreference

    def get_by_user_id(self, user_id: int) -> Optional[IrisNotificationPreference]:
        """Preferencias del usuario, o ``None`` si nunca las ha tocado --
        en ese caso rigen los valores por defecto del modelo sin que exista
        fila alguna (ver ``IrisNotificationPreferenceManager.get_or_default``)."""
        return (
            self._session.query(IrisNotificationPreference)
            .filter(IrisNotificationPreference.user_id == user_id)
            .first()
        )

    def get_due_for_digest(self, interval_hours: int) -> List[IrisNotificationPreference]:
        """Usuarios con el digest activo a los que toca enviarles uno:
        nunca se les ha enviado, o el último fue hace más de
        ``iris.digestIntervalHours``."""
        cutoff = utcnow_naive() - timedelta(hours=interval_hours)
        return (
            self._session.query(IrisNotificationPreference)
            .filter(
                IrisNotificationPreference.digest_enabled.is_(True),
                (IrisNotificationPreference.digest_last_sent_at.is_(None))
                | (IrisNotificationPreference.digest_last_sent_at < cutoff),
            )
            .all()
        )


class IrisTrustedSenderRepository(BaseRepository[IrisTrustedSender]):
    """Acceso a las excepciones de confianza (``IrisTrustedSender``).

    Las filas no se borran al revocarse: la auditoría necesita las caducadas y
    las revocadas tanto como las activas.
    """

    _MODEL = IrisTrustedSender

    def get_by_user(self, user_id: int) -> List[IrisTrustedSender]:
        """Todas las excepciones de un usuario, de la más reciente a la más antigua.

        Args:
            user_id: Dueño de las excepciones.

        Returns:
            List[IrisTrustedSender]: Activas, caducadas y revocadas; lista
                vacía si no tiene ninguna.
        """
        return (
            self._session.query(IrisTrustedSender)
            .filter(IrisTrustedSender.user_id == user_id)
            .order_by(IrisTrustedSender.id.desc())
            .all()
        )

    def get_active_for_user(self, user_id: int, now: datetime) -> List[IrisTrustedSender]:
        """Excepciones de un usuario que siguen en vigor en un instante.

        Args:
            user_id: Dueño de las excepciones.
            now: Instante de referencia (UTC naive).

        Returns:
            List[IrisTrustedSender]: Las no revocadas cuya caducidad es
                posterior a ``now``.
        """
        return (
            self._session.query(IrisTrustedSender)
            .filter(
                IrisTrustedSender.user_id == user_id,
                IrisTrustedSender.revoked_at.is_(None),
                IrisTrustedSender.expires_at > now,
            )
            .order_by(IrisTrustedSender.id.asc())
            .all()
        )

    def has_active(self, user_id: int, kind: str, value: str, now: datetime) -> bool:
        """Si el usuario ya tiene en vigor una excepción idéntica.

        Args:
            user_id: Dueño de las excepciones.
            kind: ``sender`` o ``domain``.
            value: Valor ya normalizado.
            now: Instante de referencia (UTC naive).

        Returns:
            bool: ``True`` si hay una no revocada y no caducada con ese tipo y
                valor.
        """
        return (
            self._session.query(IrisTrustedSender.id)
            .filter(
                IrisTrustedSender.user_id == user_id,
                IrisTrustedSender.kind == kind,
                IrisTrustedSender.value == value,
                IrisTrustedSender.revoked_at.is_(None),
                IrisTrustedSender.expires_at > now,
            )
            .first()
        ) is not None


class IrisSavedViewRepository(BaseRepository[IrisSavedView]):
    """Acceso a las vistas guardadas del historial (``IrisSavedView``)."""

    _MODEL = IrisSavedView

    def get_by_user(self, user_id: int) -> List[IrisSavedView]:
        """Vistas de un usuario, por nombre.

        Args:
            user_id: Dueño de las vistas.

        Returns:
            List[IrisSavedView]: Las vistas; lista vacía si no tiene.
        """
        return (
            self._session.query(IrisSavedView)
            .filter(IrisSavedView.user_id == user_id)
            .order_by(IrisSavedView.name.asc())
            .all()
        )

    def count_by_user(self, user_id: int) -> int:
        """Cuántas vistas tiene guardadas un usuario.

        Args:
            user_id: Dueño de las vistas.

        Returns:
            int: Número de vistas.
        """
        return self._session.query(IrisSavedView.id).filter(IrisSavedView.user_id == user_id).count()

    def get_by_user_and_name(self, user_id: int, name: str) -> Optional[IrisSavedView]:
        """Vista de un usuario con un nombre exacto.

        Args:
            user_id: Dueño de las vistas.
            name: Nombre ya recortado.

        Returns:
            Optional[IrisSavedView]: La vista, o ``None`` si no hay ninguna con ese nombre.
        """
        return (
            self._session.query(IrisSavedView)
            .filter(IrisSavedView.user_id == user_id, IrisSavedView.name == name)
            .first()
        )


class IrisAnalysisTagRepository(BaseRepository[IrisAnalysisTag]):
    """Acceso a las etiquetas de los análisis (``IrisAnalysisTag``)."""

    _MODEL = IrisAnalysisTag

    def delete_by_analysis(self, analysis_id: int) -> None:
        """Quita todas las etiquetas de un análisis.

        Args:
            analysis_id: Primary key del ``IrisAnalysis``.
        """
        self._session.query(IrisAnalysisTag).filter(IrisAnalysisTag.analysis_id == analysis_id).delete()

    def count_by_name_for_user(self, user_id: int) -> List[Tuple[str, int]]:
        """Etiquetas que usa un usuario y en cuántos análisis aparece cada una.

        Args:
            user_id: Dueño de los análisis.

        Returns:
            List[Tuple[str, int]]: ``(nombre, análisis)``, de la más usada a la
                menos y, a igual uso, por nombre.
        """
        count = func.count(IrisAnalysisTag.id)
        return [
            (name, total) for name, total in (
                self._session.query(IrisAnalysisTag.name, count)
                .join(IrisAnalysis, IrisAnalysis.id == IrisAnalysisTag.analysis_id)
                .filter(IrisAnalysis.user_id == user_id)
                .group_by(IrisAnalysisTag.name)
                .order_by(count.desc(), IrisAnalysisTag.name.asc())
                .all()
            )
        ]


class IrisIndicatorRepository(BaseRepository[IrisIndicator]):
    """Acceso al índice de IOCs (``IrisIndicator``).

    Las búsquedas por IOC las hace ``IrisAnalysisRepository.get_by_user_paginated``,
    que es donde se combinan con el resto de filtros del historial.
    """

    _MODEL = IrisIndicator


class IrisCaseRepository(BaseRepository[IrisCase]):
    """Acceso a los casos de analista (``IrisCase``)."""

    _MODEL = IrisCase

    def get_by_user_filtered(self, user_id: int, *, status: Optional[str] = None,
                             priority: Optional[str] = None,
                             assignee_id: Optional[int] = None) -> List[IrisCase]:
        """Casos de un usuario, del modificado más recientemente al más antiguo.

        Args:
            user_id: Dueño de los casos.
            status: Solo los de este estado. Por defecto ``None``: todos.
            priority: Solo los de esta prioridad. Por defecto ``None``: todas.
            assignee_id: Solo los asignados a este usuario. Por defecto
                ``None``: sin filtro.

        Returns:
            List[IrisCase]: Los casos, con sus vínculos y su asignado cargados.
        """
        query = (
            self._session.query(IrisCase)
            .options(selectinload(IrisCase.links), joinedload(IrisCase.assignee))
            .filter(IrisCase.user_id == user_id)
        )
        if status:
            query = query.filter(IrisCase.status == status)
        if priority:
            query = query.filter(IrisCase.priority == priority)
        if assignee_id is not None:
            query = query.filter(IrisCase.assignee_id == assignee_id)
        return query.order_by(IrisCase.updated_at.desc(), IrisCase.id.desc()).all()

    def count_by_status_for_user(self, user_id: int) -> dict:
        """Cuántos casos tiene un usuario en cada estado.

        Args:
            user_id: Dueño de los casos.

        Returns:
            dict: ``{estado: casos}``, solo con los estados que tienen alguno.
        """
        rows = (
            self._session.query(IrisCase.status, func.count(IrisCase.id))
            .filter(IrisCase.user_id == user_id)
            .group_by(IrisCase.status)
            .all()
        )
        return {status: total for status, total in rows}


class IrisCaseAnalysisRepository(BaseRepository[IrisCaseAnalysis]):
    """Acceso a los vínculos entre casos y análisis (``IrisCaseAnalysis``)."""

    _MODEL = IrisCaseAnalysis

    def get_link(self, case_id: int, analysis_id: int) -> Optional[IrisCaseAnalysis]:
        """El vínculo entre un caso y un análisis, si existe.

        Args:
            case_id: Primary key del caso.
            analysis_id: Primary key del análisis.

        Returns:
            Optional[IrisCaseAnalysis]: El vínculo, o ``None``.
        """
        return (
            self._session.query(IrisCaseAnalysis)
            .filter(IrisCaseAnalysis.case_id == case_id, IrisCaseAnalysis.analysis_id == analysis_id)
            .first()
        )


class IrisCaseEventRepository(BaseRepository[IrisCaseEvent]):
    """Acceso a la timeline de los casos (``IrisCaseEvent``).

    Los eventos se leen a través de ``IrisCase.events``; aquí solo se guardan.
    """

    _MODEL = IrisCaseEvent


class IrisReportRepository(DocumentRepository[IrisDocument]):
    """Data-access layer for IrisDocument records (generated PDF reports).

    Las tres consultas de documentos las aporta ``DocumentRepository``.
    """

    _MODEL = IrisDocument
    _PARENT_FK = "analysis_id"
