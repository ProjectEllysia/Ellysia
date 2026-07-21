"""
Acceso a datos del módulo Hygeia.

Extiende BaseRepository para CRUD tipado sobre MonitoredAsset, AssetSnapshot
y Anomaly. Las lecturas se construyen con ``build_repository`` (sesión
ambiental, sin demarcar transacción); las escrituras, dentro de un
``UnitOfWork``. Ningún método de este módulo crea ni cierra sesiones.
"""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from sqlalchemy import update
from sqlalchemy.orm import Session

from src.modules.infrastructure import BaseRepository, UnitOfWork

from .model import Anomaly, AssetSnapshot, MonitoredAsset


class MonitoredAssetRepository(BaseRepository[MonitoredAsset]):
    """Acceso a datos de MonitoredAsset."""

    def __init__(self, uow: Optional[UnitOfWork] = None, session: Optional[Session] = None) -> None:
        super().__init__(MonitoredAsset, uow=uow, session=session)

    def get_by_user(self, user_id: int) -> List[MonitoredAsset]:
        """Devuelve todos los activos monitorizados de un usuario, más recientes primero."""
        return (
            self._session.query(MonitoredAsset)
            .filter(MonitoredAsset.user_id == user_id)
            .order_by(MonitoredAsset.created_at.desc())
            .all()
        )

    def get_by_agent_key_id(self, agent_key_id: str) -> Optional[MonitoredAsset]:
        """Localiza el activo cuya clave de agente empieza por ``agent_key_id``.

        Es la única consulta que ejecuta la superficie de ingesta: el índice
        sobre ``agent_key_id`` la resuelve en O(1), una sola fila, sin tener
        que recorrer ni verificar el Argon2 de ningún otro activo.
        """
        return self.get_by_field("agent_key_id", agent_key_id)

    def count_by_user(self, user_id: int) -> int:
        """Cuenta cuántos activos tiene ya dados de alta un usuario (cuota §16.4)."""
        return (
            self._session.query(MonitoredAsset)
            .filter(MonitoredAsset.user_id == user_id)
            .count()
        )

    def get_active_for_presence_check(self) -> List[MonitoredAsset]:
        """Activos candidatos a que el detector de presencia los reevalúe.

        Excluye los que ya están ``offline``: un job que corre cada minuto
        no debe seguir tocando activos que ya se declararon caídos.
        """
        return (
            self._session.query(MonitoredAsset)
            .filter(MonitoredAsset.status.in_(["online", "stale"]))
            .all()
        )

    def transition_status_if_still_silent(
        self, asset_id: int, cutoff: datetime, from_status: str, new_status: str,
    ) -> bool:
        """Realiza la transición de presencia con una escritura condicional atómica.

        Si se leyera ``last_seen_at`` en Python y se decidiera la transición
        antes de escribir, un heartbeat que llegase justo en ese instante
        dejaría la lectura obsoleta y el activo se marcaría caído pese a
        haber respondido. Al mover tanto la condición ``last_seen_at < cutoff``
        como el estado de origen esperado al propio UPDATE, es Postgres quien
        decide de forma atómica si el activo seguía realmente en el estado y
        silencio esperados en el momento de escribir — a salvo también de dos
        ejecuciones del job solapadas.

        Args:
            asset_id: Activo a transicionar.
            cutoff: Instante límite; solo transiciona si ``last_seen_at`` es
                anterior a este valor.
            from_status: Estado en el que debe estar la fila para que la
                transición aplique ("online" | "stale").
            new_status: Nuevo estado ("stale" | "offline").

        Returns:
            True si la fila se actualizó (seguía en ``from_status`` y en
            silencio), False si no (un heartbeat la actualizó primero, otro
            job ya la transicionó, o ya no cumplía la condición).
        """
        result = self._session.execute(
            update(MonitoredAsset)
            .where(
                MonitoredAsset.id == asset_id,
                MonitoredAsset.status == from_status,
                MonitoredAsset.last_seen_at < cutoff,
            )
            .values(status=new_status)
        )
        return result.rowcount > 0


class AssetSnapshotRepository(BaseRepository[AssetSnapshot]):
    """Acceso a datos de AssetSnapshot (heartbeats)."""

    def __init__(self, uow: Optional[UnitOfWork] = None, session: Optional[Session] = None) -> None:
        super().__init__(AssetSnapshot, uow=uow, session=session)

    def get_series(
        self, asset_id: int, since: Optional[datetime] = None,
        until: Optional[datetime] = None, limit: int = 1000,
    ) -> List[AssetSnapshot]:
        """Devuelve los ``limit`` snapshots **más recientes** de un activo, en orden cronológico.

        El recorte se aplica por la cola, no por la cabeza: se ordena de más
        nuevo a más viejo, se corta a ``limit`` y se reinvierte en memoria. Un
        ``ORDER BY ... ASC`` con ``LIMIT`` devolvería los puntos más antiguos,
        que para una gráfica de pulso es justo lo contrario de lo que se pide.

        El eje es ``received_at`` (reloj del servidor), nunca ``collected_at``
        (reloj del agente): ``check_clock_skew`` solo acota la deriva del
        agente a una banda de ± unos minutos, y dentro de esa banda un reloj
        desviado bastaría para desordenar la serie o para anclar la ventana
        en filas viejas. Los filtros ``since``/``until`` se aplican sobre el
        mismo campo, para que ventana y orden hablen del mismo reloj.

        Args:
            asset_id: Activo cuya serie se consulta.
            since: Límite inferior opcional de ``received_at``.
            until: Límite superior opcional de ``received_at``.
            limit: Máximo de puntos a devolver, para no cargar un histórico sin fin.

        Returns:
            Lista de snapshots ordenados de más antiguo a más reciente.
        """
        query = self._session.query(AssetSnapshot).filter(AssetSnapshot.asset_id == asset_id)
        if since is not None:
            query = query.filter(AssetSnapshot.received_at >= since)
        if until is not None:
            query = query.filter(AssetSnapshot.received_at <= until)

        rows = query.order_by(AssetSnapshot.received_at.desc()).limit(limit).all()
        rows.reverse()
        return rows

    def delete_older_than(self, cutoff: datetime) -> int:
        """Elimina snapshots anteriores a ``cutoff`` (job de retención, §7.3).

        Poda por ``received_at``, el mismo eje que ordena la serie: con
        ``collected_at`` las filas de un agente con el reloj adelantado
        sobrevivirían a su ventana de retención.

        Returns:
            Número de filas eliminadas.
        """
        result = self._session.query(AssetSnapshot).filter(
            AssetSnapshot.received_at < cutoff
        ).delete(synchronize_session=False)
        return result


class AnomalyRepository(BaseRepository[Anomaly]):
    """Acceso a datos de Anomaly."""

    def __init__(self, uow: Optional[UnitOfWork] = None, session: Optional[Session] = None) -> None:
        super().__init__(Anomaly, uow=uow, session=session)

    #: Estados que cuentan como "todavía activa" a efectos de detección:
    #: reconocer una anomalía (``acknowledged``) no la da por resuelta, así
    #: que sigue bloqueando una reapertura duplicada y sigue siendo
    #: candidata a auto-resolverse cuando la métrica vuelve a la normalidad.
    #: Solo ``resolved`` es un estado terminal.
    _ACTIVE_STATES = ("open", "acknowledged")

    def get_active(self, asset_id: int, kind: str, metric: Optional[str] = None) -> Optional[Anomaly]:
        """Devuelve la anomalía activa (abierta o reconocida) de un tipo/métrica para un activo.

        ``metric`` distingue instancias del mismo ``kind`` que pueden
        coexistir activas a la vez — p. ej. ``disk_full`` en ``/`` y en
        ``/data`` son dos anomalías independientes del mismo activo. Para
        tipos sin métrica asociada (``host_down``), se pasa ``None``.

        Se usa tanto para la apertura idempotente (no duplicar una anomalía
        ya activa) como para la resolución (localizar cuál cerrar).
        """
        query = self._session.query(Anomaly).filter(
            Anomaly.asset_id == asset_id,
            Anomaly.kind == kind,
            Anomaly.state.in_(self._ACTIVE_STATES),
        )
        query = query.filter(Anomaly.metric.is_(None) if metric is None else Anomaly.metric == metric)
        return query.one_or_none()

    def get_all_active(self, asset_id: int) -> List[Anomaly]:
        """Todas las anomalías activas (abiertas o reconocidas) de un activo.

        Usado por la evaluación de umbrales para saber, de un vistazo, qué
        está ya activo antes de decidir qué abrir o resolver en este
        heartbeat — un ``ack`` no debe hacer que se reabra como si fuera
        nueva.
        """
        return (
            self._session.query(Anomaly)
            .filter(Anomaly.asset_id == asset_id, Anomaly.state.in_(self._ACTIVE_STATES))
            .all()
        )

    def get_by_id_for_user(self, anomaly_id: int, user_id: int) -> Optional[Anomaly]:
        """Obtiene una anomalía por id, verificando que pertenece a un activo del usuario.

        El JOIN con MonitoredAsset es la comprobación de propiedad: devuelve
        None tanto si la anomalía no existe como si pertenece a un activo de
        otro usuario, para no permitir enumerar anomalías ajenas.
        """
        return (
            self._session.query(Anomaly)
            .join(MonitoredAsset, Anomaly.asset_id == MonitoredAsset.id)
            .filter(Anomaly.id == anomaly_id, MonitoredAsset.user_id == user_id)
            .one_or_none()
        )

    def get_for_user(
        self, user_id: int, state: Optional[str] = None,
        severity: Optional[str] = None, asset_id: Optional[int] = None,
    ) -> List[Anomaly]:
        """Lista las anomalías de los activos de un usuario, con filtros opcionales.

        El filtro por dueño se aplica a través del JOIN con MonitoredAsset:
        un usuario nunca ve anomalías de activos ajenos.
        """
        query = (
            self._session.query(Anomaly)
            .join(MonitoredAsset, Anomaly.asset_id == MonitoredAsset.id)
            .filter(MonitoredAsset.user_id == user_id)
        )
        if state is not None:
            query = query.filter(Anomaly.state == state)
        if severity is not None:
            query = query.filter(Anomaly.severity == severity)
        if asset_id is not None:
            query = query.filter(Anomaly.asset_id == asset_id)
        return query.order_by(Anomaly.opened_at.desc()).all()
