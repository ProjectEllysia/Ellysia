"""
Job periódico de notificaciones de Iris: digests diarios pendientes
de enviar y avisos de conexión atascada sin un sync limpio.

No es un scheduler propio (no hay una clase con su propia instancia de
APScheduler aquí): ``IrisMailboxScheduler`` (``services/mailbox/scheduling.py``)
ya cubre el dominio de Iris con un scheduler dedicado, y añadirle un segundo
``add_job`` que llame a ``check_and_notify()`` evita crear una sexta
instancia de scheduler solo para un chequeo que, a diferencia del sondeo de
buzón, no hace ninguna llamada a un proveedor externo -- es una consulta a
la propia base de datos, así que compartir el hilo del scheduler de buzón
no le añade ningún coste real.

El aviso de reautenticación (``IrisReauthNotifyManager``) no vive aquí: se
dispara al momento desde ``IrisMailboxManager._mark_reauth_required``,
porque es la transición a un estado la que importa, no un sondeo periódico.
"""

from __future__ import annotations

import logging
from typing import Optional

import src.modules.system.config_reading as CR
from src.modules.infrastructure import UnitOfWork
from src.modules.infrastructure.session import build_repository
from src.modules.shared import utcnow_naive
from src.modules.system.taskqueue.dispatcher import OutboxDispatcher
from src.modules.system.taskqueue.outbox_repository import TaskDispatchRepository

from ...managers.notifications import IrisDigestNotifyManager, IrisStuckSyncNotifyManager
from ...repositories import IrisMailboxConnectionRepository, IrisNotificationPreferenceRepository

logger = logging.getLogger(__name__)


def check_and_notify() -> None:
    """Entry point del job: digests diarios pendientes + conexiones
    recién atascadas. Cada mitad es independiente -- un fallo en una no
    debe impedir que la otra corra."""
    _send_due_digests()
    _notify_stuck_connections()


def _send_due_digests() -> None:
    interval_hours = CR.iris_config().digest_interval_hours
    due = build_repository(IrisNotificationPreferenceRepository).get_due_for_digest(interval_hours)
    for preference in due:
        IrisDigestNotifyManager.enqueue_for(preference.user_id)
    if due:
        logger.info("Digest de Iris: %d usuario(s) encolado(s)", len(due))


def _notify_stuck_connections() -> None:
    """Avisa una sola vez de cada conexión activa que lleva atascada sin un
    sync limpio más de ``iris.stuckSyncAfterMinutes``.

    El guardia se pone aquí, en el scheduler, y no dentro del job en segundo
    plano: el scheduler corre con ``max_instances=1``, así que no hay carrera
    entre dos pasadas de este mismo chequeo, y marcarlo aquí evita reencolar
    el mismo aviso si el job tarda en ejecutarse.
    """
    threshold = CR.iris_config().stuck_sync_after_minutes
    stuck = build_repository(IrisMailboxConnectionRepository).get_newly_stuck_connections(threshold)
    for connection in stuck:
        dispatch_id = _mark_stuck_alert_sent_and_dispatch(connection.id)
        if dispatch_id is not None:
            # Camino feliz: publicar ya. Si Redis falla, la fila queda
            # `pending` y la recogen el barrido periódico o la reconciliación
            # de arranque -- el guardia ya no puede suprimir el aviso.
            OutboxDispatcher.dispatch(dispatch_id)
    if stuck:
        logger.info("Sync atascado de Iris: %d conexión(es) avisada(s)", len(stuck))


def _mark_stuck_alert_sent_and_dispatch(connection_id: int) -> Optional[int]:
    """Pone el guardia ``stuck_alert_sent_at`` y guarda la intención de
    avisar, en un único commit.

    Antes eran dos pasos: se confirmaba la marca y después se encolaba. Si el
    proceso moría o Redis fallaba entre medias, la siguiente pasada veía la
    marca puesta y no volvía a encolar, así que el aviso se perdía para
    siempre sin que nadie lo notara. Ahora la marca y la fila
    ``TaskDispatch`` existen las dos o ninguna.

    Args:
        connection_id: Primary key de la ``IrisMailboxConnection`` atascada.

    Returns:
        Optional[int]: Primary key de la fila ``TaskDispatch`` que queda por
            publicar; ``None`` si la conexión se borró entre la consulta y
            este punto, en cuyo caso no se marca ni se encola nada.
    """
    with UnitOfWork() as uow:
        repo = IrisMailboxConnectionRepository(uow)
        fresh = repo.get_by_id(connection_id)
        if fresh is None:
            return None
        fresh.stuck_alert_sent_at = utcnow_naive()
        repo.update(fresh)
        dispatch_id = TaskDispatchRepository(uow).save(
            IrisStuckSyncNotifyManager.build_dispatch_for(connection_id),
        ).id
        # Durable antes de publicar: el worker corre en otro proceso.
        uow.commit_for_handoff()
        return dispatch_id
