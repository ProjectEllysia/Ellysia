"""
OutboxDispatcher — publica en TaskQueue las filas de ``TaskDispatch``
pendientes (B08). Ver ``outbox.py`` para el porqué de la tabla y el diseño
general; este módulo es la mitad que sí toca Redis.
"""

from __future__ import annotations

import logging
from typing import Optional

from src.modules.infrastructure import UnitOfWork
from src.modules.infrastructure.session import build_repository
from src.modules.shared import utcnow_naive
from src.modules.shared._exceptions import IllegalStateError

from .outbox import decode_func
from .outbox_repository import TaskDispatchRepository
from .queue import ITaskQueue, TaskQueue

logger = logging.getLogger(__name__)


class OutboxDispatcher:
    """Publica en TaskQueue las filas de ``TaskDispatch`` pendientes."""

    @staticmethod
    def dispatch(dispatch_id: int, task_queue: Optional[ITaskQueue] = None) -> bool:
        """Intenta publicar una fila concreta de ``TaskDispatch`` en TaskQueue.

        Efectos secundarios sobre la fila:
            - Éxito: ``status="dispatched"``, ``dispatched_at`` a ahora.
            - Ya publicada por un intento anterior (``IllegalStateError`` con
              el job todavía "started"): se marca ``dispatched`` sin volver a
              publicar -- ver el docstring de ``outbox.py``.
            - Cualquier otro fallo (típicamente Redis caído): ``attempts`` y
              ``last_error`` se actualizan, la fila se queda ``pending`` para
              el próximo intento.

        Ese cambio se confirma en el acto, también dentro de una request: la
        fila describe algo que ya pasó fuera de la BD -- el job está o no está
        en Redis --, así que no puede depender de cómo acabe la request. Si
        la request lanzaba después (``IrisMailboxManager._mark_reauth_required``
        lo hace desde ``update_connection``), el rollback del teardown devolvía
        a ``pending`` una fila ya publicada y el barrido la republicaba: el
        mismo correo, dos veces. Todos los llamantes confirman su
        entidad justo antes de llamar aquí, así que este commit no arrastra
        nada suyo.

        Args:
            dispatch_id: Primary key de la fila ``TaskDispatch`` a publicar.
            task_queue: ``ITaskQueue`` a usar para publicar. Por defecto
                ``None``, que resuelve a ``TaskQueue.get_instance()`` (el
                singleton real respaldado por Redis) -- pásalo explícitamente
                para reutilizar el mismo ``ITaskQueue`` inyectado del manager
                llamante (p.ej. en tests) o para publicar contra un doble.

        Returns:
            bool: ``True`` si la fila quedó ``dispatched`` (ahora mismo, o ya
                lo estaba de un intento anterior); ``False`` si el intento de
                publicar falló y la fila sigue ``pending``, o si
                ``dispatch_id`` no existe.
        """
        with UnitOfWork() as uow:
            repo = TaskDispatchRepository(uow)
            dispatch = repo.get_by_id(dispatch_id)
            if dispatch is None:
                return False
            if dispatch.status == "dispatched":
                return True

            try:
                func = decode_func(dispatch.func_path)
                (task_queue or TaskQueue.get_instance()).submit(
                    func=func, name=dispatch.name, category=dispatch.category,
                    args=tuple(dispatch.args or []), kwargs=dict(dispatch.kwargs or {}),
                    external_id=dispatch.external_id, timeout=dispatch.timeout,
                )
            except IllegalStateError:
                pass
            except Exception as e:  # pylint: disable=broad-exception-caught
                dispatch.attempts += 1
                dispatch.last_error = str(e)[:2000]
                repo.update(dispatch)
                uow.commit_for_handoff()
                logger.warning(
                    "No se pudo publicar TaskDispatch %s (%s intento(s)): %s",
                    dispatch_id, dispatch.attempts, e,
                )
                return False

            dispatch.status = "dispatched"
            dispatch.dispatched_at = utcnow_naive()
            repo.update(dispatch)
            uow.commit_for_handoff()
            return True

    @staticmethod
    def dispatch_pending(limit: int = 100) -> int:
        """Barrido: publica todas las filas de ``TaskDispatch`` que sigan
        ``pending``, hasta ``limit``.

        Se llama al arrancar la API (reconcilia lo que quedó de una caída
        anterior) y periódicamente mientras vive (``TaskDispatchScheduler``),
        para recuperarse de una caída de Redis sin esperar a un reinicio.

        Args:
            limit: Máximo de filas ``pending`` a procesar en esta pasada. Por
                defecto ``100`` -- una cota, no una promesa de que se vacíe
                la cola entera de una vez si hay más pendientes que eso.

        Returns:
            int: Cuántas filas quedaron ``dispatched`` en esta pasada
                (incluye las que ya lo estaban de un intento anterior).
        """
        pending_ids = [
            row.id for row in build_repository(TaskDispatchRepository).get_pending(limit)
        ]
        return sum(1 for dispatch_id in pending_ids if OutboxDispatcher.dispatch(dispatch_id))
