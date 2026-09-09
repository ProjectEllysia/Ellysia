"""
IrisMailboxScheduler — sondea las conexiones de buzón activas cada
``iris.pollIntervalMinutes`` y encola un job de sync por conexión vencida.
También registra el chequeo periódico de notificaciones de M08 (digests
diarios pendientes y avisos de conexión atascada) -- ver el docstring de
``services/notifications/scheduling.py`` sobre por qué comparte este
scheduler en vez de tener uno propio.

Mismo patrón que ``hygeia/services/scheduling.py::HygeiaScheduler``:
instancia propia de APScheduler (no compartida con Themis/Hygeia — acoplar
módulos hermanos solo por compartir el mecanismo de scheduling no aporta
nada), con más de un job registrado sobre ella. Ninguno de los dos jobs hace
I/O de red/proveedor directamente: el de sondeo solo decide qué conexiones
están vencidas y las encola en TaskQueue, donde corre el trabajo real
(``IrisMailboxManager._sync_connection``) en un proceso worker aislado; el
de notificaciones solo consulta la base de datos y encola sobre la misma
cola.
"""

from __future__ import annotations

import logging
from typing import Optional

from apscheduler.schedulers.background import BackgroundScheduler

import src.modules.system.config_reading as CR
from src.modules.infrastructure.session import build_repository
from src.modules.infrastructure.scheduling import make_background_scheduler, scheduler_job

from ...managers.mailbox import IrisMailboxManager
from ...repositories import IrisMailboxConnectionRepository
from ..notifications.scheduling import check_and_notify

logger = logging.getLogger(__name__)


class IrisMailboxScheduler:
    """Ciclo de vida del scheduler de sondeo de buzones de Iris."""

    _scheduler: Optional[BackgroundScheduler] = None

    @classmethod
    def start(cls) -> None:
        """Arranca el scheduler y registra sus jobs. Idempotente."""
        if cls._scheduler is not None:
            return

        interval = CR.iris_config().poll_interval_minutes
        notification_interval = CR.iris_config().notification_check_interval_minutes
        cls._scheduler = make_background_scheduler()
        cls._scheduler.add_job(
            func=cls._poll_connections,
            trigger="interval",
            minutes=interval,
            id="iris_mailbox_poll",
            replace_existing=True,
            max_instances=1,
            name="Iris mailbox poll",
        )
        cls._scheduler.add_job(
            func=cls._run_notifications,
            trigger="interval",
            minutes=notification_interval,
            id="iris_notification_check",
            replace_existing=True,
            max_instances=1,
            name="Iris notification check",
        )
        cls._scheduler.start()
        logger.info(
            "Scheduler de buzones de Iris iniciado (sondeo cada %d min, notificaciones cada %d min)",
            interval, notification_interval,
        )

    @classmethod
    def stop(cls) -> None:
        """Detiene el scheduler. Idempotente."""
        if cls._scheduler is None:
            return
        cls._scheduler.shutdown(wait=True)
        cls._scheduler = None
        logger.info("Scheduler de buzones de Iris detenido")

    @staticmethod
    @scheduler_job(logger, "Error sondeando conexiones de buzón de Iris")
    def _poll_connections() -> None:
        """Entry point del job (aislamiento de errores y cierre de sesión vía ``scheduler_job``)."""
        interval = CR.iris_config().poll_interval_minutes
        due = build_repository(IrisMailboxConnectionRepository).get_due_for_sync(interval)
        manager = IrisMailboxManager()
        queued = 0
        for connection in due:
            try:
                manager.submit_sync(connection.id)
                queued += 1
            except Exception as e:
                # B02: una conexión que no se puede encolar (p.ej. ya hay un
                # job "started" con el mismo job_id determinista) no debe
                # tumbar el resto del sondeo -- cada conexión es
                # independiente de sus vecinas en la lista de vencidas.
                logger.warning(f"No se pudo encolar el sync de la conexión {connection.id}: {e}")
        if queued:
            logger.info("Sondeo de buzones de Iris: %d conexión(es) encolada(s)", queued)

    @staticmethod
    @scheduler_job(logger, "Error revisando notificaciones de Iris")
    def _run_notifications() -> None:
        """Entry point del job de notificaciones de M08 (aislamiento de
        errores y cierre de sesión vía ``scheduler_job``)."""
        check_and_notify()
