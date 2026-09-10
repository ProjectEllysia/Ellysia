"""
IrisMailboxScheduler — sondea las conexiones de buzón activas cada
``iris.pollIntervalMinutes`` y encola un job de sync por conexión vencida.
También registra el chequeo periódico de notificaciones (digests
diarios pendientes y avisos de conexión atascada) y el job de retención
(purgar raw vencido, borrar análisis enteros si hay un límite
duro configurado) -- ver los docstrings de ``services/notifications/
scheduling.py`` y ``services/retention.py`` sobre por qué comparten este
scheduler en vez de tener uno propio cada uno.

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
from ..retention import run_retention

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
        retention_interval = CR.iris_config().retention_check_interval_hours
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
        cls._scheduler.add_job(
            func=cls._run_retention,
            trigger="interval",
            hours=retention_interval,
            id="iris_retention",
            replace_existing=True,
            max_instances=1,
            name="Iris retention",
        )
        cls._scheduler.start()
        logger.info(
            "Scheduler de buzones de Iris iniciado (sondeo cada %d min, "
            "notificaciones cada %d min, retención cada %d h)",
            interval, notification_interval, retention_interval,
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
                # Una conexión que no se puede encolar (p.ej. ya hay un
                # job "started" con el mismo job_id determinista) no debe
                # tumbar el resto del sondeo -- cada conexión es
                # independiente de sus vecinas en la lista de vencidas.
                logger.warning(f"No se pudo encolar el sync de la conexión {connection.id}: {e}")
        if queued:
            logger.info("Sondeo de buzones de Iris: %d conexión(es) encolada(s)", queued)

    @staticmethod
    @scheduler_job(logger, "Error revisando notificaciones de Iris")
    def _run_notifications() -> None:
        """Entry point del job de notificaciones (aislamiento de
        errores y cierre de sesión vía ``scheduler_job``)."""
        check_and_notify()

    @staticmethod
    @scheduler_job(logger, "Error en la retención de Iris")
    def _run_retention() -> None:
        """Entry point del job de retención (aislamiento de
        errores y cierre de sesión vía ``scheduler_job``)."""
        run_retention()
