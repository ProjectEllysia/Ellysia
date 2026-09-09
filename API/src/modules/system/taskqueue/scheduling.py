"""
TaskDispatchScheduler — reintenta periódicamente los ``TaskDispatch`` que
sigan ``pending`` (B08 outbox, ver ``outbox.py``).

El intento inmediato tras el commit (``OutboxDispatcher.dispatch()`` llamado
desde el propio manager) cubre el caso normal. Este scheduler es la red de
seguridad para cuando ese intento falló porque Redis estaba caído justo en
ese momento: sin este barrido, la fila se quedaría ``pending`` hasta el
próximo reinicio de la API (que sí reconcilia al arrancar, ver
``run.py::_configure_scheduling``), y un despliegue puede pasar horas sin
reiniciarse.
"""

from __future__ import annotations

import logging
from typing import Optional

from apscheduler.schedulers.background import BackgroundScheduler

import src.modules.system.config_reading as CR
from src.modules.infrastructure.scheduling import make_background_scheduler, scheduler_job

from .dispatcher import OutboxDispatcher

logger = logging.getLogger(__name__)


class TaskDispatchScheduler:
    """Ciclo de vida del scheduler de barrido de la outbox de TaskQueue."""

    _scheduler: Optional[BackgroundScheduler] = None

    @classmethod
    def start(cls) -> None:
        """Arranca el scheduler y registra el job de barrido. Idempotente."""
        if cls._scheduler is not None:
            return

        interval = CR.taskqueue_config().outbox_sweep_interval_seconds
        cls._scheduler = make_background_scheduler()
        cls._scheduler.add_job(
            func=cls._sweep,
            trigger="interval",
            seconds=interval,
            id="taskqueue_outbox_sweep",
            replace_existing=True,
            max_instances=1,
            name="TaskQueue outbox sweep",
        )
        cls._scheduler.start()
        logger.info("Scheduler de outbox de TaskQueue iniciado (cada %ds)", interval)

    @classmethod
    def stop(cls) -> None:
        """Detiene el scheduler. Idempotente."""
        if cls._scheduler is None:
            return
        cls._scheduler.shutdown(wait=True)
        cls._scheduler = None
        logger.info("Scheduler de outbox de TaskQueue detenido")

    @staticmethod
    @scheduler_job(logger, "Error en el barrido de la outbox de TaskQueue")
    def _sweep() -> None:
        """Entry point del job (aislamiento de errores y cierre de sesión vía ``scheduler_job``)."""
        dispatched = OutboxDispatcher.dispatch_pending()
        if dispatched:
            logger.info("Barrido de outbox: %d job(s) publicado(s)", dispatched)
