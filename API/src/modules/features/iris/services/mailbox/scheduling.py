"""
IrisMailboxScheduler — sondea las conexiones de buzón activas cada
``iris.pollIntervalMinutes`` y encola un job de sync por conexión vencida.

Mismo patrón que ``hygeia/services/scheduling.py::HygeiaScheduler``:
instancia propia de APScheduler (no compartida con Themis/Hygeia — acoplar
módulos hermanos solo por compartir el mecanismo de scheduling no aporta
nada). El job del scheduler NUNCA hace I/O de red/proveedor directamente:
solo decide qué conexiones están vencidas y las encola en TaskQueue, donde
corre el trabajo real (``IrisMailboxManager._sync_connection``) en un
proceso worker aislado.
"""

from __future__ import annotations

import logging
from datetime import timezone
from typing import Optional

from apscheduler.schedulers.background import BackgroundScheduler

import src.modules.system.config_reading as CR
from src.modules.infrastructure.session import build_repository
from src.modules.infrastructure.unit_of_work import close_all

from ...mailbox_managers import IrisMailboxManager
from ...repositories import IrisMailboxConnectionRepository

logger = logging.getLogger(__name__)


class IrisMailboxScheduler:
    """Ciclo de vida del scheduler de sondeo de buzones de Iris."""

    _scheduler: Optional[BackgroundScheduler] = None

    @classmethod
    def start(cls) -> None:
        """Arranca el scheduler y registra el job de sondeo. Idempotente."""
        if cls._scheduler is not None:
            return

        interval = CR.get_iris_poll_interval_minutes()
        cls._scheduler = BackgroundScheduler(
            timezone=timezone.utc,
            job_defaults={"misfire_grace_time": 60},
        )
        cls._scheduler.add_job(
            func=cls._poll_connections,
            trigger="interval",
            minutes=interval,
            id="iris_mailbox_poll",
            replace_existing=True,
            max_instances=1,
            name="Iris mailbox poll",
        )
        cls._scheduler.start()
        logger.info("Scheduler de buzones de Iris iniciado (cada %d min)", interval)

    @classmethod
    def stop(cls) -> None:
        """Detiene el scheduler. Idempotente."""
        if cls._scheduler is None:
            return
        cls._scheduler.shutdown(wait=True)
        cls._scheduler = None
        logger.info("Scheduler de buzones de Iris detenido")

    @staticmethod
    def _poll_connections() -> None:
        """Entry point del job: aísla errores y libera la sesión del hilo
        (mismo razonamiento que ``HygeiaScheduler._run_presence_check`` —
        APScheduler corre en un hilo de vida larga y ``scoped_session`` está
        keyed por hilo)."""
        try:
            interval = CR.get_iris_poll_interval_minutes()
            due = build_repository(IrisMailboxConnectionRepository).get_due_for_sync(interval)
            manager = IrisMailboxManager()
            for connection in due:
                manager.submit_sync(connection.id)
            if due:
                logger.info("Sondeo de buzones de Iris: %d conexión(es) encolada(s)", len(due))
        except Exception:
            logger.exception("Error sondeando conexiones de buzón de Iris")
        finally:
            close_all()
