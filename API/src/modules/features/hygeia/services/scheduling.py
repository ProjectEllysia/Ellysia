"""
hygeia.services.scheduling
────────────────────────────
Scheduler propio de Hygeia (APScheduler): detector de presencia (cada
minuto) y poda de snapshots (diaria, cron configurable).

Deliberadamente independiente del ``Scheduler`` de Themis — engancharse a
él acoplaría dos módulos hermanos que hoy son independientes, solo porque
ambos usan APScheduler. Mismo principio que el resto del módulo: nada de
importar de ``themis`` para ahorrarse una instancia de scheduler.
"""

from __future__ import annotations

import logging
from datetime import timezone
from typing import Optional

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

import src.modules.system.config_reading as CR
from src.modules.infrastructure.scheduling import make_background_scheduler, scheduler_job

from ..managers import HygeiaMaintenanceManager

logger = logging.getLogger(__name__)


class HygeiaScheduler:
    """Ciclo de vida del scheduler de mantenimiento de Hygeia."""

    _scheduler: Optional[BackgroundScheduler] = None

    @classmethod
    def start(cls) -> None:
        """Arranca el scheduler y registra sus jobs. Idempotente."""
        if cls._scheduler is not None:
            return

        cls._scheduler = make_background_scheduler()
        cls._scheduler.add_job(
            func=cls._run_presence_check,
            trigger="interval",
            seconds=60,
            id="hygeia_presence_check",
            replace_existing=True,
            max_instances=1,
            name="Hygeia presence check",
        )
        cls._scheduler.add_job(
            func=cls._run_retention,
            trigger=CronTrigger.from_crontab(CR.get_hygeia_retention_cron(), timezone=timezone.utc),
            id="hygeia_retention",
            replace_existing=True,
            max_instances=1,
            name="Hygeia snapshot retention",
        )
        cls._scheduler.start()
        logger.info("Scheduler de Hygeia iniciado")

    @classmethod
    def stop(cls) -> None:
        """Detiene el scheduler. Idempotente."""
        if cls._scheduler is None:
            return
        cls._scheduler.shutdown(wait=True)
        cls._scheduler = None
        logger.info("Scheduler de Hygeia detenido")

    @staticmethod
    @scheduler_job(logger, "Error en el chequeo de presencia de Hygeia")
    def _run_presence_check() -> None:
        """Entry point del job de presencia (aislamiento de errores y cierre de sesión vía ``scheduler_job``)."""
        HygeiaMaintenanceManager.execute_presence_check()

    @staticmethod
    @scheduler_job(logger, "Error en la poda de snapshots de Hygeia")
    def _run_retention() -> None:
        """Entry point del job de retención (aislamiento de errores y cierre de sesión vía ``scheduler_job``)."""
        deleted = HygeiaMaintenanceManager.execute_retention()
        logger.info("Retención de Hygeia: %d snapshot(s) eliminado(s)", deleted)
