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
from src.modules.infrastructure.unit_of_work import close_all

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

        # timezone=UTC y misfire_grace_time, por la misma razón que en el
        # Scheduler de Themis: alinea next_run_time con las columnas naive-UTC
        # del esquema, y da margen para que un retraso mínimo del hilo del
        # scheduler no descarte el disparo en vez de ejecutarlo tarde.
        cls._scheduler = BackgroundScheduler(
            timezone=timezone.utc,
            job_defaults={"misfire_grace_time": 60},
        )
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
    def _run_presence_check() -> None:
        """Entry point del job de presencia: aísla errores y libera la sesión del hilo.

        APScheduler corre en un hilo de vida larga y ``scoped_session`` está
        keyed por hilo: sin el ``close_all()`` del ``finally``, la sesión de
        este disparo quedaría pegada al hilo y un estado abortado
        envenenaría el siguiente (mismo razonamiento que ``Scheduler.execute``
        en Themis).
        """
        try:
            HygeiaMaintenanceManager.execute_presence_check()
        except Exception:
            logger.exception("Error en el chequeo de presencia de Hygeia")
        finally:
            close_all()

    @staticmethod
    def _run_retention() -> None:
        """Entry point del job de retención: aísla errores y libera la sesión del hilo."""
        try:
            deleted = HygeiaMaintenanceManager.execute_retention()
            logger.info("Retención de Hygeia: %d snapshot(s) eliminado(s)", deleted)
        except Exception:
            logger.exception("Error en la poda de snapshots de Hygeia")
        finally:
            close_all()
