"""Scheduler de avisos de seguridad de la capa de usuarios."""

from __future__ import annotations

import logging
from typing import Optional

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from src.modules.infrastructure.scheduling import make_background_scheduler, scheduler_job

from .mfa_notices import send_mfa_reminders

logger = logging.getLogger(__name__)


class UsersScheduler:
    """Ciclo de vida del job periódico de recordatorios MFA."""

    _scheduler: Optional[BackgroundScheduler] = None

    @classmethod
    def start(cls) -> None:
        """Arranca el scheduler. Idempotente."""
        if cls._scheduler is not None:
            return

        cls._scheduler = make_background_scheduler()
        cls._scheduler.add_job(
            func=cls._run_mfa_reminders,
            # La cadencia de envío real la decide last_mfa_reminder_at y la
            # configuración; revisar a diario evita depender de un reinicio.
            trigger=CronTrigger(hour=9, minute=0),
            id="users_mfa_reminders",
            replace_existing=True,
            max_instances=1,
            name="Recordatorios de MFA",
        )
        cls._scheduler.start()
        logger.info("Scheduler de users iniciado")

    @classmethod
    def stop(cls) -> None:
        if cls._scheduler is not None:
            cls._scheduler.shutdown(wait=False)
            cls._scheduler = None

    @staticmethod
    @scheduler_job(logger, "Fallo enviando los recordatorios MFA")
    def _run_mfa_reminders() -> None:
        send_mfa_reminders()
