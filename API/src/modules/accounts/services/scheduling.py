"""
Scheduler de la capa comercial: un solo job, y solo para avisar.

Independiente de los de Themis, Hygeia e Iris por el mismo criterio que ellos
entre sí: engancharse a otro acoplaría dos módulos que hoy no se conocen, solo
porque ambos usan APScheduler.

Lo importante de este scheduler es lo que **no** hace. No degrada suscripciones
ni aplica caducidades: eso se calcula al leer (``is_effective``). Si no corre,
lo único que se pierde es un correo.
"""

from __future__ import annotations

import logging
from typing import Optional

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from src.modules.infrastructure.scheduling import make_background_scheduler, scheduler_job

from .notices import send_subscription_notices

logger = logging.getLogger(__name__)


class AccountsScheduler:
    """Ciclo de vida del job de avisos de suscripción."""

    _scheduler: Optional[BackgroundScheduler] = None

    @classmethod
    def start(cls) -> None:
        """Arranca el scheduler. Idempotente."""
        if cls._scheduler is not None:
            return

        cls._scheduler = make_background_scheduler()
        cls._scheduler.add_job(
            func=cls._run_notices,
            # Una vez al día a las 9:00 UTC. No hace falta más: avisar de algo
            # que pasa dentro de tres días no gana nada por mirarse cada hora, y
            # sí perdería si mandara el mismo correo varias veces.
            trigger=CronTrigger(hour=9, minute=0),
            id="accounts_subscription_notices",
            replace_existing=True,
            max_instances=1,
            name="Avisos de suscripcion",
        )
        cls._scheduler.start()
        logger.info("Scheduler de accounts iniciado")

    @classmethod
    def stop(cls) -> None:
        if cls._scheduler is not None:
            cls._scheduler.shutdown(wait=False)
            cls._scheduler = None

    @staticmethod
    @scheduler_job(logger, "Fallo enviando los avisos de suscripcion")
    def _run_notices() -> None:
        send_subscription_notices()
