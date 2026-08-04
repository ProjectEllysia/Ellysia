
import logging

from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from apscheduler.schedulers.background import BackgroundScheduler as _BgScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from croniter import croniter

from src.modules.infrastructure import UnitOfWork
from src.modules.infrastructure.retry import retry_on_transient
from src.modules.infrastructure.scheduling import make_background_scheduler, scheduler_job
from src.modules.shared import utcnow_naive

from ..exceptions import InvalidProgramedTaskArgumentError
from ..repositories import ProgramedScanRepository, ScanRepository
from ..model import ScanType

logger = logging.getLogger(__name__)


def _require_args(
    arguments: dict[str, Any],
    required: "tuple[str, ...] | list[str]",
    scan_type: str,
) -> None:
    for field in required:
        if arguments.get(field) is None:
            raise InvalidProgramedTaskArgumentError(scan_type, field)


class ThemisScheduler:

    _scheduler: Optional[_BgScheduler] = None

    # =========================================================================
    # JOB HELPERS
    # =========================================================================

    @classmethod
    def _build_job_id(cls, ps_id: int) -> str:
        return f"programed_scan_{ps_id}"

    @classmethod
    def _build_trigger(cls, schedule_type: str, schedule_config: dict):
        # timezone=UTC explícito: los triggers de APScheduler, por defecto, fijan
        # la zona LOCAL del servidor al construirse. Sin esto, un cron "0 2 * * *"
        # dispararía a las 02:00 locales mientras que calculate_next_run/croniter y
        # las columnas DateTime trabajan en UTC naive → la UI mostraría una hora
        # distinta a la real. Forzando UTC todo queda coherente.
        if schedule_type == "interval":
            every = int(schedule_config["every"])
            unit = schedule_config["unit"]
            return IntervalTrigger(**{unit: every}, timezone=timezone.utc)
        elif schedule_type == "cron":
            return CronTrigger.from_crontab(schedule_config["cron"], timezone=timezone.utc)
        else:
            raise ValueError(f"Unknown schedule_type: {schedule_type}")

    # =========================================================================
    # LIFECYCLE
    # =========================================================================

    @classmethod
    def start(cls) -> None:
        if cls._scheduler is not None:
            return
        cls._scheduler = make_background_scheduler()
        cls._scheduler.start()
        logger.info("Scheduler started")
        cls._sync_from_db()
        cls._schedule_kb_sync()

    @classmethod
    def stop(cls) -> None:
        if cls._scheduler is None:
            return
        cls._scheduler.shutdown(wait=True)
        cls._scheduler = None
        logger.info("Scheduler stopped")

    # =========================================================================
    # JOB MANAGEMENT
    # =========================================================================

    @classmethod
    def schedule(cls, ps_id: int, scan_type: str, user_id: int,
                 schedule_type: str, schedule_config: dict) -> None:
        if cls._scheduler is None:
            logger.warning("Scheduler not started, skipping schedule of %d", ps_id)
            return

        cls._scheduler.add_job(
            func=cls.execute,
            trigger=cls._build_trigger(schedule_type, schedule_config),
            args=[ps_id],
            id=cls._build_job_id(ps_id),
            replace_existing=True,
            max_instances=1,
            name=f"{scan_type} scan (user {user_id})",
        )
        logger.info("Scheduled scan %d: %s (%s)", ps_id, scan_type, schedule_type)

    @classmethod
    def unschedule(cls, ps_id: int) -> None:
        if cls._scheduler is None:
            return
        job = cls._scheduler.get_job(cls._build_job_id(ps_id))
        if job is not None:
            job.remove()
            logger.info("Unscheduled scan %d", ps_id)

    @classmethod
    def _job_next_run(cls, ps_id: int) -> Optional[datetime]:
        """APScheduler's authoritative next fire time for a job, as naive UTC.

        Returned right after ``add_job`` (no race), unlike reading it from inside
        ``execute``. ``None`` if the job is missing or paused.
        """
        if cls._scheduler is None:
            return None
        job = cls._scheduler.get_job(cls._build_job_id(ps_id))
        if job is None or job.next_run_time is None:
            return None
        return job.next_run_time.astimezone(timezone.utc).replace(tzinfo=None)

    # =========================================================================
    # INTERNALS
    # =========================================================================

    @classmethod
    def _schedule_kb_sync(cls) -> None:
        """Register the nightly Lybra KB sync job, if enabled in config.

        Deferred imports avoid a circular dependency (managers import this
        module transitively). The job is a plain recurring cron, independent of
        the per-user ProgramedScan jobs.
        """
        import src.modules.system.config_reading as CR
        if not CR.knowledge_base_config().enabled:
            return
        from ..managers import KbSyncManager
        cls._scheduler.add_job(  # type: ignore[union-attr]
            func=KbSyncManager.execute_kb_sync,
            trigger=CronTrigger.from_crontab(CR.knowledge_base_config().sync_cron, timezone=timezone.utc),
            id="lybra_kb_sync",
            replace_existing=True,
            max_instances=1,
            name="Lybra KB sync",
        )
        logger.info("Scheduled Lybra KB sync (%s)", CR.knowledge_base_config().sync_cron)

    @classmethod
    def _sync_from_db(cls) -> None:
        if cls._scheduler is None:
            return
        with UnitOfWork() as uow:
            repo = ProgramedScanRepository(uow)
            active_scans = repo.get_all_active()
            for ps in active_scans:
                cls.schedule(
                    ps_id=ps.id,
                    scan_type=ps.scan_type,
                    user_id=ps.user_id,
                    schedule_type=ps.schedule_type,
                    schedule_config=ps.schedule_config,
                )
                # Tras (re)programar, APScheduler ya conoce el próximo disparo real.
                # Persistirlo deja la UI coherente tras un reinicio en lugar de
                # mostrar un next_run_at pasado/obsoleto. Las ejecuciones perdidas
                # durante la caída NO se recuperan: el horario se reanuda desde
                # ahora (decisión de diseño, sin catch-up). El commit del UoW al
                # salir persiste el cambio.
                next_run = cls._job_next_run(ps.id)
                if next_run is not None:
                    ps.next_run_at = next_run
            logger.info("Synced %d active scans from database", len(active_scans))

    # =========================================================================
    # EXECUTION
    # =========================================================================

    @classmethod
    @retry_on_transient()
    def _load_and_guard(cls, ps_id: int) -> Optional[dict[str, Any]]:
        """Phase 1 — load, validate and guard against overlapping runs.

        Returns the launch parameters, or ``None`` when the scan should be
        skipped (deleted, inactive, or already pending/running). Retried on
        transient DB errors since a pure read is idempotent.
        """
        with UnitOfWork() as uow:
            ps = ProgramedScanRepository(uow).get_by_id(ps_id)
            if ps is None:
                logger.warning("Programed scan %d no longer exists, skipping", ps_id)
                return None
            if not ps.is_active:
                logger.info("Programed scan %d is inactive, skipping", ps_id)
                return None

            # Import perezoso: managers/__init__.py importa programed.py, que
            # importa services/__init__.py, que importa este módulo — un
            # import a nivel de módulo de ScanManager aquí cerraría el ciclo.
            from ..managers import ScanManager
            if ScanType(ps.scan_type) not in ScanManager._registry:  # pylint: disable=protected-access
                raise ValueError(f"Unknown scan type: {ps.scan_type}")

            if ScanRepository(uow).has_active_run_for_programed(ps.id):
                logger.info(
                    "Programed scan %d already has a pending/running scan, skipping",
                    ps.id,
                )
                return None

            return {
                "scan_type": ps.scan_type,
                "user_id": ps.user_id,
                "arguments": dict(ps.arguments or {}),
                "schedule_type": ps.schedule_type,
                "schedule_config": dict(ps.schedule_config or {}),
            }

    @classmethod
    @retry_on_transient()
    def _record_run(cls, ps_id: int, now: datetime, next_run: datetime) -> None:
        """Phase 3 — record the execution in a *fresh* session so the new
        next_run_at actually reaches the database (and thus the UI). Idempotent
        write (last value wins), so safe to retry on transient errors."""
        with UnitOfWork() as uow:
            repo = ProgramedScanRepository(uow)
            ps = repo.get_by_id(ps_id)
            if ps is not None:
                repo.update_run_timestamps(ps, last_run=now, next_run=next_run)

    @classmethod
    def _run_scheduled_scan(cls, ps_id: int, user_id: int, arguments: dict[str, Any], scan_type: ScanType) -> int:
        """Launch a scheduled scan of ``scan_type`` (B1).

        Despacha por el mismo ``ScanManager._registry`` que ``resolve_manager``
        usa — añadir un tipo de escaneo nuevo (y darlo de alta con
        ``@ScanManager.register``) es lo único que hace falta para que
        también sea programable, sin volver a tocar este scheduler.
        Solo depende de datos planos (ids + arguments), nunca de un
        ``ProgramedScan`` atado al ORM: los managers de escaneo abren su
        propio ``UnitOfWork``, que en un hilo del scheduler comparte — y
        luego cierra — la sesión del hilo.
        """
        from ..managers import ScanManager

        manager_class = ScanManager._registry[scan_type]  # pylint: disable=protected-access
        _require_args(arguments, manager_class.SCHEDULED_REQUIRED_ARGS, scan_type.value)

        logger.info("Launching %s scheduled scan #%d", scan_type.value, ps_id)

        scan_id = manager_class().run_scan(
            user_id=user_id, programed_scan_id=ps_id,
            **manager_class.scheduled_run_kwargs(arguments),
        )

        logger.info("%s scheduled scan #%d launched (scan_id=%d)", scan_type.value, ps_id, scan_id)
        return scan_id

    @staticmethod
    @scheduler_job(logger, "Scheduled scan %d failed")
    def execute(ps_id: int) -> None:
        """Fire a programed scan: launch it and advance its run timestamps.

        Split into three phases on purpose. The scan managers open their own
        UnitOfWork, and in this background thread that shares and then *closes*
        the thread-scoped session — detaching any ORM object loaded before the
        launch. Recording last_run_at / next_run_at therefore happens in a
        fresh session *after* the launch; otherwise the flush would target a
        detached ProgramedScan and the update would silently never persist
        (the cause of the stale "next run" shown in the UI).

        Aislamiento de errores y cierre de sesión vía ``@scheduler_job`` (B6)
        — antes reimplementaba ese try/except/finally a mano pese a ser el
        mismo helper que ya usan Hygeia e Iris. ``@staticmethod`` en vez de
        ``@classmethod`` porque ``scheduler_job`` reenvía sus ``*args`` al
        formateo ``%d`` del mensaje de error; con ``@classmethod`` el primer
        arg sería ``cls``, no ``ps_id``.
        """
        logger.info("Triggered programed scan %d", ps_id)
        # Phase 1 — load, validate and guard against overlapping runs.
        params = ThemisScheduler._load_and_guard(ps_id)
        if params is None:
            return

        # Phase 2 — launch the scan (manager owns its own session).
        ThemisScheduler._run_scheduled_scan(
            ps_id, params["user_id"], params["arguments"], ScanType(params["scan_type"]),
        )

        # Phase 3 — record the execution in a *fresh* session.
        now = utcnow_naive()
        next_run = ThemisScheduler.calculate_next_run(
            params["schedule_type"], params["schedule_config"], last_run=now
        )
        ThemisScheduler._record_run(ps_id, now, next_run)

        logger.info(
            "Programed scan %d executed; next run at %s",
            ps_id, next_run.isoformat() if next_run else "N/A",
        )

    @classmethod
    def calculate_next_run(
        cls,
        schedule_type: str,
        schedule_config: dict,
        last_run: Optional[datetime] = None,
    ) -> datetime:
        """Compute the next run time as a naive UTC datetime.

        Naive UTC keeps it consistent with ``utcnow_naive()`` used across the
        codebase and with the timezone-naive ``DateTime`` columns.
        """
        reference = last_run if last_run is not None else utcnow_naive()

        if schedule_type == "interval":
            every = int(schedule_config["every"])
            unit = schedule_config["unit"]
            try:
                return reference + timedelta(**{unit: every})
            except TypeError as exc:
                raise ValueError(f"Unknown interval unit: {unit}") from exc

        if schedule_type == "cron":
            return croniter(schedule_config["cron"], reference).get_next(datetime)

        raise ValueError(f"Unknown schedule_type: {schedule_type}")
