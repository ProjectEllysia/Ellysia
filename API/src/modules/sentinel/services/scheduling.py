
import logging

from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional

from apscheduler.schedulers.background import BackgroundScheduler as _BgScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from croniter import croniter
from sqlalchemy.orm import Session

from src.modules.infrastructure import UnitOfWork
from src.modules.infrastructure.unit_of_work import close_all
from src.modules.infrastructure.retry import retry_on_transient
from src.modules.shared import utcnow_naive

from ..exceptions import InvalidProgramedTaskArgumentError
from ..repositories import ProgramedScanRepository
from ..model import Scan, ScanStatus, ScanType

logger = logging.getLogger(__name__)


def _require_args(
    arguments: dict[str, Any],
    required: list[str],
    scan_type: str,
) -> None:
    for field in required:
        if arguments.get(field) is None:
            raise InvalidProgramedTaskArgumentError(scan_type, field)


# =============================================================================
# SCAN RUNNERS
# -----------------------------------------------------------------------------
# Each runner only depends on plain data (ids + arguments), never on an
# ORM-attached ProgramedScan. This matters because the scan managers open their
# own UnitOfWork, which in a scheduler thread shares — and then closes — the
# thread-scoped SQLAlchemy session. Passing primitives keeps these functions
# free of detached-instance hazards.
# =============================================================================

def _run_nmap_scan(ps_id: int, user_id: int, arguments: dict[str, Any]) -> None:
    _require_args(arguments, ["target_host", "target_ports"], "nmap")

    logger.info(
        "Launching Nmap scheduled scan #%d: %s ports %s",
        ps_id, arguments["target_host"], arguments["target_ports"],
    )

    from ..managers import NmapScanManager

    scan_id = NmapScanManager().run_scan(
        target_host=arguments["target_host"],
        target_ports=arguments["target_ports"],
        user_id=user_id,
        programed_scan_id=ps_id,
    )

    logger.info("Nmap scheduled scan #%d launched (scan_id=%d)", ps_id, scan_id)


def _run_nikto_scan(ps_id: int, user_id: int, arguments: dict[str, Any]) -> None:
    _require_args(arguments, ["target_domain"], "nikto")

    logger.info("Launching Nikto scheduled scan #%d: %s", ps_id, arguments["target_domain"])

    from ..managers import NiktoScanManager

    scan_id = NiktoScanManager().run_scan(
        target_domain=arguments["target_domain"],
        user_id=user_id,
        programed_scan_id=ps_id,
    )

    logger.info("Nikto scheduled scan #%d launched (scan_id=%d)", ps_id, scan_id)


def _run_openvas_scan(ps_id: int, user_id: int, arguments: dict[str, Any]) -> None:
    _require_args(arguments, ["target"], "openvas")

    logger.info("Launching OpenVAS scheduled scan #%d: %s", ps_id, arguments["target"])

    from ..managers import OpenVASScanManager

    scan_id = OpenVASScanManager().run_scan(
        target=arguments["target"],
        user_id=user_id,
        programed_scan_id=ps_id,
    )

    logger.info("OpenVAS scheduled scan #%d launched (scan_id=%d)", ps_id, scan_id)


class Scheduler:

    _TASK_MAPPING: dict[ScanType, Callable[[int, int, dict[str, Any]], None]] = {
        ScanType.NMAP:    _run_nmap_scan,
        ScanType.NIKTO:   _run_nikto_scan,
        ScanType.OPENVAS: _run_openvas_scan,
    }

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
        # timezone=UTC para alinear los tiempos internos de APScheduler (incluido
        # job.next_run_time) con las columnas DateTime naive-UTC de la BD.
        # job_defaults.misfire_grace_time: APScheduler por defecto es 1 segundo.
        # Con eso, cualquier retraso mínimo del hilo del scheduler (otro scan
        # corriendo, GIL ocupado) hace que el disparo se descarte en vez de
        # ejecutarse tarde — el WARNING "Run time... was missed" y el escaneo
        # que nunca se lanza. 60s da margen sin arriesgar solapes reales.
        cls._scheduler = _BgScheduler(
            timezone=timezone.utc,
            job_defaults={"misfire_grace_time": 60},
        )
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
        """Register the nightly Ellysia KB sync job, if enabled in config.

        Deferred imports avoid a circular dependency (managers import this
        module transitively). The job is a plain recurring cron, independent of
        the per-user ProgramedScan jobs.
        """
        import src.modules.system.config_reading as CR
        if not CR.is_kb_sync_enabled():
            return
        from ..managers import KbSyncManager
        cls._scheduler.add_job(  # type: ignore[union-attr]
            func=KbSyncManager.execute_kb_sync,
            trigger=CronTrigger.from_crontab(CR.get_kb_sync_cron(), timezone=timezone.utc),
            id="ellysia_kb_sync",
            replace_existing=True,
            max_instances=1,
            name="Ellysia KB sync",
        )
        logger.info("Scheduled Ellysia KB sync (%s)", CR.get_kb_sync_cron())

    @classmethod
    def _sync_from_db(cls) -> None:
        if cls._scheduler is None:
            return
        with UnitOfWork() as uow:
            repo = ProgramedScanRepository(uow)
            active = repo.get_all_active()
            for ps in active:
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
            logger.info("Synced %d active scans from database", len(active))

    @staticmethod
    def _has_active_run(session: Session, ps_id: int) -> bool:
        """True if the programed scan already has a pending/running scan."""
        return (
            session.query(Scan)
            .filter(
                Scan.programed_scan_id == ps_id,
                Scan.status.in_([ScanStatus.PENDING.value, ScanStatus.RUNNING.value]),
            )
            .first()
            is not None
        )

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

            if ScanType(ps.scan_type) not in cls._TASK_MAPPING:
                raise ValueError(f"Unknown scan type: {ps.scan_type}")

            if cls._has_active_run(uow.session, ps.id):
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
    def execute(cls, ps_id: int) -> None:
        """Fire a programed scan: launch it and advance its run timestamps.

        Split into three phases on purpose. The scan managers open their own
        UnitOfWork, and in this background thread that shares and then *closes*
        the thread-scoped session — detaching any ORM object loaded before the
        launch. Recording last_run_at / next_run_at therefore happens in a
        fresh session *after* the launch; otherwise the flush would target a
        detached ProgramedScan and the update would silently never persist
        (the cause of the stale "next run" shown in the UI).
        """
        logger.info("Triggered programed scan %d", ps_id)
        try:
            # Phase 1 — load, validate and guard against overlapping runs.
            params = cls._load_and_guard(ps_id)
            if params is None:
                return

            runner = cls._TASK_MAPPING[ScanType(params["scan_type"])]

            # Phase 2 — launch the scan (manager owns its own session).
            runner(ps_id, params["user_id"], params["arguments"])

            # Phase 3 — record the execution in a *fresh* session.
            now = utcnow_naive()
            next_run = cls.calculate_next_run(
                params["schedule_type"], params["schedule_config"], last_run=now
            )
            cls._record_run(ps_id, now, next_run)

            logger.info(
                "Programed scan %d executed; next run at %s",
                ps_id, next_run.isoformat() if next_run else "N/A",
            )

        except Exception:
            logger.exception("Scheduled scan %d failed", ps_id)
        finally:
            # APScheduler corre en un hilo de vida larga y scoped_session está
            # keyed por hilo: sin esto, la sesión usada en este disparo quedaría
            # pegada al hilo y un estado abortado envenenaría el siguiente.
            close_all()

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
