"""Tests de integración del ciclo de vida de escaneos programados.

Cubre la regresión reportada: tras ejecutar un escaneo programado, la fecha
del próximo escaneo no se reflejaba en la interfaz (aunque internamente, en
memoria, el trigger de APScheduler seguía siendo correcto). La causa era una
sesión de SQLAlchemy compartida por hilo: el ``UnitOfWork`` anidado que abren
los managers de escaneo (``NmapScanManager._create_scan_record``, etc.) cerraba
la sesión thread-local y dejaba el ``ProgramedScan`` cargado *detached*, de
modo que el ``flush`` posterior de ``last_run_at``/``next_run_at`` nunca
llegaba a la base de datos.

El escaneo real (nmap) se mockea: aquí solo importa el ciclo de
``ProgramedScan``, no la ejecución de la herramienta externa.
"""

from datetime import datetime, timedelta
from unittest import mock

import pytest

from src.modules.infrastructure import UnitOfWork
from src.modules.themis.managers import NmapScanManager, ProgramedScanManager
from src.modules.themis.model import NmapScan, ScanStatus, ScanType
from src.modules.themis.repositories import ProgramedScanRepository, ScanRepository
from src.modules.themis.services.scheduling import Scheduler

pytestmark = pytest.mark.integration

_ARGS = {"target_host": "127.0.0.1", "target_ports": "80"}
_SCHEDULE_CONFIG = {"every": 5, "unit": "minutes"}


def _register(app, user_id: int):
    with app.app_context():
        ps = ProgramedScanManager.register(
            user_id=user_id,
            scan_type=ScanType.NMAP,
            arguments=_ARGS,
            schedule_type="interval",
            schedule_config=_SCHEDULE_CONFIG,
        )
        return ps.id, ps.next_run_at


def _fetch(app, ps_id: int):
    with app.app_context():
        with UnitOfWork() as uow:
            return ProgramedScanRepository(uow).get_by_id(ps_id)


def test_execute_persists_run_timestamps_to_the_database(app, regular_user):
    """The bug: next_run_at must change in the DB, not just in memory."""
    ps_id, original_next_run = _register(app, regular_user.id)

    with mock.patch.object(NmapScanManager, "run_scan", return_value=999) as mock_run:
        with app.app_context():
            Scheduler.execute(ps_id)

    mock_run.assert_called_once()
    _, kwargs = mock_run.call_args
    assert kwargs["target_host"] == "127.0.0.1"
    assert kwargs["target_ports"] == "80"
    assert kwargs["programed_scan_id"] == ps_id

    refreshed = _fetch(app, ps_id)
    assert refreshed.last_run_at is not None
    assert refreshed.next_run_at is not None
    assert refreshed.next_run_at > original_next_run
    assert refreshed.next_run_at - refreshed.last_run_at == timedelta(minutes=5)


def test_execute_skips_when_a_run_is_already_active(app, regular_user):
    ps_id, _ = _register(app, regular_user.id)

    with app.app_context():
        with UnitOfWork() as uow:
            scan = NmapScan(
                target="127.0.0.1",
                user_id=regular_user.id,
                programed_scan_id=ps_id,
                status=ScanStatus.RUNNING.value,
            )
            ScanRepository(uow).save(scan)

    with mock.patch.object(NmapScanManager, "run_scan") as mock_run:
        with app.app_context():
            Scheduler.execute(ps_id)

    mock_run.assert_not_called()
    assert _fetch(app, ps_id).last_run_at is None


def test_execute_skips_inactive_programed_scan(app, regular_user):
    ps_id, _ = _register(app, regular_user.id)

    with app.app_context():
        with UnitOfWork() as uow:
            repo = ProgramedScanRepository(uow)
            ps = repo.get_by_id(ps_id)
            ps.is_active = False
            repo.update(ps)

    with mock.patch.object(NmapScanManager, "run_scan") as mock_run:
        with app.app_context():
            Scheduler.execute(ps_id)

    mock_run.assert_not_called()
    assert _fetch(app, ps_id).last_run_at is None


def test_execute_on_missing_programed_scan_does_not_raise(app):
    with mock.patch.object(NmapScanManager, "run_scan") as mock_run:
        with app.app_context():
            Scheduler.execute(999_999)  # ya no existe / nunca existió

    mock_run.assert_not_called()


def test_register_with_cron_schedule_does_not_run_immediately(app, regular_user):
    """Regresión del bug del repositorio: para cron, next_run_at se igualaba
    a ``datetime.utcnow()`` (ejecución inmediata) en lugar de calcular la
    próxima ocurrencia real vía croniter."""
    with app.app_context():
        ps = ProgramedScanManager.register(
            user_id=regular_user.id,
            scan_type=ScanType.NMAP,
            arguments=_ARGS,
            schedule_type="cron",
            schedule_config={"cron": "0 0 * * *"},
        )
        assert ps.next_run_at > datetime.utcnow()


def test_sync_from_db_refreshes_stale_next_run_on_restart(app, regular_user):
    """Al reiniciar la app después de la hora X, _sync_from_db reprograma el job
    y reescribe next_run_at con el próximo disparo real (futuro), en lugar de
    dejar el valor pasado/obsoleto que mostraba la UI."""
    ps_id, _ = _register(app, regular_user.id)

    # Simula una BD con next_run_at ya vencido (la app estuvo caída más allá de X).
    stale = datetime.utcnow() - timedelta(hours=1)
    with app.app_context():
        with UnitOfWork() as uow:
            repo = ProgramedScanRepository(uow)
            ps = repo.get_by_id(ps_id)
            ps.next_run_at = stale
            repo.update(ps)

    with app.app_context():
        Scheduler.stop()  # parte de un estado limpio (singleton de clase)
        try:
            Scheduler.start()  # arranca el scheduler real y llama a _sync_from_db
            with UnitOfWork() as uow:
                refreshed = ProgramedScanRepository(uow).get_by_id(ps_id)
                next_run = refreshed.next_run_at
            # Se reanuda desde ahora: la próxima ejecución es futura, no la pasada.
            assert next_run > datetime.utcnow()
            # Coincide (±60 s) con el next_run_time autoritativo de APScheduler.
            expected = datetime.utcnow() + timedelta(minutes=5)
            assert abs((next_run - expected).total_seconds()) < 60
        finally:
            Scheduler.stop()


def test_build_trigger_uses_utc(app):
    """Los triggers deben fijar UTC explícito; por defecto APScheduler usaría la
    zona local del servidor y el cron dispararía a una hora distinta de la que
    calcula croniter/la BD (UTC)."""
    interval = Scheduler._build_trigger("interval", {"every": 5, "unit": "minutes"})
    cron = Scheduler._build_trigger("cron", {"cron": "0 2 * * *"})
    assert str(interval.timezone) == "UTC"
    assert str(cron.timezone) == "UTC"
