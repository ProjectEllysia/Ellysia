"""La reconciliación de arranque no mata escaneos que siguen vivos.

``ScanManager.reconcile_orphaned_scans()`` corre una vez al arrancar la API y
existe para rescatar registros que quedaron colgados cuando el proceso murió a
mitad: sin ella, un escaneo se queda en ``running`` para siempre y bloquea que
el scheduler vuelva a lanzar ese escaneo programado.

El criterio era demasiado agresivo. Conservaba el escaneo **solo** si su tarea
estaba exactamente en ``PENDING`` y marcaba como fallido todo lo demás — pero
los workers son procesos aparte, y reiniciar la API no los para. Un job
``RUNNING`` puede estar escaneando ahora mismo en otro proceso.

Lo que veía el usuario era una contradicción: el escaneo aparecía como fallido
y, minutos más tarde, el worker terminaba y escribía ``finished`` encima de esa
misma fila.

Es el mismo defecto que Iris arregló en #208, y no por casualidad: esta
reconciliación fue el original del que aquélla se copió. Estos tests son el
espejo de ``test_iris_reconciliation.py``, con la diferencia de que aquí el
método es un ``classmethod`` sobre una clase abstracta que barre los escaneos de
los cuatro escáneres a la vez.
"""

from __future__ import annotations

from datetime import datetime
from typing import Callable, Optional
from unittest import mock

import pytest

from src.modules.infrastructure import UnitOfWork
from src.modules.system.taskqueue import Task, TaskStatus

import src.modules.features.themis.managers.scan as scan_mod
from src.modules.features.themis.managers import ScanManager
from src.modules.features.themis.model import NmapScan, ScanStatus
from src.modules.features.themis.repositories import ScanRepository

pytestmark = pytest.mark.integration


class _FakeQueue:
    """Cola fake que responde lo que el test necesite por external_id.

    ``recoverable`` modela la respuesta de ``is_recoverable()``, que en la
    implementación real combina el estado del job con la comprobación de si el
    worker que lo tomó sigue vivo. Aquí se declara directamente: lo que estos
    tests fijan es qué hace la reconciliación con esa respuesta, no cómo la
    calcula la cola.
    """

    def __init__(self, tasks_by_external_id: dict, recoverable: Optional[dict] = None):
        self._tasks = tasks_by_external_id
        self._recoverable = recoverable or {}

    def get_task_by_external_id(self, external_id: str, category: Optional[str] = None):
        return self._tasks.get(external_id)

    def is_recoverable(self, external_id: str, category: Optional[str] = None) -> bool:
        if external_id in self._recoverable:
            return self._recoverable[external_id]
        task = self._tasks.get(external_id)
        return task is not None and task.status is TaskStatus.PENDING

    def submit(self, func: Callable, **kwargs): raise NotImplementedError
    def cancel(self, task_id: str) -> bool: return True
    def get_task(self, task_id: str): return None
    def update_progress(self, task_id: str, progress: int) -> None: pass
    def is_cancelled(self, task_id: str) -> bool: return False
    def clear_cancel_signal(self, task_id: str) -> None: pass


def _make_scan(app, user_id: int, status: str) -> int:
    with app.app_context():
        with UnitOfWork() as uow:
            scan = NmapScan(target="10.0.0.5", user_id=user_id,
                            started_at=datetime.now(), status=status)
            ScanRepository(uow).save(scan)
            return scan.id


def _reconcile(app, queue) -> int:
    with app.app_context():
        with mock.patch.object(scan_mod.TaskQueue, "get_instance", return_value=queue):
            return ScanManager.reconcile_orphaned_scans()


def _status_of(app, scan_id: int) -> str:
    with app.app_context():
        with UnitOfWork() as uow:
            return ScanRepository(uow).get_by_id(scan_id).status


def _task(external_id: str, status: TaskStatus) -> Task:
    return Task(id="job1", name="job1", category="themis.scan",
                external_id=external_id, status=status)


def test_a_scan_without_any_task_is_marked_failed(app, admin_user):
    """Sin tarea en la cola no queda nadie que vaya a terminar el escaneo.

    Es el caso para el que la reconciliación existe: el proceso murió antes de
    encolar, o el job caducó del historial.
    """
    scan_id = _make_scan(app, admin_user.id, ScanStatus.RUNNING.value)

    assert _reconcile(app, _FakeQueue({})) == 1
    assert _status_of(app, scan_id) == ScanStatus.FAILED.value


def test_a_queued_scan_is_left_alone(app, admin_user):
    """Un job en cola lo tomará el primer worker libre: no está huérfano."""
    scan_id = _make_scan(app, admin_user.id, ScanStatus.PENDING.value)
    external_id = f"scan:{scan_id}"
    queue = _FakeQueue({external_id: _task(external_id, TaskStatus.PENDING)})

    assert _reconcile(app, queue) == 0
    assert _status_of(app, scan_id) == ScanStatus.PENDING.value


def test_a_running_scan_whose_worker_is_alive_is_left_alone(app, admin_user):
    """El caso que motiva el arreglo.

    El worker está escaneando ahora mismo en otro proceso. Con el criterio
    viejo —conservar sólo si el estado es exactamente ``PENDING``— este escaneo
    se marcaba ``failed``, el usuario lo veía fallido, y poco después el worker
    escribía ``finished`` encima de la misma fila.
    """
    scan_id = _make_scan(app, admin_user.id, ScanStatus.RUNNING.value)
    external_id = f"scan:{scan_id}"
    queue = _FakeQueue(
        {external_id: _task(external_id, TaskStatus.RUNNING)},
        recoverable={external_id: True},   # su worker sigue vivo
    )

    assert _reconcile(app, queue) == 0
    assert _status_of(app, scan_id) == ScanStatus.RUNNING.value


def test_a_running_scan_whose_worker_died_is_marked_failed(app, admin_user):
    """La otra mitad, y la razón de que no baste con mirar el estado del job.

    Un job sigue figurando como ``RUNNING`` cuando su worker muere de golpe:
    nadie está ahí para cambiarlo. Eso sí es un huérfano, y distinguirlo del
    caso de arriba es justo lo que hace ``is_recoverable`` comprobando el PID
    del worker.
    """
    scan_id = _make_scan(app, admin_user.id, ScanStatus.RUNNING.value)
    external_id = f"scan:{scan_id}"
    queue = _FakeQueue(
        {external_id: _task(external_id, TaskStatus.RUNNING)},
        recoverable={external_id: False},   # el worker ya no está
    )

    assert _reconcile(app, queue) == 1
    assert _status_of(app, scan_id) == ScanStatus.FAILED.value


def test_a_completed_job_over_a_still_active_scan_is_marked_failed(app, admin_user):
    """Un job terminado sobre una fila que sigue activa es una fila colgada: el
    worker acabó sin llegar a escribir el estado final."""
    scan_id = _make_scan(app, admin_user.id, ScanStatus.RUNNING.value)
    external_id = f"scan:{scan_id}"
    queue = _FakeQueue({external_id: _task(external_id, TaskStatus.COMPLETED)})

    assert _reconcile(app, queue) == 1
    assert _status_of(app, scan_id) == ScanStatus.FAILED.value


def test_scans_of_every_scanner_are_swept_together(app, admin_user):
    """La reconciliación se invoca sobre ``ScanManager``, la clase abstracta, y
    recorre los escaneos activos de los cuatro escáneres.

    Funciona porque los cuatro heredan el mismo ``EXTERNAL_ID_PREFIX`` y la
    misma ``TASK_CATEGORY``. Si algún escáner futuro declarase los suyos
    propios, sus escaneos se marcarían como huérfanos aunque estuvieran vivos —
    este test es donde eso se notaría.
    """
    from src.modules.features.themis.managers import (
        NmapScanManager, NiktoScanManager, NucleiScanManager, LybraEngineManager,
    )

    prefixes = {manager.EXTERNAL_ID_PREFIX for manager in
                (NmapScanManager, NiktoScanManager, NucleiScanManager, LybraEngineManager)}
    categories = {manager.TASK_CATEGORY for manager in
                  (NmapScanManager, NiktoScanManager, NucleiScanManager, LybraEngineManager)}

    assert prefixes == {ScanManager.EXTERNAL_ID_PREFIX}
    assert categories == {ScanManager.TASK_CATEGORY}
