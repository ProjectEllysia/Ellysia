"""C1/B04: reconciliación de análisis Iris huérfanos tras un apagado abrupto.

Espejo de la reconciliación que ya existía para Themis (ScanManager.
reconcile_orphaned_scans) — sin esto, un análisis que queda en pending/running
cuando el proceso muere se queda así para siempre, porque no hay ninguna tarea
viva en TaskQueue que lo actualice tras reiniciar.

`B04` cambió el criterio. Antes se conservaba el análisis solo si su tarea
estaba exactamente en ``pending``, y eso se comía trabajo vivo: los workers son
procesos aparte, reiniciar la API no los para, y un job ``running`` puede estar
avanzando ahora mismo en otro proceso. La pregunta correcta no es "¿en qué
estado está el job?" sino "¿queda alguien que vaya a terminarlo?", que es lo que
responde ``TaskQueue.is_recoverable()``.
"""

from __future__ import annotations

from typing import Callable, Optional
from unittest import mock

import pytest

from src.modules.infrastructure import UnitOfWork
from src.modules.system.taskqueue import Task, TaskStatus

import src.modules.features.iris.managers.analysis as managers_mod
from src.modules.features.iris.model import IrisAnalysis
from src.modules.features.iris.repositories import IrisAnalysisRepository
from src.modules.features.iris.services.failures import FAILURE_WORKER_LOST

pytestmark = pytest.mark.integration


class _FakeQueue:
    """Cola fake que responde lo que el test necesite por external_id.

    ``recoverable`` modela la respuesta de ``is_recoverable()``, que en la
    implementación real combina el estado del job con la comprobación de si el
    worker que lo tomó sigue vivo. Aquí se declara directamente: lo que estos
    tests fijan es qué hace la reconciliación con esa respuesta, no cómo la
    calcula la cola (eso vive en ``tests/unit/test_taskqueue.py``).
    """

    def __init__(self, tasks_by_external_id: dict[str, Optional[Task]],
                 recoverable: Optional[dict[str, bool]] = None):
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


def _make_analysis(app, user_id, status="running"):
    with app.app_context():
        with UnitOfWork() as uow:
            analysis = IrisAnalysis(raw_headers="From: a@b.com", user_id=user_id, status=status)
            IrisAnalysisRepository(uow).save(analysis)
            return analysis.id


def _reconcile(app, queue) -> int:
    with app.app_context():
        with mock.patch.object(managers_mod.TaskQueue, "get_instance", return_value=queue):
            return managers_mod.IrisManager.reconcile_orphaned_analyses()


def _reload(app, analysis_id) -> IrisAnalysis:
    with app.app_context():
        with UnitOfWork() as uow:
            return IrisAnalysisRepository(uow).get_by_id(analysis_id)


def _task(external_id: str, status: TaskStatus) -> Task:
    return Task(id="job1", name="job1", category="iris.analyze",
                external_id=external_id, status=status)


def test_reconcile_marks_orphan_without_any_task_as_failed(app, regular_user):
    """Sin tarea en TaskQueue no hay nadie que vaya a terminar el análisis."""
    analysis_id = _make_analysis(app, regular_user.id, status="running")

    assert _reconcile(app, _FakeQueue({})) == 1
    assert _reload(app, analysis_id).status == "failed"


def test_reconcile_records_why_the_analysis_was_orphaned(app, regular_user):
    """Un `failed` sin explicación no le dice nada al usuario: aquí la causa no
    es que el motor fallara, sino que el proceso que lo ejecutaba desapareció."""
    analysis_id = _make_analysis(app, regular_user.id, status="running")

    _reconcile(app, _FakeQueue({}))

    analysis = _reload(app, analysis_id)
    assert analysis.failure_code == FAILURE_WORKER_LOST
    assert analysis.failure_reason
    assert analysis.finished_at is not None


def test_reconcile_leaves_still_queued_analysis_alone(app, regular_user):
    """Un job en cola lo tomará el primer worker libre: no está huérfano."""
    analysis_id = _make_analysis(app, regular_user.id, status="pending")
    external_id = f"iris-analysis:{analysis_id}"
    queue = _FakeQueue({external_id: _task(external_id, TaskStatus.PENDING)})

    assert _reconcile(app, queue) == 0
    assert _reload(app, analysis_id).status == "pending"


def test_reconcile_leaves_a_running_analysis_alone(app, regular_user):
    """El caso que motiva B04.

    El worker está analizando ahora mismo en otro proceso. Con el criterio
    viejo —conservar solo si el estado es exactamente ``pending``— este
    análisis se marcaba ``failed``, el usuario lo veía fallido, y poco después
    el worker escribía ``finished`` encima de esa misma fila.
    """
    analysis_id = _make_analysis(app, regular_user.id, status="running")
    external_id = f"iris-analysis:{analysis_id}"
    queue = _FakeQueue(
        {external_id: _task(external_id, TaskStatus.RUNNING)},
        recoverable={external_id: True},  # su worker sigue vivo
    )

    assert _reconcile(app, queue) == 0
    analysis = _reload(app, analysis_id)
    assert analysis.status == "running"
    assert analysis.finished_at is None


def test_reconcile_recovers_a_running_analysis_whose_worker_died(app, regular_user):
    """Mismo estado ``running``, decisión contraria: si el worker que tomó el
    job ya no existe, nadie va a leer su señal ni a escribir su resultado."""
    analysis_id = _make_analysis(app, regular_user.id, status="running")
    external_id = f"iris-analysis:{analysis_id}"
    queue = _FakeQueue(
        {external_id: _task(external_id, TaskStatus.RUNNING)},
        recoverable={external_id: False},  # kill -9 al worker
    )

    assert _reconcile(app, queue) == 1
    assert _reload(app, analysis_id).status == "failed"


def test_reconcile_recovers_an_analysis_whose_job_expired(app, regular_user):
    """RQ purga su historial por TTL: el job existió, pero ya no está y su
    resultado nunca llegó a la fila."""
    analysis_id = _make_analysis(app, regular_user.id, status="running")
    external_id = f"iris-analysis:{analysis_id}"
    queue = _FakeQueue({external_id: None}, recoverable={external_id: False})

    assert _reconcile(app, queue) == 1
    assert _reload(app, analysis_id).status == "failed"


def test_reconcile_recovers_an_analysis_whose_job_already_failed(app, regular_user):
    """Un job en estado terminal no va a volver a tocar la fila: si el análisis
    sigue activo es porque el proceso murió entre el trabajo y su escritura."""
    analysis_id = _make_analysis(app, regular_user.id, status="running")
    external_id = f"iris-analysis:{analysis_id}"
    queue = _FakeQueue({external_id: _task(external_id, TaskStatus.FAILED)})

    assert _reconcile(app, queue) == 1
    assert _reload(app, analysis_id).status == "failed"


def test_reconcile_ignores_already_finished_analyses(app, regular_user):
    _make_analysis(app, regular_user.id, status="finished")

    assert _reconcile(app, _FakeQueue({})) == 0
