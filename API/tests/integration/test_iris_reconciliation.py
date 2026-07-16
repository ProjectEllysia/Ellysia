"""C1: reconciliación de análisis Iris huérfanos tras un apagado abrupto.

Espejo de la reconciliación que ya existía para Themis (ScanManager.
reconcile_orphaned_scans) — sin esto, un análisis que queda en pending/running
cuando el proceso muere se queda así para siempre, porque no hay ninguna tarea
viva en TaskQueue que lo actualice tras reiniciar.
"""

from __future__ import annotations

from typing import Callable, Optional
from unittest import mock

import pytest

from src.modules.infrastructure import UnitOfWork
from src.modules.system.taskqueue import Task, TaskStatus

import src.modules.features.iris.managers as managers_mod
from src.modules.features.iris.model import IrisAnalysis
from src.modules.features.iris.repositories import IrisAnalysisRepository

pytestmark = pytest.mark.integration


class _FakeQueue:
    """Cola fake: devuelve lo que el test necesite por external_id."""

    def __init__(self, tasks_by_external_id: dict[str, Optional[Task]]):
        self._tasks = tasks_by_external_id

    def get_task_by_external_id(self, external_id: str, category: Optional[str] = None):
        return self._tasks.get(external_id)

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


def test_reconcile_marks_orphan_without_any_task_as_failed(app, regular_user):
    analysis_id = _make_analysis(app, regular_user.id, status="running")
    queue = _FakeQueue({})  # sin tarea en TaskQueue -> huérfano

    with app.app_context():
        with mock.patch.object(managers_mod.TaskQueue, "get_instance", return_value=queue):
            fixed = managers_mod.IrisManager.reconcile_orphaned_analyses()
        assert fixed == 1
        with UnitOfWork() as uow:
            assert IrisAnalysisRepository(uow).get_by_id(analysis_id).status == "failed"


def test_reconcile_leaves_still_queued_analysis_alone(app, regular_user):
    analysis_id = _make_analysis(app, regular_user.id, status="pending")
    external_id = f"iris-analysis:{analysis_id}"
    queue = _FakeQueue({external_id: Task(
        id="job1", name="job1", category="iris.analyze",
        external_id=external_id, status=TaskStatus.PENDING,
    )})

    with app.app_context():
        with mock.patch.object(managers_mod.TaskQueue, "get_instance", return_value=queue):
            fixed = managers_mod.IrisManager.reconcile_orphaned_analyses()
        assert fixed == 0
        with UnitOfWork() as uow:
            assert IrisAnalysisRepository(uow).get_by_id(analysis_id).status == "pending"


def test_reconcile_ignores_already_finished_analyses(app, regular_user):
    _make_analysis(app, regular_user.id, status="finished")
    queue = _FakeQueue({})

    with app.app_context():
        with mock.patch.object(managers_mod.TaskQueue, "get_instance", return_value=queue):
            fixed = managers_mod.IrisManager.reconcile_orphaned_analyses()
        assert fixed == 0
