"""
tests/test_taskqueue.py
───────────────────────
Tests unitarios de las costuras SOLID del sistema de tareas. No requieren
Redis ni RQ: ejercitan el registro de colas, el contrato ``ITaskQueue`` y el
mixin de seguimiento usando una cola falsa inyectada (DIP).

Ejecutar desde el directorio ``API``::

    python -m pytest tests/test_taskqueue.py -q
"""

from __future__ import annotations

from typing import Callable, Optional

import pytest

from src.modules.system.taskqueue import (
    DEFAULT_QUEUE,
    ITaskQueue,
    QueueRegistry,
    Task,
    TaskStatus,
    TaskTrackingMixin,
)


# ---------------------------------------------------------------------------
# Doble de prueba: implementación en memoria de ITaskQueue
# ---------------------------------------------------------------------------

class FakeTaskQueue:
    """Implementación mínima de ITaskQueue para tests (sin Redis)."""

    def __init__(self) -> None:
        self.submitted: list[dict] = []
        self.cancelled: list[str] = []
        self._by_external: dict[str, Task] = {}
        self._cancelled_signals: set[str] = set()

    def seed_task(self, external_id: str, task: Task) -> None:
        self._by_external[external_id] = task

    def submit(self, func: Callable, *, name: str = "", category: str = "",
               args: tuple = (), kwargs: Optional[dict] = None,
               external_id: Optional[str] = None, timeout: int = 600) -> Task:
        task = Task(id=name or "job", name=name, category=category,
                    external_id=external_id, status=TaskStatus.PENDING)
        self.submitted.append({"name": name, "category": category,
                               "external_id": external_id, "args": args})
        if external_id:
            self._by_external[external_id] = task
        return task

    def cancel(self, task_id: str) -> bool:
        self.cancelled.append(task_id)
        return True

    def get_task(self, task_id: str) -> Optional[Task]:
        return None

    def get_task_by_external_id(self, external_id: str,
                                category: Optional[str] = None) -> Optional[Task]:
        task = self._by_external.get(external_id)
        if task is None:
            return None
        if category is not None and task.category != category:
            return None
        return task

    def update_progress(self, task_id: str, progress: int) -> None:
        pass

    def is_cancelled(self, task_id: str) -> bool:
        return task_id in self._cancelled_signals

    def clear_cancel_signal(self, task_id: str) -> None:
        self._cancelled_signals.discard(task_id)


class _DummyManager(TaskTrackingMixin):
    EXTERNAL_ID_PREFIX = "demo:"
    TASK_CATEGORY = "demo.category"

    def __init__(self, task_queue: ITaskQueue) -> None:
        self._task_queue = task_queue


# ---------------------------------------------------------------------------
# QueueRegistry (OCP)
# ---------------------------------------------------------------------------

def test_registry_always_contains_default():
    assert DEFAULT_QUEUE in QueueRegistry.names()


def test_registry_register_is_idempotent():
    QueueRegistry.register("demo.category")
    QueueRegistry.register("demo.category")
    names = QueueRegistry.names()
    assert names.count("demo.category") == 1
    assert QueueRegistry.is_registered("demo.category")


def test_registry_unknown_category_not_registered():
    assert not QueueRegistry.is_registered("never.registered.category")


# ---------------------------------------------------------------------------
# ITaskQueue (DIP) — conformidad runtime_checkable
# ---------------------------------------------------------------------------

def test_fake_queue_satisfies_interface():
    assert isinstance(FakeTaskQueue(), ITaskQueue)


# ---------------------------------------------------------------------------
# TaskTrackingMixin (DRY)
# ---------------------------------------------------------------------------

def test_external_id_for_uses_prefix():
    mgr = _DummyManager(FakeTaskQueue())
    assert mgr.external_id_for(42) == "demo:42"


def test_task_status_and_progress_lookup():
    fake = FakeTaskQueue()
    fake.seed_task(
        "demo:7",
        Task(id="job-7", category="demo.category",
             status=TaskStatus.RUNNING, progress=55),
    )
    mgr = _DummyManager(fake)
    assert mgr.task_status_of(7) == "running"
    assert mgr.task_progress_of(7) == 55


def test_missing_task_returns_none():
    mgr = _DummyManager(FakeTaskQueue())
    assert mgr.task_status_of(999) is None
    assert mgr.task_progress_of(999) is None


def test_category_mismatch_is_filtered():
    fake = FakeTaskQueue()
    fake.seed_task(
        "demo:8",
        Task(id="job-8", category="other.category", status=TaskStatus.RUNNING),
    )
    mgr = _DummyManager(fake)
    # El mixin pasa TASK_CATEGORY="demo.category"; la tarea es de otra
    # categoría, así que no debe resolverse.
    assert mgr.task_status_of(8) is None


# ---------------------------------------------------------------------------
# Inyección de la cola en un manager real (DIP de extremo a extremo)
# ---------------------------------------------------------------------------

def test_manager_uses_injected_queue_on_submit():
    fake = FakeTaskQueue()
    mgr = _DummyManager(fake)
    # Simula lo que hacen los managers: enviar usando la cola inyectada.
    mgr._task_queue.submit(func=lambda: None, name="Demo-1",
                   category=mgr.TASK_CATEGORY,
                   external_id=mgr.external_id_for(1))
    assert len(fake.submitted) == 1
    assert fake.submitted[0]["external_id"] == "demo:1"
    assert fake.submitted[0]["category"] == "demo.category"


# ---------------------------------------------------------------------------
# C4: rechazo del reencolado cuando el job existente sigue "started"
# ---------------------------------------------------------------------------

def test_reject_if_still_running_raises_for_started_job():
    from src.modules.shared._exceptions import IllegalStateError
    from src.modules.system.taskqueue.queue import _reject_if_still_running

    with pytest.raises(IllegalStateError) as exc_info:
        _reject_if_still_running("NmapScan-1", "started")
    assert exc_info.value.status_code == 409


@pytest.mark.parametrize("status", ["queued", "scheduled", "finished", "failed"])
def test_reject_if_still_running_allows_other_statuses(status):
    from src.modules.system.taskqueue.queue import _reject_if_still_running

    _reject_if_still_running("NmapScan-1", status)  # no debe lanzar
