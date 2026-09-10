"""B08: la outbox transaccional de TaskQueue.

``TaskDispatch`` es la intención de publicar un job, guardada en la misma
transacción que la entidad que la origina. Estos tests cubren el
``OutboxDispatcher`` de forma aislada (con un ``ITaskQueue`` doble, sin Redis
real) y, al final, el escenario íntegro que el issue pide: la API puede
reiniciarse entre el commit del análisis y la publicación del job sin perder
el trabajo ni duplicarlo.
"""

from __future__ import annotations

import pytest

from src.modules.accounts.services.limits import LimitKey
from src.modules.accounts.services.quotas import QuotaManager
from src.modules.features.iris.managers.analysis import IrisManager
from src.modules.features.iris.repositories import IrisAnalysisRepository
from src.modules.infrastructure import UnitOfWork
from src.modules.shared._exceptions import IllegalStateError
from src.modules.system.taskqueue.dispatcher import OutboxDispatcher
from src.modules.system.taskqueue.outbox import build_dispatch, decode_func, encode_func
from src.modules.system.taskqueue.outbox_repository import TaskDispatchRepository

pytestmark = pytest.mark.integration


class _RecordingQueue:
    """Doble de ITaskQueue que apunta lo que se le publica, sin Redis real."""

    def __init__(self) -> None:
        self.submitted: list[dict] = []

    def submit(self, **kwargs):
        self.submitted.append(kwargs)


class _RejectingQueue:
    """Simula Redis caído: cualquier submit() falla."""

    def submit(self, **kwargs):
        raise ConnectionError("Redis no disponible")


class _AlreadyStartedQueue:
    """Simula que un intento anterior sí llegó a publicar el job y ya está
    "started" -- exactamente lo que TaskQueue.submit() señaliza con
    IllegalStateError cuando el job_id determinista ya está en marcha."""

    def submit(self, **kwargs):
        raise IllegalStateError(
            "ya en ejecución", expected_state="not_started", current_state="started",
        )


def _save_dispatch(app, **overrides) -> int:
    defaults = dict(
        func=IrisManager.execute_iris_analysis,
        name="Outbox-Test-1", category="iris.analyze",
        args=(1, "raw"), external_id="outbox-test:1",
    )
    defaults.update(overrides)
    with app.app_context():
        with UnitOfWork() as uow:
            dispatch = TaskDispatchRepository(uow).save(build_dispatch(**defaults))
            return dispatch.id


# ------------------------------------------------------------ encode/decode

def test_encode_decode_func_roundtrips_a_real_staticmethod():
    path = encode_func(IrisManager.execute_iris_analysis)
    assert decode_func(path) is IrisManager.execute_iris_analysis


def test_decode_func_raises_for_a_path_that_no_longer_resolves():
    with pytest.raises((ImportError, AttributeError)):
        decode_func("src.modules.features.iris.managers.analysis:IrisManager.does_not_exist")


# --------------------------------------------------------------- dispatch()

def test_dispatch_publishes_a_pending_row(app):
    dispatch_id = _save_dispatch(app)
    queue = _RecordingQueue()

    with app.app_context():
        published = OutboxDispatcher.dispatch(dispatch_id, task_queue=queue)

        assert published is True
        assert len(queue.submitted) == 1
        assert queue.submitted[0]["name"] == "Outbox-Test-1"
        assert queue.submitted[0]["func"] is IrisManager.execute_iris_analysis
        assert queue.submitted[0]["args"] == (1, "raw")

        with UnitOfWork() as uow:
            row = TaskDispatchRepository(uow).get_by_id(dispatch_id)
            assert row.status == "dispatched"
            assert row.dispatched_at is not None


def test_dispatch_leaves_the_row_pending_when_redis_is_down(app):
    dispatch_id = _save_dispatch(app)

    with app.app_context():
        published = OutboxDispatcher.dispatch(dispatch_id, task_queue=_RejectingQueue())

        assert published is False
        with UnitOfWork() as uow:
            row = TaskDispatchRepository(uow).get_by_id(dispatch_id)
            assert row.status == "pending"
            assert row.attempts == 1
            assert "Redis" in row.last_error


def test_dispatch_retries_a_previously_failed_row(app):
    """Cada intento fallido suma -- así se puede ver cuántas veces lleva
    reintentando una fila concreta sin tener que mirar los logs."""
    dispatch_id = _save_dispatch(app)

    with app.app_context():
        OutboxDispatcher.dispatch(dispatch_id, task_queue=_RejectingQueue())
        OutboxDispatcher.dispatch(dispatch_id, task_queue=_RejectingQueue())

        queue = _RecordingQueue()
        published = OutboxDispatcher.dispatch(dispatch_id, task_queue=queue)

        assert published is True
        assert len(queue.submitted) == 1
        with UnitOfWork() as uow:
            row = TaskDispatchRepository(uow).get_by_id(dispatch_id)
            assert row.status == "dispatched"


def test_dispatch_is_a_no_op_once_already_dispatched(app):
    """Reintentar una fila ya publicada no debe volver a llamar a submit() --
    es la mitad de la garantía "nunca lo duplica": una vez marcada, se queda
    marcada."""
    dispatch_id = _save_dispatch(app)
    first_queue = _RecordingQueue()

    with app.app_context():
        OutboxDispatcher.dispatch(dispatch_id, task_queue=first_queue)
        assert len(first_queue.submitted) == 1

        second_queue = _RecordingQueue()
        published = OutboxDispatcher.dispatch(dispatch_id, task_queue=second_queue)

        assert published is True
        assert second_queue.submitted == []


def test_dispatch_treats_an_already_started_job_as_dispatched(app):
    """La rendija que TaskQueue.submit() por sí solo no cierra: un intento
    anterior sí publicó el job (ya está "started" con el mismo id
    determinista) pero el proceso murió antes de marcar esta fila. El
    siguiente intento no debe tratarlo como un fallo ni reintentar publicar
    -- eso sí duplicaría el trabajo si el job ya hubiera terminado para
    cuando llega el reintento (ver el docstring de outbox.py)."""
    dispatch_id = _save_dispatch(app)

    with app.app_context():
        published = OutboxDispatcher.dispatch(dispatch_id, task_queue=_AlreadyStartedQueue())

        assert published is True
        with UnitOfWork() as uow:
            row = TaskDispatchRepository(uow).get_by_id(dispatch_id)
            assert row.status == "dispatched"
            assert row.attempts == 0
            assert row.last_error is None


def test_dispatch_unknown_id_returns_false(app):
    with app.app_context():
        assert OutboxDispatcher.dispatch(999999, task_queue=_RecordingQueue()) is False


def test_a_request_that_fails_afterwards_does_not_unmark_a_published_row(app):
    """La fila refleja algo que ya ocurrió en Redis, no en la request.

    Dentro de una request, ``UnitOfWork`` no confirma nada: lo hace el
    teardown, y si la request lanza, hace rollback. Cuando el dispatcher
    dependía de ese commit, una request que publicaba y después fallaba
    devolvía la fila a ``pending`` con el job ya en la cola, y el barrido lo
    publicaba otra vez.
    """
    from src.modules.infrastructure.session import (
        init_request_session, shutdown_request_session,
    )

    dispatch_id = _save_dispatch(app)
    queue = _RecordingQueue()

    with app.test_request_context():
        init_request_session()
        assert OutboxDispatcher.dispatch(dispatch_id, task_queue=queue) is True
        shutdown_request_session(exception=RuntimeError("la request falla después"))

    with app.app_context():
        with UnitOfWork() as uow:
            row = TaskDispatchRepository(uow).get_by_id(dispatch_id)
            assert row.status == "dispatched"
        assert OutboxDispatcher.dispatch_pending() == 0

    assert len(queue.submitted) == 1


# ----------------------------------------------------------- dispatch_pending()

def test_dispatch_pending_publishes_every_pending_row(app, monkeypatch):
    first_id = _save_dispatch(app, name="Outbox-Test-A", external_id="outbox-test:a")
    second_id = _save_dispatch(app, name="Outbox-Test-B", external_id="outbox-test:b")

    with app.app_context():
        import src.modules.system.taskqueue.dispatcher as dispatcher_mod
        queue = _RecordingQueue()
        monkeypatch.setattr(dispatcher_mod.TaskQueue, "get_instance", staticmethod(lambda: queue))
        dispatched = OutboxDispatcher.dispatch_pending()

        assert dispatched == 2
        assert {s["name"] for s in queue.submitted} == {"Outbox-Test-A", "Outbox-Test-B"}

        with UnitOfWork() as uow:
            repo = TaskDispatchRepository(uow)
            assert repo.get_by_id(first_id).status == "dispatched"
            assert repo.get_by_id(second_id).status == "dispatched"


def test_dispatch_pending_skips_rows_already_dispatched(app, monkeypatch):
    dispatch_id = _save_dispatch(app)

    with app.app_context():
        OutboxDispatcher.dispatch(dispatch_id, task_queue=_RecordingQueue())

        import src.modules.system.taskqueue.dispatcher as dispatcher_mod
        queue = _RecordingQueue()
        monkeypatch.setattr(dispatcher_mod.TaskQueue, "get_instance", staticmethod(lambda: queue))
        dispatched = OutboxDispatcher.dispatch_pending()

        assert dispatched == 0
        assert queue.submitted == []


# --------------------------------------------------- escenario íntegro (B08)

def test_analyze_survives_a_restart_between_commit_and_publish(
    app, regular_user, set_plan_limits, monkeypatch,
):
    """El criterio de cierre del issue, de punta a punta: se crea el
    análisis con Redis caído en ese instante (simulando el momento exacto en
    que la API podría reiniciarse o Redis fallar), y luego una llamada
    aparte -- como la reconciliación de arranque en run.py -- termina de
    publicarlo. Nunca se pierde, y publicarlo dos veces (aquí, y en un
    hipotético segundo arranque) no lo duplica."""
    set_plan_limits({LimitKey.IRIS_ANALYSES: 5})

    with app.app_context():
        manager = IrisManager(task_queue=_RejectingQueue())
        analysis_id = manager.analyze(
            raw_headers="From: a@b.com\r\nSubject: Hi\r\n", user_id=regular_user.id,
        )

        # El análisis existe -- no se perdió nada aunque el submit fallara.
        with UnitOfWork() as uow:
            analysis = IrisAnalysisRepository(uow).get_by_id(analysis_id)
            assert analysis is not None
            assert analysis.status == "pending"

        with UnitOfWork() as uow:
            pending = TaskDispatchRepository(uow).get_pending()
            assert len(pending) == 1
            assert pending[0].args == [analysis_id, "From: a@b.com\r\nSubject: Hi\r\n"]

        # "Reinicio": la reconciliación de arranque (u otro barrido) publica
        # lo que quedó pendiente, ahora con Redis arriba.
        recovery_queue = _RecordingQueue()
        import src.modules.system.taskqueue.dispatcher as dispatcher_mod
        monkeypatch.setattr(dispatcher_mod.TaskQueue, "get_instance", staticmethod(lambda: recovery_queue))
        dispatched = OutboxDispatcher.dispatch_pending()

        assert dispatched == 1
        assert len(recovery_queue.submitted) == 1

        # Un segundo "reinicio" que barriera otra vez no vuelve a publicar:
        # la fila ya quedó `dispatched` en el primero.
        dispatched_again = OutboxDispatcher.dispatch_pending()

        assert dispatched_again == 0
        assert len(recovery_queue.submitted) == 1
