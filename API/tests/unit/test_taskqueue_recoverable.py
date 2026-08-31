"""B04: ``TaskQueue.is_recoverable()`` — ¿queda alguien que termine este trabajo?

Las reconciliaciones de arranque necesitan distinguir un trabajo abandonado de
uno que sigue vivo en otro proceso. Mirar solo el estado del job no basta: un
job ``started`` puede estar avanzando ahora mismo, o pertenecer a un worker que
murió de un ``kill -9`` y no va a volver. Estos tests fijan esa tabla de
decisión sobre la implementación real, con Redis y RQ sustituidos por dobles.
"""

from __future__ import annotations

from unittest import mock

import pytest

from src.modules.system.taskqueue.queue import TaskQueue

pytestmark = pytest.mark.unit

_EXTERNAL_ID = "iris-analysis:42"
_CATEGORY = "iris.analyze"


class _ExternalIdStore:
    """Doble del mapeo external_id → job_id que vive en Redis."""

    def __init__(self, mapping: dict[str, str]):
        self._mapping = mapping

    def get(self, external_id: str):
        return self._mapping.get(external_id)


def _queue(job_id: str | None = "job-1") -> TaskQueue:
    """Instancia de TaskQueue sin pasar por ``__init__``.

    El constructor real abre la conexión a Redis; aquí solo se necesitan las
    tres costuras que ``is_recoverable`` consulta, y cada test las sustituye.
    """
    queue = TaskQueue.__new__(TaskQueue)
    queue._external = _ExternalIdStore({_EXTERNAL_ID: job_id} if job_id else {})
    return queue


def _rq_job(status: str, worker_name: str | None = "worker-1"):
    """Doble de un ``rq.job.Job`` con lo justo que lee ``Task.from_rq_job``."""
    job = mock.MagicMock()
    job.id = "job-1"
    job.description = "Analysis-42"
    job.meta = {"category": _CATEGORY, "external_id": _EXTERNAL_ID}
    job.get_status.return_value = status
    job.created_at = None
    job.started_at = None
    job.ended_at = None
    job.exc_info = None
    job.worker_name = worker_name
    return job


def test_no_mapping_means_nobody_will_finish_it():
    queue = _queue(job_id=None)

    assert queue.is_recoverable(_EXTERNAL_ID, _CATEGORY) is False


def test_expired_job_is_not_recoverable():
    """RQ purga su historial por TTL: el mapeo sigue, el job ya no."""
    queue = _queue()

    with mock.patch.object(TaskQueue, "_try_fetch_job", return_value=None):
        assert queue.is_recoverable(_EXTERNAL_ID, _CATEGORY) is False


def test_queued_job_is_recoverable():
    """Sigue en la cola; el primer worker libre lo tomará."""
    queue = _queue()

    with mock.patch.object(TaskQueue, "_try_fetch_job", return_value=_rq_job("queued")):
        assert queue.is_recoverable(_EXTERNAL_ID, _CATEGORY) is True


def test_started_job_with_a_live_worker_is_recoverable():
    """El caso que motiva B04: está corriendo, no hay que tocarlo."""
    queue = _queue()

    with mock.patch.object(TaskQueue, "_try_fetch_job", return_value=_rq_job("started")), \
         mock.patch.object(TaskQueue, "_worker_alive", return_value=True):
        assert queue.is_recoverable(_EXTERNAL_ID, _CATEGORY) is True


def test_started_job_whose_worker_died_is_not_recoverable():
    """La clave ``rq:worker:<name>`` sobrevive con TTL completo a un ``kill -9``,
    así que "el job dice started" no prueba que alguien lo esté ejecutando."""
    queue = _queue()

    with mock.patch.object(TaskQueue, "_try_fetch_job", return_value=_rq_job("started")), \
         mock.patch.object(TaskQueue, "_worker_alive", return_value=False):
        assert queue.is_recoverable(_EXTERNAL_ID, _CATEGORY) is False


@pytest.mark.parametrize("rq_status", ["finished", "failed", "stopped"])
def test_terminal_jobs_are_not_recoverable(rq_status):
    queue = _queue()

    with mock.patch.object(TaskQueue, "_try_fetch_job", return_value=_rq_job(rq_status)):
        assert queue.is_recoverable(_EXTERNAL_ID, _CATEGORY) is False


def test_category_mismatch_is_not_recoverable():
    """Un external_id reutilizado por otro módulo no responde por este trabajo."""
    queue = _queue()

    with mock.patch.object(TaskQueue, "_try_fetch_job", return_value=_rq_job("started")), \
         mock.patch.object(TaskQueue, "_worker_alive", return_value=True):
        assert queue.is_recoverable(_EXTERNAL_ID, "themis.scan") is False


def test_redis_failure_assumes_recoverable():
    """Conservador a propósito: sin poder mirar no hay prueba de que el trabajo
    esté perdido, y el precio de equivocarse es asimétrico — un huérfano que
    sobrevive un arranque se reconcilia en el siguiente, pero marcar `failed`
    un trabajo vivo se lo enseña al usuario como fallido justo antes de que el
    worker escriba su resultado encima."""
    queue = _queue()

    with mock.patch.object(TaskQueue, "_try_fetch_job",
                           side_effect=ConnectionError("Redis caído")):
        assert queue.is_recoverable(_EXTERNAL_ID, _CATEGORY) is True
