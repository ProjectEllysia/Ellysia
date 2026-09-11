"""Transiciones de estado atómicas frente a cancelación concurrente.

``cancel_analysis()`` señaliza TaskQueue y ``_persist_analysis_results()``
(el worker, al terminar de evaluar las reglas) escriben el ``status`` final
del mismo ``IrisAnalysis`` desde dos sitios distintos. Antes de este arreglo
ninguno de los dos comprobaba el estado actual de la fila antes de escribir
-- si el usuario cancelaba justo cuando el worker terminaba (o viceversa),
ganaba quien confirmara el commit último, no quien tuviera razón. Estos
tests ponen una barrera explícita entre "se decide cancelar/terminar" y "se
escribe en la base de datos" para demostrar que la transición condicionada
(``IrisAnalysisRepository.transition_if_state()``) cierra esa carrera en los
dos sentidos.
"""

from __future__ import annotations

from unittest import mock

import pytest

import src.modules.features.iris.managers.analysis as managers_mod
from src.modules.features.iris.managers.analysis import IrisManager
from src.modules.features.iris.model import IrisAnalysis
from src.modules.features.iris.repositories import IrisAnalysisRepository, IrisRuleResultRepository
from src.modules.features.iris.services.contexts import CONTEXT_INNER, ContextEvaluation
from src.modules.features.iris.services.quality import AnalysisQuality
from src.modules.features.iris.services.registry import RuleResult
from src.modules.infrastructure import UnitOfWork
from src.modules.shared import utcnow_naive
from src.modules.system.taskqueue import Task, TaskStatus

pytestmark = pytest.mark.integration


def _make_analysis(app, user_id, status="running") -> int:
    with app.app_context():
        with UnitOfWork() as uow:
            analysis = IrisAnalysis(
                raw_headers="From: a@b.com\r\nSubject: Hi\r\n", user_id=user_id, status=status,
            )
            IrisAnalysisRepository(uow).save(analysis)
            return analysis.id


def _reload(app, analysis_id) -> IrisAnalysis:
    with app.app_context():
        with UnitOfWork() as uow:
            return IrisAnalysisRepository(uow).get_by_id(analysis_id)


class _FakeCancelQueue:
    """Cola fake para cancel_analysis(): siempre encuentra una tarea
    "started" y deja que el test decida qué pasa cuando se pide cancelarla
    -- incluyendo, para la prueba de la carrera, ejecutar código arbitrario
    justo en ese instante (simulando al worker terminando en paralelo)."""

    def __init__(self, on_cancel=None, cancel_returns: bool = True):
        self._on_cancel = on_cancel
        self._cancel_returns = cancel_returns

    def get_task_by_external_id(self, external_id, category=None):
        return Task(id="job1", name="job1", category=category or "iris.analyze",
                    external_id=external_id, status=TaskStatus.RUNNING)

    def cancel(self, task_id: str) -> bool:
        if self._on_cancel is not None:
            self._on_cancel()
        return self._cancel_returns


def _cancel(app, queue, analysis_id, user_id) -> bool:
    with app.app_context():
        with mock.patch.object(managers_mod.TaskQueue, "get_instance", return_value=queue):
            return IrisManager(task_queue=queue).cancel_analysis(analysis_id, user_id)


# --------------------------------------------------------------- transition_if_state

def test_transition_if_state_applies_when_the_row_matches(app, regular_user):
    analysis_id = _make_analysis(app, regular_user.id, status="running")

    with app.app_context():
        with UnitOfWork() as uow:
            applied = IrisAnalysisRepository(uow).transition_if_state(
                analysis_id, ["running"], status="finished", verdict="Legitimate",
            )
        assert applied is True

    reloaded = _reload(app, analysis_id)
    assert reloaded.status == "finished"
    assert reloaded.verdict == "Legitimate"


def test_transition_if_state_is_a_no_op_when_the_row_does_not_match(app, regular_user):
    """Si el estado ya cambió, ni `status` ni ningún otro campo del intento
    perdedor se escriben -- no solo `status` se queda como estaba."""
    analysis_id = _make_analysis(app, regular_user.id, status="cancelled")

    with app.app_context():
        with UnitOfWork() as uow:
            applied = IrisAnalysisRepository(uow).transition_if_state(
                analysis_id, ["running"], status="finished", verdict="Phishing",
            )
        assert applied is False

    reloaded = _reload(app, analysis_id)
    assert reloaded.status == "cancelled"
    assert reloaded.verdict is None


def test_transition_if_state_returns_false_for_a_missing_analysis(app):
    with app.app_context():
        with UnitOfWork() as uow:
            applied = IrisAnalysisRepository(uow).transition_if_state(
                999999, ["running"], status="finished",
            )
        assert applied is False


# ------------------------------------------------------------- cancel_analysis()

def test_cancel_analysis_transitions_a_running_analysis(app, regular_user):
    analysis_id = _make_analysis(app, regular_user.id, status="running")

    result = _cancel(app, _FakeCancelQueue(), analysis_id, regular_user.id)

    assert result is True
    reloaded = _reload(app, analysis_id)
    assert reloaded.status == "cancelled"
    assert reloaded.finished_at is not None
    assert reloaded.cancel_requested_at is not None


def test_cancel_analysis_returns_false_when_the_queue_says_it_already_finished(app, regular_user):
    """TaskQueue.cancel() devuelve False si RQ ya sabe que el job terminó --
    ni siquiera merece la pena intentar la transición condicionada."""
    analysis_id = _make_analysis(app, regular_user.id, status="running")

    result = _cancel(app, _FakeCancelQueue(cancel_returns=False), analysis_id, regular_user.id)

    assert result is False
    reloaded = _reload(app, analysis_id)
    assert reloaded.status == "running"  # sin tocar
    assert reloaded.cancel_requested_at is None  # ni se intentó escribir nada


def test_cancel_analysis_does_not_overwrite_a_result_the_worker_wins_the_race_to_persist(
    app, regular_user,
):
    """La barrera del issue, en el sentido "el worker gana": justo cuando
    cancel_analysis() pide a TaskQueue que cancele el job (que todavía
    reporta "started"), el worker consigue persistir su resultado antes de
    que la transición de cancel_analysis() llegue a ejecutarse. El usuario
    pidió cancelar de buena fe -- eso se registra -- pero el resultado real
    del análisis no se pierde ni se sobreescribe con "cancelled"."""
    analysis_id = _make_analysis(app, regular_user.id, status="running")

    def _worker_wins_the_race():
        with app.app_context():
            with UnitOfWork() as uow:
                IrisAnalysisRepository(uow).transition_if_state(
                    analysis_id, ["running"], status="finished", verdict="Legitimate",
                    total_score=95.0, finished_at=utcnow_naive(),
                )

    queue = _FakeCancelQueue(on_cancel=_worker_wins_the_race)
    result = _cancel(app, queue, analysis_id, regular_user.id)

    assert result is False
    reloaded = _reload(app, analysis_id)
    assert reloaded.status == "finished"
    assert reloaded.verdict == "Legitimate"
    assert reloaded.total_score == 95.0
    # La intención de cancelar se registra igualmente, aunque perdiera la carrera.
    assert reloaded.cancel_requested_at is not None


# --------------------------------------------------------- _persist_analysis_results()

def test_persist_analysis_results_does_not_overwrite_a_cancellation(app, regular_user):
    """La barrera al revés: el usuario cancela justo antes de que el worker
    termine de evaluar las reglas y llame a _persist_analysis_results(). Las
    filas de reglas se escriben igual (son un hecho, ocurrieron), pero el
    veredicto/score calculados no deben aterrizar sobre un análisis que el
    usuario ya dio por cancelado."""
    analysis_id = _make_analysis(app, regular_user.id, status="running")

    with app.app_context():
        with UnitOfWork() as uow:
            cancelled = IrisAnalysisRepository(uow).transition_if_state(
                analysis_id, ["running"], status="cancelled", finished_at=utcnow_naive(),
            )
        assert cancelled is True

        IrisManager._persist_analysis_results(
            analysis_id,
            rules_defs=[{"name": "SPF", "category": "auth"}],
            winner=ContextEvaluation(
                context_type=CONTEXT_INNER, verdict="Phishing", total_score=10.0,
                gate_reasons=[], quality=AnalysisQuality(quality="complete"),
                results=[RuleResult(
                    score=-10.0, verdict="fail", details={}, recommendation="revisa SPF",
                )],
            ),
            detector="test:1",
        )

    reloaded = _reload(app, analysis_id)
    assert reloaded.status == "cancelled"
    assert reloaded.verdict is None
    assert reloaded.total_score is None
    assert reloaded.detector_version is None

    with app.app_context():
        with UnitOfWork() as uow:
            rules = IrisRuleResultRepository(uow).get_by_analysis(analysis_id)
            assert len(rules) == 1
            assert rules[0].rule_name == "SPF"


def test_persist_analysis_results_finishes_a_still_running_analysis(app, regular_user):
    """Camino normal (sin carrera): la transición sí se aplica."""
    analysis_id = _make_analysis(app, regular_user.id, status="running")

    with app.app_context():
        IrisManager._persist_analysis_results(
            analysis_id,
            rules_defs=[{"name": "SPF", "category": "auth"}],
            winner=ContextEvaluation(
                context_type=CONTEXT_INNER, verdict="Legitimate", total_score=90.0,
                gate_reasons=[], quality=AnalysisQuality(quality="complete"),
                results=[RuleResult(score=2.0, verdict="pass", details={})],
            ),
            detector="test:1",
        )

    reloaded = _reload(app, analysis_id)
    assert reloaded.status == "finished"
    assert reloaded.verdict == "Legitimate"
    assert reloaded.total_score == 90.0
