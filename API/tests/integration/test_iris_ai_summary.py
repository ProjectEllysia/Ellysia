"""B10: el resumen ejecutivo de IA se pide una vez y se cobra una vez.

Antes, `generate_ai_summary` consumía cuota y encolaba sin mirar si ya había
un resumen o un trabajo en curso. Dos peticiones seguidas —dos clics, un
reintento del navegador, dos pestañas— cobraban dos veces y lanzaban dos
generaciones del mismo análisis. El `external_id` era determinista, así que la
información para evitarlo estaba ahí; simplemente nadie la consultaba.

Además, la cola `iris.ai_summary` no estaba registrada: los trabajos caían en
la cola `default` en lugar de en la suya.
"""

from __future__ import annotations

from typing import Callable, Optional
from unittest import mock

import pytest

import src.modules.features.iris.managers.analysis as analysis_mod
import src.modules.features.iris.services.ai_writer as ai_writer_mod
from src.modules.features.iris.managers.analysis import IrisManager
from src.modules.features.iris.model import IrisAnalysis
from src.modules.features.iris.repositories import IrisAnalysisRepository
from src.modules.infrastructure import UnitOfWork
from src.modules.system.taskqueue import QueueRegistry, Task, TaskStatus

pytestmark = pytest.mark.integration


class _RecordingQueue:
    """Cola que apunta lo que se le encola, sin ejecutarlo."""

    def __init__(self) -> None:
        self.submitted: list[dict] = []

    def submit(self, func: Callable, *, name: str = "", category: str = "",
               args: tuple = (), kwargs: Optional[dict] = None,
               external_id: Optional[str] = None, timeout: int = 600) -> Task:
        self.submitted.append({"name": name, "category": category,
                               "external_id": external_id, "args": args})
        return Task(id=f"job-{len(self.submitted)}", name=name, category=category,
                    external_id=external_id, status=TaskStatus.PENDING)

    def get_task_by_external_id(self, external_id: str, category: Optional[str] = None): return None
    def is_recoverable(self, external_id: str, category: Optional[str] = None) -> bool: return True
    def cancel(self, task_id: str) -> bool: return True
    def get_task(self, task_id: str): return None
    def update_progress(self, task_id: str, progress: int) -> None: pass
    def is_cancelled(self, task_id: str) -> bool: return False
    def clear_cancel_signal(self, task_id: str) -> None: pass


class _RejectingQueue(_RecordingQueue):
    def submit(self, *args, **kwargs):
        raise RuntimeError("la cola rechazó el trabajo")


class _CountingQuota:
    """Doble de QuotaManager que cuenta cobros y devoluciones."""

    consumed: list[str] = []
    refunded: list[str] = []

    @classmethod
    def reset(cls):
        cls.consumed = []
        cls.refunded = []

    def consume(self, user_id, key, amount=1):
        type(self).consumed.append(key.db_name)

    def refund(self, user_id, key, amount=1):
        type(self).refunded.append(key.db_name)


@pytest.fixture()
def counting_quota(monkeypatch):
    _CountingQuota.reset()
    monkeypatch.setattr(analysis_mod, "QuotaManager", _CountingQuota)
    return _CountingQuota


@pytest.fixture(autouse=True)
def _inert_ai_backend(monkeypatch):
    """Construir un ``IrisAIWriter`` no debe necesitar credenciales de OpenAI.

    Los tests de este módulo sustituyen ``IrisAIWriter.generate``, pero eso
    llega tarde: ``IrisAIWriter.__init__`` llama a ``build_generator("iris")``,
    que monta la estrategia configurada —OpenAI— y **ésa** sí exige
    ``OPENAI_API_KEY`` en su constructor. El método sustituido no se alcanzaba
    nunca.

    En una máquina de desarrollo no se notaba, porque ``load_dotenv()`` sube por
    el árbol de directorios y encuentra el ``.env`` de la raíz con una clave de
    verdad. En CI, que no tiene ningún ``.env``, la construcción reventaba, el
    ``except Exception`` de ``execute_ai_summary_generation`` lo convertía en
    ``ai_summary_status="failed"``, y el test que esperaba ``"done"`` fallaba.

    Los dos tests que provocan un fallo a propósito también lo agradecen: hasta
    ahora pasaban en CI por el motivo equivocado —reventaba el constructor, no
    la generación que decían estar probando—.
    """
    monkeypatch.setattr(ai_writer_mod, "build_generator", lambda module=None: object())


def _seed_finished_analysis(app, user_id: int, ai_summary=None) -> int:
    with app.app_context():
        with UnitOfWork() as uow:
            analysis = IrisAnalysis(
                raw_headers="From: a@b.com\nSubject: Test\n",
                user_id=user_id, status="finished",
                total_score=-25.0, verdict="Phishing",
                ai_summary=ai_summary,
            )
            IrisAnalysisRepository(uow).save(analysis)
            return analysis.id


def _reload(app, analysis_id: int) -> IrisAnalysis:
    with app.app_context():
        with UnitOfWork() as uow:
            return IrisAnalysisRepository(uow).get_by_id(analysis_id)


# ---------------------------------------------------------------------------
# La cola nominal
# ---------------------------------------------------------------------------

def test_the_ai_summary_queue_is_registered():
    """Sin registrar, `QueueRegistry.resolve_queue_name` cae a `default` y el
    trabajo acaba compartiendo cola con todo lo demás, en vez de en la suya."""
    assert QueueRegistry.is_registered("iris.ai_summary")


def test_the_job_is_enqueued_in_its_own_queue(app, regular_user, counting_quota):
    analysis_id = _seed_finished_analysis(app, regular_user.id)
    queue = _RecordingQueue()

    with app.app_context():
        IrisManager(task_queue=queue).generate_ai_summary(analysis_id, regular_user.id)

    assert len(queue.submitted) == 1
    assert queue.submitted[0]["category"] == "iris.ai_summary"
    assert queue.submitted[0]["external_id"] == f"iris-ai-summary:{analysis_id}"


# ---------------------------------------------------------------------------
# Idempotencia
# ---------------------------------------------------------------------------

def test_two_requests_produce_a_single_job(app, regular_user, counting_quota):
    """El caso del issue: dos peticiones concurrentes del mismo análisis."""
    analysis_id = _seed_finished_analysis(app, regular_user.id)
    queue = _RecordingQueue()

    with app.app_context():
        manager = IrisManager(task_queue=queue)
        manager.generate_ai_summary(analysis_id, regular_user.id)
        manager.generate_ai_summary(analysis_id, regular_user.id)

    assert len(queue.submitted) == 1


def test_the_second_request_does_not_consume_quota(app, regular_user, counting_quota):
    """La otra mitad, y la que le cuesta dinero al usuario: perder la carrera
    no puede cobrarse."""
    analysis_id = _seed_finished_analysis(app, regular_user.id)
    queue = _RecordingQueue()

    with app.app_context():
        manager = IrisManager(task_queue=queue)
        manager.generate_ai_summary(analysis_id, regular_user.id)
        first_charges = list(counting_quota.consumed)
        manager.generate_ai_summary(analysis_id, regular_user.id)

    assert counting_quota.consumed == first_charges
    assert "iris.ai_summaries" in first_charges


def test_an_existing_summary_is_returned_without_working_or_charging(app, regular_user,
                                                                    counting_quota):
    """Doble clic sobre un análisis que ya tiene resumen: se devuelve el que
    hay. Es lo que quiere quien hizo doble clic, y no cuesta nada."""
    analysis_id = _seed_finished_analysis(
        app, regular_user.id, ai_summary={"executive_summary": "ya estaba"})
    queue = _RecordingQueue()

    with app.app_context():
        status = IrisManager(task_queue=queue).generate_ai_summary(analysis_id, regular_user.id)

    assert status == "done"
    assert queue.submitted == []
    assert counting_quota.consumed == []


def test_an_explicit_regeneration_does_work_and_charge(app, regular_user, counting_quota):
    """Y quien sí quiere otra redacción lo pide explícitamente."""
    analysis_id = _seed_finished_analysis(
        app, regular_user.id, ai_summary={"executive_summary": "ya estaba"})
    queue = _RecordingQueue()

    with app.app_context():
        status = IrisManager(task_queue=queue).generate_ai_summary(
            analysis_id, regular_user.id, regenerate=True)

    assert status == "running"
    assert len(queue.submitted) == 1
    assert counting_quota.consumed


# ---------------------------------------------------------------------------
# Reembolso
# ---------------------------------------------------------------------------

def test_a_rejected_enqueue_refunds_the_quota(app, regular_user, counting_quota):
    """Cobrar antes de trabajar es correcto —cobrar después dejaría lanzar N
    generaciones con cupo para una—, pero obliga a devolver el dinero cuando
    el trabajo no llega a hacerse."""
    analysis_id = _seed_finished_analysis(app, regular_user.id)

    with app.app_context():
        with pytest.raises(RuntimeError):
            IrisManager(task_queue=_RejectingQueue()).generate_ai_summary(
                analysis_id, regular_user.id)

    assert counting_quota.refunded == counting_quota.consumed
    assert counting_quota.refunded  # y algo se cobró, no es un empate vacío


def test_a_rejected_enqueue_leaves_the_analysis_retryable(app, regular_user, counting_quota):
    """Si la reserva no se soltara, el análisis se quedaría en `running` para
    siempre y el usuario no podría volver a pedirlo nunca."""
    analysis_id = _seed_finished_analysis(app, regular_user.id)

    with app.app_context():
        with pytest.raises(RuntimeError):
            IrisManager(task_queue=_RejectingQueue()).generate_ai_summary(
                analysis_id, regular_user.id)

    assert _reload(app, analysis_id).ai_summary_status is None

    queue = _RecordingQueue()
    with app.app_context():
        IrisManager(task_queue=queue).generate_ai_summary(analysis_id, regular_user.id)
    assert len(queue.submitted) == 1


def test_a_failed_generation_refunds_and_ends_in_a_terminal_state(app, regular_user,
                                                                  counting_quota):
    """El backend de IA puede estar caído o devolver basura. El análisis ya
    terminado no se toca, pero el resumen no puede quedarse en `running` ni
    cobrado."""
    analysis_id = _seed_finished_analysis(app, regular_user.id)

    with app.app_context():
        IrisManager(task_queue=_RecordingQueue()).generate_ai_summary(
            analysis_id, regular_user.id)
        counting_quota.reset()

        with mock.patch.object(analysis_mod.IrisAIWriter, "generate",
                               side_effect=RuntimeError("modelo caído")):
            IrisManager.execute_ai_summary_generation(analysis_id, regular_user.id)

    analysis = _reload(app, analysis_id)
    assert analysis.ai_summary_status == "failed"
    assert analysis.ai_summary is None
    assert analysis.status == "finished"  # el análisis en sí no se ve afectado
    assert counting_quota.refunded


def test_a_failed_generation_can_be_retried(app, regular_user, counting_quota):
    """`failed` es un estado reclamable: reintentar es legítimo."""
    analysis_id = _seed_finished_analysis(app, regular_user.id)

    with app.app_context():
        IrisManager(task_queue=_RecordingQueue()).generate_ai_summary(
            analysis_id, regular_user.id)
        with mock.patch.object(analysis_mod.IrisAIWriter, "generate",
                               side_effect=RuntimeError("modelo caído")):
            IrisManager.execute_ai_summary_generation(analysis_id, regular_user.id)

        retry_queue = _RecordingQueue()
        IrisManager(task_queue=retry_queue).generate_ai_summary(analysis_id, regular_user.id)

    assert len(retry_queue.submitted) == 1


# ---------------------------------------------------------------------------
# Trazabilidad
# ---------------------------------------------------------------------------

def test_a_generated_summary_records_how_it_was_made(app, regular_user, counting_quota):
    """Un resumen de hace tres meses lo escribió otro modelo con otro prompt.
    Sin registrarlo no hay forma de saber cuál."""
    analysis_id = _seed_finished_analysis(app, regular_user.id)

    with app.app_context():
        IrisManager(task_queue=_RecordingQueue()).generate_ai_summary(
            analysis_id, regular_user.id)
        with mock.patch.object(analysis_mod.IrisAIWriter, "generate",
                               return_value={"executive_summary": "resumen"}):
            IrisManager.execute_ai_summary_generation(analysis_id, regular_user.id)

    analysis = _reload(app, analysis_id)
    assert analysis.ai_summary_status == "done"
    assert analysis.ai_summary == {"executive_summary": "resumen"}
    assert analysis.ai_summary_model
    assert analysis.ai_summary_prompt_version.startswith("iris-summary:")
