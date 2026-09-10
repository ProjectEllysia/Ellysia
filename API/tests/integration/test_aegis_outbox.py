"""#551: Aegis crea la entidad y su encolado en una sola transacción.

Aegis era el caso más desprotegido de todo el proyecto. Sus dos puntos de
create-then-enqueue —lanzar una campaña y generar una píldora— no tenían
**ninguna** compensación: ni un ``try/except`` alrededor del ``submit()`` como
sí tienen los informes, ni una reconciliación de arranque como la que Themis e
Iris corren al levantar la API. Si Redis fallaba en el instante del encolado:

- la campaña quedaba lanzada (snapshot del quiz congelado, un token acuñado por
  destinatario, cuota ``AEGIS_CAMPAIGNS`` cobrada) y no salía un solo correo;
- la píldora quedaba en ``pending`` para siempre —un "Generando..." que nunca
  termina— con ``AEGIS_PILLS`` y ``AI_REQUESTS`` ya cobradas.

En los dos casos nadie se enteraba y nada lo reintentaba nunca.

Estos tests fijan que ahora la fila ``TaskDispatch`` viaja en el mismo commit
que la entidad, así que el trabajo se recupera después en vez de perderse.
"""

from __future__ import annotations

import pytest

from src.modules.features.aegis.managers import AegisManager, CampaignManager
from src.modules.features.aegis.model import AegisDocument, AegisQuizQuestion, Topic
from src.modules.features.aegis.repositories import AegisDocumentRepository, CampaignRepository
from src.modules.infrastructure import UnitOfWork
from src.modules.system.taskqueue.dispatcher import OutboxDispatcher
from src.modules.system.taskqueue.outbox_repository import TaskDispatchRepository

pytestmark = pytest.mark.integration


def _make_topic() -> int:
    """Inserta un ``Topic`` y devuelve su id. Debe llamarse dentro de un app_context."""
    with UnitOfWork() as uow:
        topic = Topic(title="Phishing")
        uow.session.add(topic)
        uow.session.flush()
        return topic.id


def _make_document_with_quiz(user_id: int) -> int:
    """Inserta una píldora ya generada con dos preguntas y devuelve su id.

    Una campaña no se deja lanzar sin preguntas (``CampaignNoQuestionsError``),
    así que el quiz es parte del montaje mínimo. Debe llamarse dentro de un
    app_context.
    """
    with UnitOfWork() as uow:
        topic = Topic(title="Phishing")
        uow.session.add(topic)
        uow.session.flush()

        document = AegisDocument(
            title="pildora_campana", filename="test_pill_outbox.json", status="done",
            format="json", topic_id=topic.id, user_id=user_id, is_ai_generated=1,
            subtitle="Phishing 101", intro="Intro", closing="Cierre",
            contact_email="sec@empresa.com", company="ACME",
        )
        document_id = AegisDocumentRepository(uow).save(document).id

        for position in (1, 2):
            uow.session.add(AegisQuizQuestion(
                document_id=document_id, position=position,
                prompt=f"¿Qué haces ante la situación de phishing nº {position}?",
                options=["Opción 1", "Opción 2"], correct_index=1,
            ))
        return document_id


class _RecordingQueue:
    """Doble de ITaskQueue que apunta lo que se le publica, sin Redis real."""

    def __init__(self) -> None:
        self.submitted: list[dict] = []

    def submit(self, **kwargs):
        self.submitted.append(kwargs)


class _RejectingQueue:
    """Simula Redis caído justo en el instante del encolado."""

    def submit(self, **kwargs):
        raise ConnectionError("Redis no disponible")


def _only_pending_dispatch() -> dict:
    """Devuelve la única fila de outbox pendiente, fallando si no hay exactamente una.

    Los atributos se materializan dentro del ``UnitOfWork``: fuera del bloque la
    instancia queda desligada de la sesión y tocar un atributo dispararía un
    lazy load contra una sesión ya cerrada.

    Returns:
        dict: Campos de la fila (``func_path``, ``name``, ``category``,
            ``args``, ``external_id``, ``status``).
    """
    with UnitOfWork() as uow:
        pending = TaskDispatchRepository(uow).get_pending()
        assert len(pending) == 1, f"se esperaba una fila pendiente, hay {len(pending)}"
        row = pending[0]
        return {
            "func_path": row.func_path,
            "name": row.name,
            "category": row.category,
            "args": list(row.args),
            "external_id": row.external_id,
            "status": row.status,
        }


# ─────────────────────────────────────────────────────────────────────────
# Campañas
# ─────────────────────────────────────────────────────────────────────────

def _launch_campaign(app, client, admin_user, admin_headers, queue):
    """Crea lista + destinatarios + campaña y la lanza con ``queue`` como cola.

    Devuelve el ``campaign_id``. El lanzamiento se hace por el manager y no por
    el endpoint para poder inyectar el doble de cola: es justo el encolado lo
    que estos tests quieren controlar.
    """
    with app.app_context():
        document_id = _make_document_with_quiz(admin_user.id)

    list_id = client.post(
        "/aegis/lists", headers=admin_headers, json={"name": "Empleados"},
    ).get_json()["id"]
    client.post(
        f"/aegis/lists/{list_id}/recipients",
        headers=admin_headers,
        json={"recipients": [
            {"email": "ana@empresa.test", "name": "Ana"},
            {"email": "bob@empresa.test", "name": "Bob"},
        ]},
    )
    campaign_id = client.post(
        "/aegis/campaigns",
        headers=admin_headers,
        json={"name": "Concienciación Q1", "documentId": document_id, "listId": list_id},
    ).get_json()["id"]

    with app.app_context():
        manager = CampaignManager(admin_user, task_queue=queue)
        manager.launch_campaign(campaign_id)

    return campaign_id


def test_launching_a_campaign_with_redis_down_leaves_a_recoverable_dispatch(
    app, client, admin_user, admin_headers,
):
    """La campaña se lanza igual, y su encolado queda pendiente en la outbox."""
    campaign_id = _launch_campaign(
        app, client, admin_user, admin_headers, _RejectingQueue(),
    )

    with app.app_context():
        # El lanzamiento sí ocurrió: snapshot congelado y tokens acuñados.
        with UnitOfWork() as uow:
            campaign = CampaignRepository(uow).get_by_id(campaign_id)
            assert campaign is not None
            assert campaign.questions_snapshot

        dispatch = _only_pending_dispatch()
        assert dispatch["name"] == f"CampaignSend-{campaign_id}"
        assert dispatch["category"] == CampaignManager.TASK_CATEGORY
        assert dispatch["args"] == [campaign_id, admin_user.id]


def test_a_failed_campaign_publish_is_recovered_by_a_later_sweep(
    app, client, admin_user, admin_headers, monkeypatch,
):
    """El barrido posterior publica el envío que Redis rechazó, y no lo duplica."""
    campaign_id = _launch_campaign(
        app, client, admin_user, admin_headers, _RejectingQueue(),
    )

    with app.app_context():
        recovery_queue = _RecordingQueue()
        import src.modules.system.taskqueue.dispatcher as dispatcher_mod
        monkeypatch.setattr(
            dispatcher_mod.TaskQueue, "get_instance", staticmethod(lambda: recovery_queue),
        )

        assert OutboxDispatcher.dispatch_pending() == 1
        assert len(recovery_queue.submitted) == 1
        assert recovery_queue.submitted[0]["name"] == f"CampaignSend-{campaign_id}"

        # Un segundo barrido no republica: la fila ya quedó `dispatched`.
        assert OutboxDispatcher.dispatch_pending() == 0
        assert len(recovery_queue.submitted) == 1


def test_launching_a_campaign_publishes_immediately_when_redis_is_up(
    app, client, admin_user, admin_headers,
):
    """Camino feliz: no se añade latencia y no queda nada pendiente."""
    queue = _RecordingQueue()
    campaign_id = _launch_campaign(
        app, client, admin_user, admin_headers, queue,
    )

    assert len(queue.submitted) == 1
    assert queue.submitted[0]["name"] == f"CampaignSend-{campaign_id}"
    with app.app_context():
        with UnitOfWork() as uow:
            assert TaskDispatchRepository(uow).get_pending() == []


# ─────────────────────────────────────────────────────────────────────────
# Píldoras
# ─────────────────────────────────────────────────────────────────────────

def test_generating_a_pill_with_redis_down_leaves_a_recoverable_dispatch(
    app, admin_user,
):
    """La píldora se crea en ``pending`` y su generación queda en la outbox.

    Antes era el peor de los dos casos de Aegis: sin outbox, sin
    try/except y sin reconciliación, el documento se quedaba en ``pending`` para
    siempre con las dos cuotas de IA ya cobradas.
    """
    with app.app_context():
        topic_id = _make_topic()
        manager = AegisManager(admin_user, task_queue=_RejectingQueue())
        document_id = manager.generate(topic_id, tweaks={"company": "ACME"})

        with UnitOfWork() as uow:
            document = AegisDocumentRepository(uow).get_by_id(document_id)
            assert document is not None
            assert document.status == "pending"

        dispatch = _only_pending_dispatch()
        assert dispatch["name"] == f"AegisGen-{document_id}"
        assert dispatch["category"] == AegisManager.TASK_CATEGORY
        # tweaks viaja como dict JSON, no como objeto pickleado.
        assert dispatch["args"] == [document_id, topic_id, {"company": "ACME"}, admin_user.id]


def test_a_failed_pill_publish_is_recovered_by_a_later_sweep(
    app, admin_user, monkeypatch,
):
    """El barrido posterior encola la generación que Redis rechazó."""
    with app.app_context():
        topic_id = _make_topic()
        manager = AegisManager(admin_user, task_queue=_RejectingQueue())
        document_id = manager.generate(topic_id, tweaks={"company": "ACME"})

        recovery_queue = _RecordingQueue()
        import src.modules.system.taskqueue.dispatcher as dispatcher_mod
        monkeypatch.setattr(
            dispatcher_mod.TaskQueue, "get_instance", staticmethod(lambda: recovery_queue),
        )

        assert OutboxDispatcher.dispatch_pending() == 1
        assert recovery_queue.submitted[0]["name"] == f"AegisGen-{document_id}"
        assert OutboxDispatcher.dispatch_pending() == 0
        assert len(recovery_queue.submitted) == 1


def test_generating_a_pill_publishes_immediately_when_redis_is_up(app, admin_user):
    """Camino feliz: el job sale en la misma llamada y nada queda pendiente."""
    with app.app_context():
        topic_id = _make_topic()
        queue = _RecordingQueue()
        document_id = AegisManager(admin_user, task_queue=queue).generate(
            topic_id, tweaks={"company": "ACME"},
        )

        assert len(queue.submitted) == 1
        assert queue.submitted[0]["name"] == f"AegisGen-{document_id}"
        with UnitOfWork() as uow:
            assert TaskDispatchRepository(uow).get_pending() == []
