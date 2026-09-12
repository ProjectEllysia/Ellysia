"""
Tests de integración de las campañas de concienciación Aegis (quiz + listas
de distribución + envío + tracking público).

El envío de email nunca toca la red: se apunta a un servidor SMTP local real
(aiosmtpd) vía monkeypatch de la config de `herald`, igual que
tests/unit/test_herald_smtp.py. El encolado en TaskQueue se sustituye por un
doble en memoria (_FakeTaskQueue) para no depender de Redis — mismo patrón
que tests/integration/test_system.py. El worker en sí (execute_campaign_send)
se invoca directamente como función síncrona: job_context() no-opea de forma
segura fuera de un worker RQ real.
"""

from __future__ import annotations

import email
import email.policy
import socket
from unittest import mock

import pytest

aiosmtpd_controller = pytest.importorskip("aiosmtpd.controller")
Controller = aiosmtpd_controller.Controller

from src.modules.features.aegis.managers import CampaignManager
from src.modules.system.taskqueue import TaskQueue

pytestmark = pytest.mark.integration


# ─────────────────────────────────────────────────────────────────────────
# Infraestructura de test: servidor SMTP local + fake TaskQueue
# ─────────────────────────────────────────────────────────────────────────

class _FakeTaskQueue:
    """Registra el submit sin tocar Redis (mismo patrón que test_system.py)."""

    def __init__(self):
        self.submitted = None

    def submit(self, **kwargs):
        self.submitted = kwargs
        return None


class _CapturingHandler:
    """
    Captura mensajes y los decodifica de verdad en vez de comparar contra
    los bytes crudos del wire: el Content-Transfer-Encoding (8bit /
    quoted-printable / base64) lo elige el generador MIME según el contenido
    y no es estable entre mensajes, así que solo el 'html' decodificado es
    fiable para hacer aserciones de contenido.
    """

    def __init__(self) -> None:
        self.messages: list[dict] = []

    async def handle_DATA(self, server, session, envelope):
        parsed = email.message_from_bytes(envelope.content, policy=email.policy.default)
        html = ""
        for part in parsed.walk():
            if part.get_content_type() == "text/html":
                html = part.get_content()
                break

        self.messages.append({
            "mail_from": envelope.mail_from,
            "rcpt_tos": list(envelope.rcpt_tos),
            "content": envelope.content.decode("utf-8", errors="replace"),
            "html": html,
        })
        return "250 Message accepted for delivery"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture
def smtp_catcher():
    handler = _CapturingHandler()
    controller = Controller(handler, hostname="127.0.0.1", port=_free_port())
    controller.start()
    try:
        yield controller, handler
    finally:
        controller.stop()


@pytest.fixture
def local_email_config(monkeypatch, smtp_catcher):
    """Apunta herald al catcher SMTP local en vez de a Brevo (config real)."""
    controller, handler = smtp_catcher
    import src.modules.system.config_reading as CR

    fake_herald_config = CR.HeraldConfig(
        default_strategy="smtp",
        modules={"aegis": "smtp"},
        strategies={
            "smtp": {
                "host": controller.hostname,
                "port": controller.port,
                "useTls": False,
                "fromAddress": "noreply@ellysia.test",
                "fromName": "Ellysia Test",
            }
        },
    )
    monkeypatch.setattr(CR, "herald_config", lambda: fake_herald_config)
    monkeypatch.setattr(CR, "get_smtp_environment", lambda: {"username": "", "password": ""})
    monkeypatch.setenv("PUBLIC_WEB_URL", "http://localhost:5173")
    return handler


# ─────────────────────────────────────────────────────────────────────────
# Fixture: píldora 'done' con preguntas de quiz
# ─────────────────────────────────────────────────────────────────────────

@pytest.fixture()
def make_aegis_doc_with_quiz(app):
    """Factory: píldora 'done' con un test de ``questions`` × ``options``.

    La correcta es siempre la última opción de cada pregunta. Los tamaños son
    parámetros porque el test ya no es de 2×3 fijo: sale de
    ``features.aegis.questionsAmount`` / ``optionsAmount``. Devuelve el doc_id.
    """

    def _make(user_id, questions=2, options=2):
        from src.modules.infrastructure.unit_of_work import UnitOfWork
        from src.modules.features.aegis.model import AegisDocument, AegisQuizQuestion, Topic
        from src.modules.features.aegis.repositories import AegisDocumentRepository

        with app.app_context():
            with UnitOfWork() as uow:
                topic = Topic(title="Phishing")
                uow.session.add(topic)
                uow.session.flush()

                doc = AegisDocument(
                    title="pildora_campana",
                    filename="test_pill_campaign.json",
                    status="done",
                    format="json",
                    topic_id=topic.id,
                    user_id=user_id,
                    is_ai_generated=1,
                    subtitle="Phishing 101",
                    intro="Intro",
                    closing="Cierre",
                    contact_email="sec@empresa.com",
                    company="ACME",
                )
                saved = AegisDocumentRepository(uow).save(doc)
                doc_id = saved.id

                for position in range(1, questions + 1):
                    uow.session.add(AegisQuizQuestion(
                        document_id=doc_id, position=position,
                        prompt=f"¿Qué haces ante la situación de phishing nº {position}?",
                        options=[f"Opción {i + 1}" for i in range(options)],
                        correct_index=options - 1,
                    ))
        return doc_id

    return _make


def _fetch_token_for_email(app, campaign_id: int, email: str) -> str:
    from src.modules.features.aegis.repositories import CampaignRepository
    from src.modules.infrastructure.session import get_db_session

    with app.app_context():
        repo = CampaignRepository(session=get_db_session())
        for recipient in repo.get_recipients(campaign_id):
            if recipient.recipient_email == email:
                return recipient.token
    raise AssertionError(f"No recipient found for {email}")


# ─────────────────────────────────────────────────────────────────────────
# Distribution lists
# ─────────────────────────────────────────────────────────────────────────

def test_create_list_requires_authentication(client):
    assert client.post("/aegis/lists", json={"name": "Empleados"}).status_code == 401


def test_create_and_populate_list(client, admin_user, admin_headers):
    resp = client.post("/aegis/lists", headers=admin_headers, json={"name": "Empleados"})
    assert resp.status_code == 201
    list_id = resp.get_json()["id"]

    resp = client.post(
        f"/aegis/lists/{list_id}/recipients",
        headers=admin_headers,
        json={"recipients": [
            {"email": "ana@empresa.test", "name": "Ana"},
            {"email": "bob@empresa.test", "name": "Bob"},
        ]},
    )
    assert resp.status_code == 201
    assert resp.get_json()["count"] == 2

    resp = client.get(f"/aegis/lists/{list_id}/recipients", headers=admin_headers)
    assert resp.status_code == 200
    assert resp.get_json()["count"] == 2


def test_add_recipients_skips_duplicates(client, admin_headers):
    list_id = client.post(
        "/aegis/lists", headers=admin_headers, json={"name": "Dup"}
    ).get_json()["id"]

    client.post(
        f"/aegis/lists/{list_id}/recipients",
        headers=admin_headers,
        json={"recipients": [{"email": "ana@empresa.test"}]},
    )
    resp = client.post(
        f"/aegis/lists/{list_id}/recipients",
        headers=admin_headers,
        json={"recipients": [{"email": "ana@empresa.test"}, {"email": "carla@empresa.test"}]},
    )
    assert resp.get_json()["count"] == 1  # solo carla, ana ya existía


# ─────────────────────────────────────────────────────────────────────────
# Campaign lifecycle
# ─────────────────────────────────────────────────────────────────────────

def test_launch_campaign_without_recipients_fails(
    client, admin_user, admin_headers, make_aegis_doc_with_quiz,
):
    doc_id = make_aegis_doc_with_quiz(admin_user.id)
    list_id = client.post(
        "/aegis/lists", headers=admin_headers, json={"name": "Vacía"}
    ).get_json()["id"]
    campaign_id = client.post(
        "/aegis/campaigns", headers=admin_headers,
        json={"documentId": doc_id, "listId": list_id, "name": "Campaña vacía"},
    ).get_json()["id"]

    with mock.patch.object(TaskQueue, "get_instance", return_value=_FakeTaskQueue()):
        resp = client.post(f"/aegis/campaigns/{campaign_id}/launch", headers=admin_headers)
    assert resp.status_code == 400


def test_launch_campaign_twice_returns_409(
    client, admin_user, admin_headers, make_aegis_doc_with_quiz,
):
    doc_id = make_aegis_doc_with_quiz(admin_user.id)
    list_id = client.post(
        "/aegis/lists", headers=admin_headers, json={"name": "L"}
    ).get_json()["id"]
    client.post(
        f"/aegis/lists/{list_id}/recipients", headers=admin_headers,
        json={"recipients": [{"email": "ana@empresa.test", "name": "Ana"}]},
    )
    campaign_id = client.post(
        "/aegis/campaigns", headers=admin_headers,
        json={"documentId": doc_id, "listId": list_id, "name": "C"},
    ).get_json()["id"]

    with mock.patch.object(TaskQueue, "get_instance", return_value=_FakeTaskQueue()):
        first = client.post(f"/aegis/campaigns/{campaign_id}/launch", headers=admin_headers)
        assert first.status_code == 200
        second = client.post(f"/aegis/campaigns/{campaign_id}/launch", headers=admin_headers)
        assert second.status_code == 409


# ─────────────────────────────────────────────────────────────────────────
# End-to-end: launch -> send via herald (local SMTP) -> public quiz -> no-repeat
# ─────────────────────────────────────────────────────────────────────────

def test_full_campaign_flow_send_and_quiz_no_repeat(
    app, client, admin_user, admin_headers, make_aegis_doc_with_quiz, local_email_config,
):
    doc_id = make_aegis_doc_with_quiz(admin_user.id)

    list_id = client.post(
        "/aegis/lists", headers=admin_headers, json={"name": "Plantilla"}
    ).get_json()["id"]
    client.post(
        f"/aegis/lists/{list_id}/recipients", headers=admin_headers,
        json={"recipients": [{"email": "empleado@empresa.test", "name": "Empleado"}]},
    )
    campaign_id = client.post(
        "/aegis/campaigns", headers=admin_headers,
        json={"documentId": doc_id, "listId": list_id, "name": "Campaña Q3"},
    ).get_json()["id"]

    # Lanzar: encolar sin tocar Redis (FakeTaskQueue), snapshot + tokens sí se persisten.
    with mock.patch.object(TaskQueue, "get_instance", return_value=_FakeTaskQueue()):
        launch_resp = client.post(f"/aegis/campaigns/{campaign_id}/launch", headers=admin_headers)
    assert launch_resp.status_code == 200
    assert launch_resp.get_json()["campaign"]["status"] == "sending"

    token = _fetch_token_for_email(app, campaign_id, "empleado@empresa.test")

    # Simular al worker: ejecutar el envío de forma síncrona (job_context no-opea sin RQ).
    with app.app_context():
        CampaignManager.execute_campaign_send(campaign_id, admin_user.id)

    assert len(local_email_config.messages) == 1
    sent = local_email_config.messages[0]
    assert sent["rcpt_tos"] == ["empleado@empresa.test"]
    assert f"t={token}" in sent["html"]

    # Página pública: primera visita -> preguntas SIN correctIndex.
    quiz_resp = client.get(f"/aegis/quiz?t={token}")
    assert quiz_resp.status_code == 200
    quiz_data = quiz_resp.get_json()
    assert quiz_data["status"] == "opened"
    assert len(quiz_data["questions"]) == 2
    assert "correctIndex" not in quiz_data["questions"][0]

    # Enviar respuestas: 1 correcta (posición 2, índice 1), 1 incorrecta (posición 1, índice 0).
    submit_resp = client.post(
        f"/aegis/quiz?t={token}",
        json={"answers": [
            {"questionPosition": 1, "selectedIndex": 0},
            {"questionPosition": 2, "selectedIndex": 1},
        ]},
    )
    assert submit_resp.status_code == 200
    result = submit_resp.get_json()
    assert result["status"] == "completed"
    assert result["score"] == 1
    assert result["total"] == 2

    # Regla no-repetir: reenviar respuestas -> 409.
    repeat_resp = client.post(
        f"/aegis/quiz?t={token}",
        json={"answers": [{"questionPosition": 1, "selectedIndex": 1}]},
    )
    assert repeat_resp.status_code == 409

    # GET tras completar ya no vuelve a servir el test.
    after_resp = client.get(f"/aegis/quiz?t={token}")
    assert after_resp.status_code == 200
    after_data = after_resp.get_json()
    assert after_data["status"] == "completed"
    assert after_data["score"] == 1
    assert "questions" not in after_data


def test_campaign_list_summarises_how_far_recipients_got(
    app, client, admin_user, admin_headers, make_aegis_doc_with_quiz,
):
    """El listado trae el progreso de cada campaña sin pedir su detalle.

    Tres destinatarios: uno completa (1 de 2 aciertos), otro solo abre el
    enlace y el tercero no hace nada. Quien completó cuenta también como
    abierto. Un borrador, sin destinatarios aún, sale a cero y sin nota.
    """
    doc_id = make_aegis_doc_with_quiz(admin_user.id)
    list_id = client.post(
        "/aegis/lists", headers=admin_headers, json={"name": "Plantilla"}
    ).get_json()["id"]
    client.post(
        f"/aegis/lists/{list_id}/recipients", headers=admin_headers,
        json={"recipients": [
            {"email": "ana@empresa.test"}, {"email": "bob@empresa.test"}, {"email": "carla@empresa.test"},
        ]},
    )
    launched_id = client.post(
        "/aegis/campaigns", headers=admin_headers,
        json={"documentId": doc_id, "listId": list_id, "name": "Lanzada"},
    ).get_json()["id"]
    draft_id = client.post(
        "/aegis/campaigns", headers=admin_headers,
        json={"documentId": doc_id, "listId": list_id, "name": "Borrador"},
    ).get_json()["id"]

    with mock.patch.object(TaskQueue, "get_instance", return_value=_FakeTaskQueue()):
        assert client.post(
            f"/aegis/campaigns/{launched_id}/launch", headers=admin_headers
        ).status_code == 200

    ana = _fetch_token_for_email(app, launched_id, "ana@empresa.test")
    bob = _fetch_token_for_email(app, launched_id, "bob@empresa.test")
    client.get(f"/aegis/quiz?t={ana}")
    client.post(f"/aegis/quiz?t={ana}", json={"answers": [
        {"questionPosition": 1, "selectedIndex": 0},
        {"questionPosition": 2, "selectedIndex": 1},
    ]})
    client.get(f"/aegis/quiz?t={bob}")

    campaigns = {
        campaign["id"]: campaign
        for campaign in client.get("/aegis/campaigns", headers=admin_headers).get_json()["campaigns"]
    }

    launched = campaigns[launched_id]
    assert launched["recipientCount"] == 3
    assert launched["openedCount"] == 2
    assert launched["completedCount"] == 1
    assert launched["averageScore"] == 1.0

    draft = campaigns[draft_id]
    assert draft["recipientCount"] == 0
    assert draft["openedCount"] == 0
    assert draft["completedCount"] == 0
    assert draft["averageScore"] is None


def test_campaign_detail_reports_results_per_question_of_the_frozen_quiz(
    app, client, admin_user, admin_headers, make_aegis_doc_with_quiz,
):
    """El detalle cuenta, por pregunta, quién respondió, quién acertó y qué eligió.

    La correcta es siempre la última opción (índice 1). Ana falla la primera y
    acierta la segunda; Bob acierta las dos. Después de lanzar se reescribe la
    pregunta en la píldora: el detalle tiene que seguir enseñando la que los
    destinatarios vieron, la del test congelado.
    """
    doc_id = make_aegis_doc_with_quiz(admin_user.id)
    list_id = client.post(
        "/aegis/lists", headers=admin_headers, json={"name": "Plantilla"}
    ).get_json()["id"]
    client.post(
        f"/aegis/lists/{list_id}/recipients", headers=admin_headers,
        json={"recipients": [{"email": "ana@empresa.test"}, {"email": "bob@empresa.test"}]},
    )
    campaign_id = client.post(
        "/aegis/campaigns", headers=admin_headers,
        json={"documentId": doc_id, "listId": list_id, "name": "Por pregunta"},
    ).get_json()["id"]
    with mock.patch.object(TaskQueue, "get_instance", return_value=_FakeTaskQueue()):
        assert client.post(
            f"/aegis/campaigns/{campaign_id}/launch", headers=admin_headers
        ).status_code == 200

    from src.modules.infrastructure.unit_of_work import UnitOfWork
    from src.modules.features.aegis.model import AegisQuizQuestion
    with app.app_context():
        with UnitOfWork() as uow:
            for question in uow.session.query(AegisQuizQuestion).filter_by(document_id=doc_id):
                question.prompt = "Editada después de lanzar"

    for email, first_choice in (("ana@empresa.test", 0), ("bob@empresa.test", 1)):
        token = _fetch_token_for_email(app, campaign_id, email)
        client.get(f"/aegis/quiz?t={token}")
        client.post(f"/aegis/quiz?t={token}", json={"answers": [
            {"questionPosition": 1, "selectedIndex": first_choice},
            {"questionPosition": 2, "selectedIndex": 1},
        ]})

    questions = client.get(f"/aegis/campaigns/{campaign_id}", headers=admin_headers).get_json()["questions"]

    assert [question["position"] for question in questions] == [1, 2]
    assert questions[0]["prompt"].startswith("¿Qué haces ante la situación de phishing nº 1")
    assert questions[0]["optionCounts"] == [1, 1]
    assert questions[0]["answeredCount"] == 2
    assert questions[0]["correctCount"] == 1
    assert questions[1]["optionCounts"] == [0, 2]
    assert questions[1]["correctCount"] == 2


def test_quiz_serves_and_grades_more_than_two_questions(
    app, client, admin_user, admin_headers, make_aegis_doc_with_quiz,
):
    """Un test de 5 preguntas de 4 opciones llega entero al destinatario.

    El 2×3 de siempre lo imponía el prompt, no el modelo de datos: esto
    comprueba que el snapshot de campaña, la página pública y la corrección
    no traen ningún 2 ni ningún 4 escrito a mano por el camino.
    """
    doc_id = make_aegis_doc_with_quiz(admin_user.id, questions=5, options=4)

    list_id = client.post(
        "/aegis/lists", headers=admin_headers, json={"name": "Plantilla"}
    ).get_json()["id"]
    client.post(
        f"/aegis/lists/{list_id}/recipients", headers=admin_headers,
        json={"recipients": [{"email": "empleado@empresa.test", "name": "Empleado"}]},
    )
    campaign_id = client.post(
        "/aegis/campaigns", headers=admin_headers,
        json={"documentId": doc_id, "listId": list_id, "name": "Campaña larga"},
    ).get_json()["id"]

    with mock.patch.object(TaskQueue, "get_instance", return_value=_FakeTaskQueue()):
        assert client.post(
            f"/aegis/campaigns/{campaign_id}/launch", headers=admin_headers
        ).status_code == 200

    token = _fetch_token_for_email(app, campaign_id, "empleado@empresa.test")

    quiz_data = client.get(f"/aegis/quiz?t={token}").get_json()
    assert len(quiz_data["questions"]) == 5
    assert all(len(question["options"]) == 4 for question in quiz_data["questions"])

    # La correcta es la última opción (índice 3): se acierta en 3 de 5.
    result = client.post(f"/aegis/quiz?t={token}", json={"answers": [
        {"questionPosition": 1, "selectedIndex": 3},
        {"questionPosition": 2, "selectedIndex": 3},
        {"questionPosition": 3, "selectedIndex": 0},
        {"questionPosition": 4, "selectedIndex": 2},
        {"questionPosition": 5, "selectedIndex": 3},
    ]}).get_json()
    assert result["score"] == 3
    assert result["total"] == 5


# ─────────────────────────────────────────────────────────────────────────
# Eliminar campañas: invalida los tokens ya enviados; borrar el documento
# arrastra sus campañas (Campaign.document_id no tiene ON DELETE CASCADE).
# ─────────────────────────────────────────────────────────────────────────

def test_delete_campaign_invalidates_sent_token(
    app, client, admin_user, admin_headers, make_aegis_doc_with_quiz,
):
    doc_id = make_aegis_doc_with_quiz(admin_user.id)
    list_id = client.post(
        "/aegis/lists", headers=admin_headers, json={"name": "L"}
    ).get_json()["id"]
    client.post(
        f"/aegis/lists/{list_id}/recipients", headers=admin_headers,
        json={"recipients": [{"email": "empleado@empresa.test", "name": "Empleado"}]},
    )
    campaign_id = client.post(
        "/aegis/campaigns", headers=admin_headers,
        json={"documentId": doc_id, "listId": list_id, "name": "C"},
    ).get_json()["id"]

    with mock.patch.object(TaskQueue, "get_instance", return_value=_FakeTaskQueue()):
        client.post(f"/aegis/campaigns/{campaign_id}/launch", headers=admin_headers)
    token = _fetch_token_for_email(app, campaign_id, "empleado@empresa.test")

    assert client.get(f"/aegis/quiz?t={token}").status_code == 200

    resp = client.delete(f"/aegis/campaigns/{campaign_id}", headers=admin_headers)
    assert resp.status_code == 200

    assert client.get(f"/aegis/campaigns/{campaign_id}", headers=admin_headers).status_code == 404
    assert client.get(f"/aegis/quiz?t={token}").status_code == 404


def test_delete_campaign_requires_ownership(client, admin_user, admin_headers, make_aegis_doc_with_quiz):
    doc_id = make_aegis_doc_with_quiz(admin_user.id)
    list_id = client.post(
        "/aegis/lists", headers=admin_headers, json={"name": "L"}
    ).get_json()["id"]
    campaign_id = client.post(
        "/aegis/campaigns", headers=admin_headers,
        json={"documentId": doc_id, "listId": list_id, "name": "C"},
    ).get_json()["id"]

    assert client.delete(f"/aegis/campaigns/{campaign_id}").status_code == 401


def test_deleting_document_deletes_its_campaigns(
    app, client, admin_user, admin_headers, make_aegis_doc_with_quiz,
):
    """Campaign.document_id no tiene ON DELETE CASCADE: si el manager no
    borrase antes las campañas, esto fallaría con un IntegrityError de FK."""
    doc_id = make_aegis_doc_with_quiz(admin_user.id)
    list_id = client.post(
        "/aegis/lists", headers=admin_headers, json={"name": "L"}
    ).get_json()["id"]
    client.post(
        f"/aegis/lists/{list_id}/recipients", headers=admin_headers,
        json={"recipients": [{"email": "empleado@empresa.test"}]},
    )
    campaign_id = client.post(
        "/aegis/campaigns", headers=admin_headers,
        json={"documentId": doc_id, "listId": list_id, "name": "C"},
    ).get_json()["id"]
    with mock.patch.object(TaskQueue, "get_instance", return_value=_FakeTaskQueue()):
        client.post(f"/aegis/campaigns/{campaign_id}/launch", headers=admin_headers)
    token = _fetch_token_for_email(app, campaign_id, "empleado@empresa.test")

    resp = client.delete(f"/aegis/document?id={doc_id}", headers=admin_headers)
    assert resp.status_code == 200

    assert client.get(f"/aegis/campaigns/{campaign_id}", headers=admin_headers).status_code == 404
    assert client.get(f"/aegis/quiz?t={token}").status_code == 404


def test_deleting_list_deletes_its_campaigns(
    app, client, admin_user, admin_headers, make_aegis_doc_with_quiz,
):
    """Campaign.list_id tampoco tiene ON DELETE CASCADE: sin borrar antes las
    campañas, el DELETE de la lista reventaba con un IntegrityError de FK en el
    commit de teardown — un 500 sin traza en el log."""
    doc_id = make_aegis_doc_with_quiz(admin_user.id)
    list_id = client.post(
        "/aegis/lists", headers=admin_headers, json={"name": "L"}
    ).get_json()["id"]
    client.post(
        f"/aegis/lists/{list_id}/recipients", headers=admin_headers,
        json={"recipients": [{"email": "empleado@empresa.test"}]},
    )
    campaign_id = client.post(
        "/aegis/campaigns", headers=admin_headers,
        json={"documentId": doc_id, "listId": list_id, "name": "C"},
    ).get_json()["id"]
    with mock.patch.object(TaskQueue, "get_instance", return_value=_FakeTaskQueue()):
        client.post(f"/aegis/campaigns/{campaign_id}/launch", headers=admin_headers)
    token = _fetch_token_for_email(app, campaign_id, "empleado@empresa.test")

    resp = client.delete(f"/aegis/lists/{list_id}", headers=admin_headers)
    assert resp.status_code == 200

    assert client.get(f"/aegis/lists/{list_id}", headers=admin_headers).status_code == 404
    assert client.get(f"/aegis/campaigns/{campaign_id}", headers=admin_headers).status_code == 404
    assert client.get(f"/aegis/quiz?t={token}").status_code == 404


def test_public_quiz_unknown_token_returns_404(client):
    resp = client.get("/aegis/quiz?t=this-token-does-not-exist")
    assert resp.status_code == 404


def test_public_quiz_is_rate_limited(client, rate_limiting_enabled):
    # T4: mismo idioma que los tests de rate limit de oauth/mfa. /aegis/quiz
    # es el único endpoint sin autenticación de toda la API (el token opaco
    # es la única identidad) — sin límite real, sería enumerable a fuerza
    # bruta. "30 per hour".
    for _ in range(30):
        resp = client.get("/aegis/quiz?t=this-token-does-not-exist")
        assert resp.status_code == 404

    resp = client.get("/aegis/quiz?t=this-token-does-not-exist")
    assert resp.status_code == 429


# ─────────────────────────────────────────────────────────────────────────
# White-labeling
# ─────────────────────────────────────────────────────────────────────────

#: PNG de 1x1, el logo más pequeño que un cliente de correo acepta.
_LOGO_URI = (
    "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAA"
    "CklEQVR4nGNgAAAAAgABf6ZX1AAAAABJRU5ErkJggg=="
)
_COLOR = "#1a73e8"


def _save_org_profile(client, headers, **overrides):
    payload = {
        "company": "ACME S.L.",
        "mentionContact": "seguridad@acme.test",
        "tone": "profesional",
        "companySize": "",
        "jurisdiction": "",
        "language": "es",
        "sector": "",
        "workModel": "",
        "employeeCount": None,
        "trackedProducts": [],
        "useHygeiaInventory": False,
    }
    payload.update(overrides)
    return client.put("/aegis/org-profile", headers=headers, json=payload)


def _run_campaign(client, app, headers, user_id, doc_id, email="empleado@empresa.test"):
    list_id = client.post("/aegis/lists", headers=headers, json={"name": "Plantilla"}).get_json()["id"]
    client.post(
        f"/aegis/lists/{list_id}/recipients", headers=headers,
        json={"recipients": [{"email": email, "name": "Empleado"}]},
    )
    campaign_id = client.post(
        "/aegis/campaigns", headers=headers,
        json={"documentId": doc_id, "listId": list_id, "name": "Campaña"},
    ).get_json()["id"]
    with mock.patch.object(TaskQueue, "get_instance", return_value=_FakeTaskQueue()):
        client.post(f"/aegis/campaigns/{campaign_id}/launch", headers=headers)
    with app.app_context():
        CampaignManager.execute_campaign_send(campaign_id, user_id)
    return campaign_id


def test_org_profile_round_trips_white_label_settings(client, admin_headers):
    saved = _save_org_profile(
        client, admin_headers, whiteLabelLevel="logo", brandLogo=_LOGO_URI, brandColor=_COLOR,
    ).get_json()

    assert saved["whiteLabelLevel"] == "logo"
    assert saved["brandLogo"] == _LOGO_URI
    assert saved["brandColor"] == _COLOR

    fetched = client.get("/aegis/org-profile", headers=admin_headers).get_json()
    assert fetched["whiteLabelLevel"] == "logo"
    assert fetched["brandLogo"] == _LOGO_URI
    assert fetched["brandColor"] == _COLOR


def test_org_profile_defaults_to_no_white_label(client, admin_headers):
    """Un perfil que nunca tocó el ajuste manda el correo de siempre."""
    profile = client.get("/aegis/org-profile", headers=admin_headers).get_json()
    assert profile["whiteLabelLevel"] == "none"
    assert profile["brandLogo"] == ""
    assert profile["brandColor"] == ""


@pytest.mark.parametrize(
    "overrides",
    [
        {"brandLogo": "https://cdn.acme.test/logo.png"},
        {"brandLogo": "data:image/svg+xml;base64,PHN2Zy8+"},
        {"whiteLabelLevel": "parcial"},
        {"brandColor": "rojo"},
        {"brandColor": "#fff; background:url(http://x)"},
    ],
)
def test_org_profile_rejects_invalid_white_label_input(client, admin_headers, overrides):
    assert _save_org_profile(client, admin_headers, **overrides).status_code == 422


def test_campaign_email_without_white_label_keeps_the_product_brand(
    app, client, admin_user, admin_headers, make_aegis_doc_with_quiz, local_email_config,
):
    doc_id = make_aegis_doc_with_quiz(admin_user.id)
    _save_org_profile(client, admin_headers)

    _run_campaign(client, app, admin_headers, admin_user.id, doc_id)

    sent = local_email_config.messages[0]
    assert "Ellysia" in sent["html"]
    assert "cid:" not in sent["html"]


def test_campaign_email_with_color_level_only_repaints_the_accent(
    app, client, admin_user, admin_headers, make_aegis_doc_with_quiz, local_email_config,
):
    doc_id = make_aegis_doc_with_quiz(admin_user.id)
    _save_org_profile(
        client, admin_headers, whiteLabelLevel="color", brandLogo=_LOGO_URI, brandColor=_COLOR,
    )

    _run_campaign(client, app, admin_headers, admin_user.id, doc_id)

    sent = local_email_config.messages[0]
    assert _COLOR in sent["html"]
    assert "cid:" not in sent["html"]
    assert "Ellysia" in sent["html"]


def test_campaign_email_with_logo_level_embeds_the_customer_logo(
    app, client, admin_user, admin_headers, make_aegis_doc_with_quiz, local_email_config,
):
    doc_id = make_aegis_doc_with_quiz(admin_user.id)
    _save_org_profile(
        client, admin_headers, whiteLabelLevel="logo", brandLogo=_LOGO_URI, brandColor=_COLOR,
    )

    _run_campaign(client, app, admin_headers, admin_user.id, doc_id)

    sent = local_email_config.messages[0]
    assert 'src="cid:brand-logo"' in sent["html"]
    # La imagen viaja dentro del mensaje: nada que descargar de un servidor.
    assert "image/png" in sent["content"]
    # Este nivel solo añade: la marca del producto sigue en cabecera y pie.
    assert "Ellysia" in sent["html"]


def test_campaign_email_with_full_level_removes_the_product_brand(
    app, client, admin_user, admin_headers, make_aegis_doc_with_quiz, local_email_config,
):
    doc_id = make_aegis_doc_with_quiz(admin_user.id)
    _save_org_profile(
        client, admin_headers, whiteLabelLevel="full", brandLogo=_LOGO_URI, brandColor=_COLOR,
    )

    _run_campaign(client, app, admin_headers, admin_user.id, doc_id)

    sent = local_email_config.messages[0]
    assert "Ellysia" not in sent["html"]
    # La marca que sustituye es la misma que el destinatario lee en el cuerpo
    # ("Desde ACME, te hacemos llegar…"), que es la de la píldora.
    assert "ACME" in sent["html"]
    assert 'src="cid:brand-logo"' in sent["html"]


# ─────────────────────────────────────────────────────────────────────────
# Tope de nivel por plan (aegis.white_label)
# ─────────────────────────────────────────────────────────────────────────

@pytest.fixture()
def white_label_allowance(app):
    """Fija el tope que concede el plan del usuario de test.

    El plan por defecto de la suite lo da todo por ilimitado; aquí se baja a
    un escalón concreto para ejercitar el corte.
    """
    def _set(value):
        from src.modules.accounts.model import PlanLimit
        from src.modules.infrastructure.unit_of_work import UnitOfWork

        with app.app_context():
            with UnitOfWork() as uow:
                rows = uow.session.query(PlanLimit).filter(
                    PlanLimit.limit_key == "aegis.white_label",
                ).all()
                for row in rows:
                    row.value = value
    return _set


def test_profile_reports_the_level_its_plan_allows(client, admin_headers, white_label_allowance):
    white_label_allowance(2)
    profile = client.get("/aegis/org-profile", headers=admin_headers).get_json()
    assert profile["maxWhiteLabelLevel"] == "logo"

    white_label_allowance(0)
    profile = client.get("/aegis/org-profile", headers=admin_headers).get_json()
    assert profile["maxWhiteLabelLevel"] == "none"


def test_saving_a_level_above_the_plan_is_rejected(client, admin_headers, white_label_allowance):
    white_label_allowance(1)  # solo el color

    rejected = _save_org_profile(
        client, admin_headers, whiteLabelLevel="full", brandLogo=_LOGO_URI, brandColor=_COLOR,
    )
    assert rejected.status_code == 402

    allowed = _save_org_profile(
        client, admin_headers, whiteLabelLevel="color", brandColor=_COLOR,
    )
    assert allowed.status_code == 200


def test_plan_without_white_label_cannot_even_change_the_color(client, admin_headers, white_label_allowance):
    white_label_allowance(0)
    assert _save_org_profile(
        client, admin_headers, whiteLabelLevel="color", brandColor=_COLOR,
    ).status_code == 402
    # El nivel "none" es el de siempre y no depende del plan.
    assert _save_org_profile(client, admin_headers, whiteLabelLevel="none").status_code == 200


def test_campaign_send_caps_the_level_to_the_current_plan(
    app, client, admin_user, admin_headers, make_aegis_doc_with_quiz, local_email_config,
    white_label_allowance,
):
    """Una bajada de plan surte efecto en el siguiente envío, sin tocar lo guardado."""
    doc_id = make_aegis_doc_with_quiz(admin_user.id)
    _save_org_profile(
        client, admin_headers, whiteLabelLevel="full", brandLogo=_LOGO_URI, brandColor=_COLOR,
    )

    white_label_allowance(2)  # baja de "sin marca" a "logo"
    _run_campaign(client, app, admin_headers, admin_user.id, doc_id)

    sent = local_email_config.messages[0]
    # Degradado a "logo": el logo y el color siguen, la marca del producto vuelve.
    assert 'src="cid:brand-logo"' in sent["html"]
    assert _COLOR in sent["html"]
    assert "Ellysia" in sent["html"]

    # Y lo guardado no se ha tocado: al recuperar el plan vuelve a aplicarse.
    assert client.get(
        "/aegis/org-profile", headers=admin_headers
    ).get_json()["whiteLabelLevel"] == "full"


def test_public_quiz_serves_the_same_brand_as_the_email(
    app, client, admin_user, admin_headers, make_aegis_doc_with_quiz, local_email_config,
):
    """El test es la segunda mitad de la campaña: llega con la misma marca."""
    doc_id = make_aegis_doc_with_quiz(admin_user.id)
    _save_org_profile(
        client, admin_headers, whiteLabelLevel="full", brandLogo=_LOGO_URI, brandColor=_COLOR,
    )
    campaign_id = _run_campaign(client, app, admin_headers, admin_user.id, doc_id)
    token = _fetch_token_for_email(app, campaign_id, "empleado@empresa.test")

    quiz = client.get(f"/aegis/quiz?t={token}").get_json()

    assert quiz["whiteLabel"] == {
        "level": "full", "brandName": "ACME", "brandLogo": _LOGO_URI, "brandColor": _COLOR,
    }


def test_public_quiz_without_white_label_reports_nothing_to_replace(
    app, client, admin_user, admin_headers, make_aegis_doc_with_quiz, local_email_config,
):
    doc_id = make_aegis_doc_with_quiz(admin_user.id)
    _save_org_profile(client, admin_headers)
    campaign_id = _run_campaign(client, app, admin_headers, admin_user.id, doc_id)
    token = _fetch_token_for_email(app, campaign_id, "empleado@empresa.test")

    quiz = client.get(f"/aegis/quiz?t={token}").get_json()

    assert quiz["whiteLabel"] == {
        "level": "none", "brandName": "", "brandLogo": "", "brandColor": "",
    }
