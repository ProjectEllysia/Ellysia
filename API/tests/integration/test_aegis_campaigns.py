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
