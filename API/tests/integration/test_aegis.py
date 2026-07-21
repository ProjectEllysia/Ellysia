"""Tests de integración del módulo Aegis (píldoras de concienciación)."""

import pytest

pytestmark = pytest.mark.integration


def test_generate_requires_authentication(client):
    assert client.post("/aegis/generate", json={"topicId": 1}).status_code == 401


def test_generate_requires_create_attribute(client, regular_user, auth_headers):
    # role_user tiene aegis_read pero no aegis_create.
    resp = client.post("/aegis/generate", headers=auth_headers(regular_user),
                       json={"topicId": 1})
    assert resp.status_code == 403


def test_list_documents_empty(client, regular_user, auth_headers):
    resp = client.get("/aegis/documents", headers=auth_headers(regular_user))
    assert resp.status_code == 200
    assert resp.get_json()["count"] == 0


def test_status_unknown_document_returns_404(client, regular_user, auth_headers):
    resp = client.get("/aegis/status?id=999999", headers=auth_headers(regular_user))
    assert resp.status_code == 404


def test_brands_catalog_available(client, regular_user, auth_headers):
    resp = client.get("/aegis/brands", headers=auth_headers(regular_user))
    assert resp.status_code == 200
    assert "brands" in resp.get_json()


# ============================================================================
# UPSERT / EDICIÓN DE PÍLDORA (PUT /aegis/document)
# ============================================================================


@pytest.fixture()
def make_aegis_doc(app):
    """Factory que crea una píldora Aegis en estado 'done' para un usuario."""

    def _make(user_id, status="done"):
        from src.modules.infrastructure.unit_of_work import UnitOfWork
        from src.modules.features.aegis.model import AegisDocument, AegisTip, Topic
        from src.modules.features.aegis.repositories import AegisDocumentRepository

        with app.app_context():
            with UnitOfWork() as uow:
                topic = Topic(title="Phishing")
                uow.session.add(topic)
                uow.session.flush()

                doc = AegisDocument(
                    title="pildora_interna",
                    filename="test_pill.json",
                    status=status,
                    format="json",
                    topic_id=topic.id,
                    user_id=user_id,
                    is_ai_generated=1,
                    subtitle="Título IA original",
                    intro="Intro original",
                    closing="Cierre original",
                    contact_email="sec@empresa.com",
                    company="ACME",
                )
                saved = AegisDocumentRepository(uow).save(doc)
                doc_id = saved.id
                uow.session.add(AegisTip(
                    document_id=doc_id, position=1,
                    headline="Tip original", body="Cuerpo original",
                ))
        return doc_id

    return _make


def _valid_pill_payload():
    return {
        "subtitle": "Título corregido",
        "intro": "Introducción mejorada\n\nSegundo párrafo.",
        "closing": "Cierre corregido",
        "contactEmail": "ciso@empresa.com",
        "company": "ACME",
        "tips": [
            {"headline": "Recomendación A", "body": "Cuerpo A", "links": []},
            {
                "headline": "Recomendación B",
                "body": "Cuerpo B",
                "links": [{"text": "Guía", "url": "https://example.com/guia"}],
            },
        ],
    }


def test_update_requires_authentication(client, make_aegis_doc, admin_user):
    doc_id = make_aegis_doc(admin_user.id)
    resp = client.put(f"/aegis/document?id={doc_id}", json=_valid_pill_payload())
    assert resp.status_code == 401


def test_update_requires_update_attribute(client, regular_user, auth_headers, make_aegis_doc):
    # role_user tiene aegis_read pero no aegis_update.
    doc_id = make_aegis_doc(regular_user.id)
    resp = client.put(
        f"/aegis/document?id={doc_id}",
        headers=auth_headers(regular_user),
        json=_valid_pill_payload(),
    )
    assert resp.status_code == 403


def test_update_unknown_document_returns_404(client, admin_user, auth_headers):
    resp = client.put(
        "/aegis/document?id=999999",
        headers=auth_headers(admin_user),
        json=_valid_pill_payload(),
    )
    assert resp.status_code == 404


def test_update_rejects_invalid_payload(client, admin_user, auth_headers, make_aegis_doc):
    doc_id = make_aegis_doc(admin_user.id)
    bad = _valid_pill_payload()
    bad["subtitle"] = ""  # viola min length
    resp = client.put(
        f"/aegis/document?id={doc_id}",
        headers=auth_headers(admin_user),
        json=bad,
    )
    assert resp.status_code in (400, 422)


def test_update_persists_pill(client, admin_user, auth_headers, make_aegis_doc):
    doc_id = make_aegis_doc(admin_user.id)
    headers = auth_headers(admin_user)

    resp = client.put(
        f"/aegis/document?id={doc_id}", headers=headers, json=_valid_pill_payload()
    )
    assert resp.status_code == 200

    got = client.get(f"/aegis/document?id={doc_id}", headers=headers)
    assert got.status_code == 200
    data = got.get_json()
    assert data["pill"]["subtitle"] == "Título corregido"
    assert "Segundo párrafo" in data["pill"]["intro"]
    assert data["pill"]["closing"] == "Cierre corregido"
    assert data["pill"]["contactEmail"] == "ciso@empresa.com"

    tips = data["pill"]["tips"]
    assert [t["headline"] for t in tips] == ["Recomendación A", "Recomendación B"]
    assert [t["position"] for t in tips] == [1, 2]
    assert tips[1]["links"] == [{"text": "Guía", "url": "https://example.com/guia"}]
