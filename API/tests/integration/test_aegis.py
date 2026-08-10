"""Tests de integración del módulo Aegis (píldoras de concienciación)."""

import pytest

pytestmark = pytest.mark.integration


def test_generate_requires_authentication(client):
    assert client.post("/aegis/generate", json={"topicId": 1}).status_code == 401


def test_generate_requires_create_attribute(client, stripped_user, auth_headers):
    # Usuario al que le han retirado aegis_create.
    resp = client.post("/aegis/generate", headers=auth_headers(stripped_user),
                       json={"topicId": 1})
    assert resp.status_code == 403


def test_generate_accepts_the_payload_the_frontend_sends(
    client, admin_user, admin_headers, monkeypatch,
):
    """Valida el contrato del endpoint contra el cuerpo REAL de la SPA.

    Los tests del workflow llaman al manager directamente y se saltan la
    validación de esquema, así que un campo que el frontend manda y
    ``AegisTweaksSchema`` no declara no se veía: Marshmallow lo rechaza como
    "Unknown field" y el usuario recibe un 422 opaco. Pasó exactamente eso con
    ``useHygeiaInventory``.
    """
    from src.modules.features.aegis.managers import AegisManager

    # El encolado real necesita Redis; aquí solo interesa que el cuerpo valide.
    monkeypatch.setattr(
        AegisManager, "generate", lambda self, topic_id, tweaks: 1234,
    )

    resp = client.post("/aegis/generate", headers=admin_headers, json={
        "topicId": 1,
        "tweaks": {
            "company": "ACME", "language": "es", "tone": "profesional",
            "audienceLevel": "mixed", "mentionContact": "", "sector": "",
            "topicFocus": "", "companySize": "", "employeeCount": None,
            "jurisdiction": "", "workModel": "", "recentIncident": "",
            "trackedProducts": [{"vendor": "microsoft", "product": "windows"}],
            "useHygeiaInventory": True,
        },
    })
    assert resp.status_code in (200, 201, 202), resp.get_json()


def test_org_profile_accepts_the_payload_the_frontend_sends(
    client, admin_user, admin_headers,
):
    resp = client.put("/aegis/org-profile", headers=admin_headers, json={
        "company": "ACME", "mentionContact": "sec@acme.test", "tone": "profesional",
        "companySize": "", "jurisdiction": "", "language": "es", "sector": "",
        "workModel": "", "employeeCount": None,
        "trackedProducts": [{"vendor": "mozilla", "product": "firefox"}],
        "useHygeiaInventory": False,
    })
    assert resp.status_code == 200, resp.get_json()

    stored = client.get("/aegis/org-profile", headers=admin_headers).get_json()
    assert stored["trackedProducts"] == [{"vendor": "mozilla", "product": "firefox"}]
    assert stored["useHygeiaInventory"] is False
    # No es un campo del perfil, sino del entorno: sin agentes, no se ofrece.
    assert stored["hygeiaInventoryAvailable"] is False


def test_list_documents_empty(client, regular_user, auth_headers):
    resp = client.get("/aegis/documents", headers=auth_headers(regular_user))
    assert resp.status_code == 200
    assert resp.get_json()["count"] == 0


def test_status_unknown_document_returns_404(client, regular_user, auth_headers):
    resp = client.get("/aegis/status?id=999999", headers=auth_headers(regular_user))
    assert resp.status_code == 404


def test_product_search_reads_the_local_cpe_index(client, regular_user, auth_headers, app):
    """El selector de productos sale del espejo local de NVD, no de un
    catálogo fijo en SecOpsConfig.json (que se retiró)."""
    from src.modules.features.themis.repositories import KbRepository
    from src.modules.infrastructure import UnitOfWork

    with app.app_context():
        with UnitOfWork() as uow:
            repo = KbRepository(uow)
            repo.upsert_cve(
                {"cve_id": "CVE-2026-7777", "cvss_score": 9.8, "cvss_vector": "CVSS:3.1/AV:N",
                 "severity": "CRITICAL", "description": "RCE", "cwe_ids": [], "source": "nvd"},
                [{"vendor": "microsoft", "product": "windows", "exact_version": "10",
                  "version_start_including": None, "version_start_excluding": None,
                  "version_end_including": None, "version_end_excluding": None}],
            )
            repo.rebuild_cpe_product_index()

    resp = client.get("/aegis/products?q=windows", headers=auth_headers(regular_user))
    assert resp.status_code == 200
    products = resp.get_json()["products"]
    assert {"vendor": "microsoft", "product": "windows"} in [
        {"vendor": p["vendor"], "product": p["product"]} for p in products
    ]


def test_product_search_requires_a_term(client, regular_user, auth_headers):
    assert client.get("/aegis/products?q=a", headers=auth_headers(regular_user)).status_code == 422


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


def test_update_requires_update_attribute(client, stripped_user, auth_headers, make_aegis_doc):
    # Usuario al que le han retirado aegis_update, sobre una píldora suya.
    doc_id = make_aegis_doc(stripped_user.id)
    resp = client.put(
        f"/aegis/document?id={doc_id}",
        headers=auth_headers(stripped_user),
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
