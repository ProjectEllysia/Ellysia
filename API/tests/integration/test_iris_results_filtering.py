"""Tests de integración de los filtros/orden de ``GET /iris/results``.

Antes de este cambio el endpoint solo aceptaba ``page``/``per_page`` y el
repositorio fijaba el orden a ``created_at DESC`` sin excepción — cualquier
"ordenar por score" del frontend solo reordenaba lo ya cargado en cliente.
Estos tests fijan el contrato nuevo: filtros por título/veredicto/estado/
origen y orden por servidor en cualquiera de los campos expuestos.
"""

from __future__ import annotations

import pytest

from src.modules.features.iris.model import IrisAnalysis, IrisMailboxConnection
from src.modules.features.iris.repositories import IrisAnalysisRepository, IrisMailboxConnectionRepository
from src.modules.infrastructure import UnitOfWork
from src.modules.shared import encrypt_at_rest

pytestmark = pytest.mark.integration


def _seed(app, user_id: int, **overrides) -> int:
    """Persist a minimal IrisAnalysis and return its id."""
    defaults = dict(
        raw_headers="From: a@b.com\nSubject: Test\n",
        user_id=user_id, status="finished", total_score=50.0, verdict="Suspicious",
    )
    defaults.update(overrides)
    with app.app_context():
        with UnitOfWork() as uow:
            analysis = IrisAnalysis(**defaults)
            IrisAnalysisRepository(uow).save(analysis)
            return analysis.id


def _seed_connection(app, user_id: int) -> int:
    with app.app_context():
        with UnitOfWork() as uow:
            connection = IrisMailboxConnection(
                user_id=user_id, provider="gmail", account_email="victim@example.com",
                scopes="gmail.metadata",
                refresh_token_enc=encrypt_at_rest("token", purpose="iris_mailbox"),
                status="active",
            )
            IrisMailboxConnectionRepository(uow).save(connection)
            return connection.id


# --------------------------------------------------------------- no-regresión

def test_list_results_without_params_behaves_as_before(app, client, regular_user, auth_headers):
    """Sin parámetros nuevos, el comportamiento (orden por fecha desc) no cambia."""
    older = _seed(app, regular_user.id, title="Older")
    newer = _seed(app, regular_user.id, title="Newer")

    resp = client.get("/iris/results?page=1&per_page=10", headers=auth_headers(regular_user))
    assert resp.status_code == 200
    body = resp.get_json()
    ids = [a["analysisId"] for a in body["analyses"]]
    assert ids == [newer, older]
    assert body["total"] == 2
    assert "thresholds" in body and "legitimate" in body["thresholds"]


# --------------------------------------------------------------- filtros

def test_filter_by_search_matches_title_case_insensitive(app, client, regular_user, auth_headers):
    # ASCII a propósito: SQLite (usado en tests) solo pliega mayúsculas/minúsculas
    # ASCII en su LOWER() nativo sin la extensión ICU; Postgres (producción) sí
    # pliega Unicode vía ILIKE, así que este caso no es representativo de un
    # bug real — se evita para no acoplar el test al límite de SQLite.
    _seed(app, regular_user.id, title="Factura pendiente")
    match_id = _seed(app, regular_user.id, title="Reset de password")

    resp = client.get("/iris/results?search=PASSWORD", headers=auth_headers(regular_user))
    body = resp.get_json()
    assert [a["analysisId"] for a in body["analyses"]] == [match_id]


def test_filter_by_verdict(app, client, regular_user, auth_headers):
    _seed(app, regular_user.id, verdict="Legitimate")
    phishing_id = _seed(app, regular_user.id, verdict="Phishing")

    resp = client.get("/iris/results?verdict=Phishing", headers=auth_headers(regular_user))
    body = resp.get_json()
    assert [a["analysisId"] for a in body["analyses"]] == [phishing_id]


def test_filter_by_status(app, client, regular_user, auth_headers):
    _seed(app, regular_user.id, status="finished", total_score=10, verdict="Suspicious")
    pending_id = _seed(app, regular_user.id, status="pending", total_score=None, verdict=None)

    resp = client.get("/iris/results?status=pending", headers=auth_headers(regular_user))
    body = resp.get_json()
    assert [a["analysisId"] for a in body["analyses"]] == [pending_id]


def test_filter_by_source_manual_and_mailbox(app, client, regular_user, auth_headers):
    connection_id = _seed_connection(app, regular_user.id)
    manual_id = _seed(app, regular_user.id, title="Manual")
    mailbox_id = _seed(app, regular_user.id, title="Buzón", connection_id=connection_id,
                        source_message_uid="msg-1")

    resp_manual = client.get("/iris/results?source=manual", headers=auth_headers(regular_user))
    assert [a["analysisId"] for a in resp_manual.get_json()["analyses"]] == [manual_id]

    resp_mailbox = client.get("/iris/results?source=mailbox", headers=auth_headers(regular_user))
    mailbox_body = resp_mailbox.get_json()["analyses"]
    assert [a["analysisId"] for a in mailbox_body] == [mailbox_id]
    assert mailbox_body[0]["provider"] == "gmail"


def test_filters_only_apply_to_own_analyses(app, client, regular_user, admin_user, auth_headers):
    _seed(app, admin_user.id, verdict="Phishing")
    resp = client.get("/iris/results?verdict=Phishing", headers=auth_headers(regular_user))
    assert resp.get_json()["total"] == 0


def test_invalid_verdict_rejected(client, regular_user, auth_headers):
    resp = client.get("/iris/results?verdict=NotAVerdict", headers=auth_headers(regular_user))
    assert resp.status_code == 422


# --------------------------------------------------------------- orden

def test_sort_by_score_ascending(app, client, regular_user, auth_headers):
    low = _seed(app, regular_user.id, total_score=10.0, title="Low")
    high = _seed(app, regular_user.id, total_score=90.0, title="High")

    resp = client.get("/iris/results?sort_by=score&sort_dir=asc", headers=auth_headers(regular_user))
    ids = [a["analysisId"] for a in resp.get_json()["analyses"]]
    assert ids == [low, high]


def test_sort_by_score_puts_null_scores_last_in_both_directions(app, client, regular_user, auth_headers):
    """Un análisis pendiente (score None) no debe colarse en ningún extremo
    de la rampa de riesgo cuando se ordena por score."""
    scored = _seed(app, regular_user.id, total_score=40.0)
    pending = _seed(app, regular_user.id, status="pending", total_score=None, verdict=None)

    for direction in ("asc", "desc"):
        resp = client.get(f"/iris/results?sort_by=score&sort_dir={direction}",
                           headers=auth_headers(regular_user))
        ids = [a["analysisId"] for a in resp.get_json()["analyses"]]
        assert ids == [scored, pending], f"failed for sort_dir={direction}"


def test_sort_by_title_descending(app, client, regular_user, auth_headers):
    a_id = _seed(app, regular_user.id, title="Alpha")
    z_id = _seed(app, regular_user.id, title="Zulu")

    resp = client.get("/iris/results?sort_by=title&sort_dir=desc", headers=auth_headers(regular_user))
    ids = [a["analysisId"] for a in resp.get_json()["analyses"]]
    assert ids == [z_id, a_id]


def test_invalid_sort_by_rejected(client, regular_user, auth_headers):
    resp = client.get("/iris/results?sort_by=not_a_field", headers=auth_headers(regular_user))
    assert resp.status_code == 422
