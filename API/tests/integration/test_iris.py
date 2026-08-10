"""Tests de integración del módulo Iris (análisis de cabeceras)."""

import pytest

pytestmark = pytest.mark.integration


def test_analyze_requires_authentication(client):
    assert client.post("/iris/analyze", json={"headers": "From: a@b.com"}).status_code == 401


def test_analyze_requires_create_attribute(client, stripped_user, auth_headers):
    # Usuario al que le han retirado iris_create.
    resp = client.post("/iris/analyze", headers=auth_headers(stripped_user),
                       json={"headers": "From: a@b.com\nSubject: Hi"})
    assert resp.status_code == 403


def test_list_results_empty(client, regular_user, auth_headers):
    resp = client.get("/iris/results?page=1&per_page=10", headers=auth_headers(regular_user))
    assert resp.status_code == 200
    assert resp.get_json()["total"] == 0


def test_status_unknown_analysis_returns_404(client, regular_user, auth_headers):
    resp = client.get("/iris/status?id=999999", headers=auth_headers(regular_user))
    assert resp.status_code == 404


def test_delete_requires_delete_attribute(client, stripped_user, auth_headers):
    # Sin iris_delete -> 403 antes de tocar la BD.
    resp = client.delete("/iris/results/1", headers=auth_headers(stripped_user))
    assert resp.status_code == 403


def test_analyze_rejects_request_without_headers_or_message(client, root_headers):
    # Fase 2: 'headers' ya no es obligatorio si se envía 'message', pero al
    # menos uno de los dos debe estar presente (validado en el schema).
    resp = client.post("/iris/analyze", headers=root_headers, json={"title": "x"})
    assert resp.status_code == 422
