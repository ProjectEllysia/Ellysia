"""Tests de integración del módulo Themis (escaneos y carpetas).

Los escaneos reales (nmap/nikto/openvas) corren en el worker en segundo plano;
aquí se verifica la frontera de autorización y los caminos síncronos de lectura
y de carpetas, sin lanzar herramientas externas ni depender de Redis.
"""

import pytest

pytestmark = pytest.mark.integration


# ------------------------------------------------------------------- escaneos

_VALID_NMAP_BODY = {"target": "127.0.0.1", "ports": "80"}


def test_start_nmap_requires_authentication(client):
    assert client.post("/themis/nmap", json=_VALID_NMAP_BODY).status_code == 401


def test_start_nmap_requires_create_attribute(client, regular_user, auth_headers):
    # role_user no incluye themis_create en su baseline.
    resp = client.post("/themis/nmap", headers=auth_headers(regular_user),
                       json=_VALID_NMAP_BODY)
    assert resp.status_code == 403


def test_list_results_empty(client, regular_user, auth_headers):
    resp = client.get("/themis/results?type=all&page=1&per_page=10",
                      headers=auth_headers(regular_user))
    assert resp.status_code == 200
    assert resp.get_json()["count"] == 0


def test_stats_for_new_user(client, regular_user, auth_headers):
    resp = client.get("/themis/stats", headers=auth_headers(regular_user))
    assert resp.status_code == 200


def test_scan_detail_not_found(client, regular_user, auth_headers):
    resp = client.get("/themis/results/999999", headers=auth_headers(regular_user))
    assert resp.status_code == 404


# -------------------------------------------------------------------- carpetas

def test_folder_crud_roundtrip(client, regular_user, auth_headers):
    headers = auth_headers(regular_user)  # role_user tiene los permisos de carpeta

    created = client.post("/themis/folders", headers=headers, json={"name": "Mi carpeta"})
    assert created.status_code == 201
    folder_id = created.get_json()["folderId"]

    listed = client.get("/themis/folders", headers=headers)
    assert listed.status_code == 200
    names = [f["name"] for f in listed.get_json()["folders"]]
    assert "Mi carpeta" in names

    renamed = client.put(f"/themis/folders/{folder_id}", headers=headers,
                         json={"name": "Renombrada"})
    assert renamed.status_code == 200
    assert renamed.get_json()["name"] == "Renombrada"

    deleted = client.delete(f"/themis/folders/{folder_id}", headers=headers)
    assert deleted.status_code == 200


def test_folder_isolation_between_users(client, make_user, auth_headers):
    owner = make_user(role="role_user")
    other = make_user(role="role_user")

    created = client.post("/themis/folders", headers=auth_headers(owner),
                         json={"name": "Privada"})
    folder_id = created.get_json()["folderId"]

    # Otro usuario no debe poder renombrar la carpeta ajena.
    resp = client.put(f"/themis/folders/{folder_id}", headers=auth_headers(other),
                     json={"name": "Hackeada"})
    assert resp.status_code == 404
