"""Tests de integración de los endpoints del conector de buzón de Iris.

La lógica de negocio (OAuth state, conectores, cuotas) ya está cubierta en
test_iris_mailbox_manager.py / test_iris_mailbox_connectors.py -- aquí se
verifica el cableado HTTP: auth, atributos, ownership entre usuarios, y
que el callback (sin Authorization header posible) responde con un
redirect en vez de JSON.
"""

from __future__ import annotations

from unittest import mock

import pytest

from src.modules.features.iris.managers.mailbox import IrisMailboxManager
from src.modules.features.iris.model import IrisMailboxConnection
from src.modules.features.iris.repositories import IrisMailboxConnectionRepository
from src.modules.features.iris.services.mailbox.base import MailboxFolder
from src.modules.infrastructure import UnitOfWork
from src.modules.shared import encrypt_at_rest

pytestmark = pytest.mark.integration


def _save_connection(app, user_id, **overrides) -> int:
    defaults = dict(
        user_id=user_id, provider="gmail", account_email="victim@example.com",
        scopes="gmail.metadata",
        refresh_token_enc=encrypt_at_rest("refresh-token", purpose="iris_mailbox"),
        status="active",
    )
    defaults.update(overrides)
    with app.app_context():
        with UnitOfWork() as uow:
            conn = IrisMailboxConnection(**defaults)
            IrisMailboxConnectionRepository(uow).save(conn)
            return conn.id


# ------------------------------------------------------------------- auth/attrs

def test_providers_requires_authentication(client):
    assert client.get("/iris/mailbox/providers").status_code == 401


def test_connect_requires_create_attribute(client, stripped_user, auth_headers):
    resp = client.post("/iris/mailbox/connect", headers=auth_headers(stripped_user),
                       json={"provider": "gmail"})
    assert resp.status_code == 403


def test_list_connections_requires_authentication(client):
    assert client.get("/iris/mailbox/connections").status_code == 401


def test_delete_connection_requires_delete_attribute(client, stripped_user, auth_headers):
    resp = client.delete("/iris/mailbox/connections/1", headers=auth_headers(stripped_user))
    assert resp.status_code == 403


# --------------------------------------------------------------------- providers

def test_providers_lists_gmail_and_microsoft(client, root_headers):
    resp = client.get("/iris/mailbox/providers", headers=root_headers)
    assert resp.status_code == 200
    assert set(resp.get_json()["providers"]) == {"gmail", "microsoft"}


# ------------------------------------------------------------------------ connect

def test_connect_rejects_unknown_provider(client, root_headers):
    resp = client.post("/iris/mailbox/connect", headers=root_headers, json={"provider": "yahoo"})
    assert resp.status_code == 400


def test_connect_returns_authorize_url(client, root_headers):
    with mock.patch.object(IrisMailboxManager, "start_connect",
                           return_value="https://provider.example/authorize?state=abc"):
        resp = client.post("/iris/mailbox/connect", headers=root_headers, json={"provider": "gmail"})
    assert resp.status_code == 201
    assert resp.get_json()["authorizeUrl"] == "https://provider.example/authorize?state=abc"


# ----------------------------------------------------------------------- callback

def test_callback_with_consent_denied_redirects_with_error(client):
    resp = client.get("/iris/mailbox/callback?state=x&error=access_denied", follow_redirects=False)
    assert resp.status_code == 302
    assert "error=consent_denied" in resp.headers["Location"]


def test_callback_missing_code_redirects_with_error(client):
    resp = client.get("/iris/mailbox/callback?state=x", follow_redirects=False)
    assert resp.status_code == 302
    assert "error=missing_code" in resp.headers["Location"]


def test_callback_invalid_state_redirects_with_error(client):
    resp = client.get("/iris/mailbox/callback?state=not-a-real-state&code=abc", follow_redirects=False)
    assert resp.status_code == 302
    assert "error=invalid_state" in resp.headers["Location"]


def test_callback_success_redirects_with_connected_flag(client):
    with mock.patch.object(IrisMailboxManager, "handle_callback", return_value=42):
        resp = client.get("/iris/mailbox/callback?state=x&code=abc", follow_redirects=False)
    assert resp.status_code == 302
    assert "connected=1" in resp.headers["Location"]


# ------------------------------------------------------------------------- CRUD

def test_list_connections_never_exposes_tokens(client, regular_user, auth_headers, app):
    _save_connection(app, regular_user.id)
    resp = client.get("/iris/mailbox/connections", headers=auth_headers(regular_user))
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["total"] == 1
    connection = body["connections"][0]
    assert connection["accountEmail"] == "victim@example.com"
    assert "refreshTokenEnc" not in connection
    assert "accessTokenEnc" not in connection


def test_update_connection_cross_user_returns_404(client, make_user, auth_headers, app):
    # regular_user (role_user) solo tiene IRIS_READ -- la comprobación de
    # ownership cruzada necesita que el actor SÍ tenga IRIS_UPDATE para
    # llegar a ella (si no, 403 por permisos llega antes, que es un test
    # distinto, ya cubierto por test_connect_requires_create_attribute).
    owner = make_user(role="role_admin")
    other_admin = make_user(role="role_admin")
    connection_id = _save_connection(app, owner.id)
    resp = client.patch(f"/iris/mailbox/connections/{connection_id}",
                        headers=auth_headers(other_admin), json={"status": "paused"})
    assert resp.status_code == 404


def test_update_connection_invalid_status_returns_422(client, admin_user, auth_headers, app):
    connection_id = _save_connection(app, admin_user.id)
    resp = client.patch(f"/iris/mailbox/connections/{connection_id}",
                        headers=auth_headers(admin_user), json={"status": "deleted"})
    assert resp.status_code == 422


def test_delete_connection_cross_user_returns_404(client, make_user, auth_headers, app):
    owner = make_user(role="role_admin")
    other_admin = make_user(role="role_admin")
    connection_id = _save_connection(app, owner.id)
    resp = client.delete(f"/iris/mailbox/connections/{connection_id}", headers=auth_headers(other_admin))
    assert resp.status_code == 404


def test_delete_unknown_connection_returns_404(client, root_headers):
    resp = client.delete("/iris/mailbox/connections/999999", headers=root_headers)
    assert resp.status_code == 404


def test_sync_unknown_connection_returns_404(client, root_headers):
    resp = client.post("/iris/mailbox/connections/999999/sync", headers=root_headers)
    assert resp.status_code == 404


def test_sync_queues_and_returns_202(client, admin_user, auth_headers, app):
    connection_id = _save_connection(app, admin_user.id)
    with mock.patch.object(IrisMailboxManager, "submit_sync") as submit_sync:
        resp = client.post(f"/iris/mailbox/connections/{connection_id}/sync",
                           headers=auth_headers(admin_user))
    assert resp.status_code == 202
    submit_sync.assert_called_once_with(connection_id)


# --------------------------------------------------------------- B16: folder

def test_update_connection_folder_too_long_returns_422(client, admin_user, auth_headers, app):
    connection_id = _save_connection(app, admin_user.id)
    resp = client.patch(f"/iris/mailbox/connections/{connection_id}",
                        headers=auth_headers(admin_user), json={"folder": "x" * 256})
    assert resp.status_code == 422


def test_connect_folder_too_long_returns_422(client, root_headers):
    resp = client.post("/iris/mailbox/connect", headers=root_headers,
                       json={"provider": "gmail", "folder": "x" * 256})
    assert resp.status_code == 422


def test_folders_unknown_connection_returns_404(client, root_headers):
    resp = client.get("/iris/mailbox/connections/999999/folders", headers=root_headers)
    assert resp.status_code == 404


def test_folders_returns_provider_folders(client, admin_user, auth_headers, app):
    connection_id = _save_connection(app, admin_user.id)
    fake_folders = [
        MailboxFolder(provider_id="Label_1", display_name="Facturas", folder_type="user"),
        MailboxFolder(provider_id="INBOX", display_name="Inbox", folder_type="system"),
    ]
    with mock.patch.object(IrisMailboxManager, "list_folders", return_value=fake_folders):
        resp = client.get(f"/iris/mailbox/connections/{connection_id}/folders",
                          headers=auth_headers(admin_user))
    assert resp.status_code == 200
    body = resp.get_json()["folders"]
    assert body == [
        {"providerId": "Label_1", "displayName": "Facturas", "folderType": "user"},
        {"providerId": "INBOX", "displayName": "Inbox", "folderType": "system"},
    ]
