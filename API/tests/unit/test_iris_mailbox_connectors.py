"""Tests unitarios de los conectores de buzón (Gmail / Microsoft Graph).

Todo el HTTP está mockeado (``unittest.mock.patch`` sobre ``requests.get``/
``requests.post``) -- sin red real, sin credenciales OAuth reales.
"""

from __future__ import annotations

import base64
from unittest import mock

import pytest

from src.modules.features.iris.services.mailbox import MessageRef, get_connector
from src.modules.features.iris.services.mailbox.gmail import GmailConnector
from src.modules.features.iris.services.mailbox.microsoft import GraphConnector

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _oauth_env(monkeypatch):
    monkeypatch.setenv("GMAIL_CLIENT_ID", "gmail-client-id")
    monkeypatch.setenv("GMAIL_CLIENT_SECRET", "gmail-client-secret")
    monkeypatch.setenv("GRAPH_CLIENT_ID", "graph-client-id")
    monkeypatch.setenv("GRAPH_CLIENT_SECRET", "graph-client-secret")
    monkeypatch.setenv("GRAPH_TENANT_ID", "common")


def _response(json_data=None, status_code=200, text=""):
    resp = mock.Mock()
    resp.status_code = status_code
    resp.json.return_value = json_data or {}
    resp.text = text
    resp.raise_for_status.side_effect = None
    return resp


# ------------------------------------------------------------------- Gmail

def test_gmail_authorize_url_picks_metadata_scope_by_default():
    connector = GmailConnector("https://app.example.com/iris/mailbox/callback")
    url = connector.authorize_url("state123", full_message_mode=False)
    assert "gmail.metadata" in url
    assert "gmail.readonly" not in url
    assert "state=state123" in url


def test_gmail_authorize_url_picks_readonly_scope_for_full_message_mode():
    connector = GmailConnector("https://app.example.com/iris/mailbox/callback")
    url = connector.authorize_url("state123", full_message_mode=True)
    assert "gmail.readonly" in url


def test_gmail_exchange_code_returns_token_set():
    connector = GmailConnector("https://app.example.com/iris/mailbox/callback")
    with mock.patch("requests.post", return_value=_response({
        "access_token": "access-1", "refresh_token": "refresh-1",
        "expires_in": 3600, "scope": "gmail.metadata",
    })) as post, mock.patch("requests.get", return_value=_response({
        "emailAddress": "victim@gmail.com", "historyId": "1000",
    })) as get:
        token_set = connector.exchange_code("auth-code")

    assert token_set.refresh_token == "refresh-1"
    assert token_set.access_token == "access-1"
    assert token_set.account_email == "victim@gmail.com"
    assert post.call_args.kwargs["data"]["grant_type"] == "authorization_code"
    get.assert_called_once()


def test_gmail_list_new_bootstrap_returns_no_messages_and_captures_cursor():
    connector = GmailConnector("https://app.example.com/iris/mailbox/callback")
    with mock.patch("requests.get", return_value=_response({"historyId": "555", "emailAddress": "x@gmail.com"})):
        refs, cursor = connector.list_new("access-token", cursor=None)

    assert refs == []
    assert cursor == "555"


def test_gmail_list_new_with_cursor_collects_added_messages():
    connector = GmailConnector("https://app.example.com/iris/mailbox/callback")
    history_response = _response({
        "history": [
            {"messagesAdded": [{"message": {"id": "msg-1"}}]},
            {"messagesAdded": [{"message": {"id": "msg-2"}}]},
        ],
        "historyId": "600",
    })
    with mock.patch("requests.get", return_value=history_response):
        refs, cursor = connector.list_new("access-token", cursor="500")

    assert [r.provider_message_id for r in refs] == ["msg-1", "msg-2"]
    assert cursor == "600"


def test_gmail_list_new_paginates_until_no_next_page_token():
    connector = GmailConnector("https://app.example.com/iris/mailbox/callback")
    page1 = _response({
        "history": [{"messagesAdded": [{"message": {"id": "msg-1"}}]}],
        "historyId": "601", "nextPageToken": "page2",
    })
    page2 = _response({
        "history": [{"messagesAdded": [{"message": {"id": "msg-2"}}]}],
        "historyId": "602",
    })
    with mock.patch("requests.get", side_effect=[page1, page2]):
        refs, cursor = connector.list_new("access-token", cursor="500")

    assert [r.provider_message_id for r in refs] == ["msg-1", "msg-2"]
    assert cursor == "602"


def test_gmail_fetch_headers_reconstructs_rfc5322_block_preserving_order():
    connector = GmailConnector("https://app.example.com/iris/mailbox/callback")
    payload = {"payload": {"headers": [
        {"name": "Authentication-Results", "value": "spf=fail (attacker forged)"},
        {"name": "From", "value": "attacker@evil.tk"},
        {"name": "Authentication-Results", "value": "spf=pass (real, older occurrence)"},
    ]}}
    with mock.patch("requests.get", return_value=_response(payload)):
        raw = connector.fetch_headers("access-token", MessageRef(provider_message_id="msg-1"))

    lines = raw.strip("\r\n").split("\r\n")
    # Orden preservado tal cual lo da la API -- crítico para que
    # parse_raw_headers (primera ocurrencia = más nueva) siga funcionando
    # igual que con un .eml pegado a mano.
    assert lines[0] == "Authentication-Results: spf=fail (attacker forged)"
    assert lines[1] == "From: attacker@evil.tk"


def test_gmail_fetch_raw_decodes_base64url():
    connector = GmailConnector("https://app.example.com/iris/mailbox/callback")
    raw_mime = "From: a@b.com\r\nSubject: Hi\r\n\r\nBody text"
    encoded = base64.urlsafe_b64encode(raw_mime.encode()).decode().rstrip("=")
    with mock.patch("requests.get", return_value=_response({"raw": encoded})):
        decoded = connector.fetch_raw("access-token", MessageRef(provider_message_id="msg-1"))

    assert decoded == raw_mime


def test_gmail_revoke_tolerates_already_revoked_token():
    connector = GmailConnector("https://app.example.com/iris/mailbox/callback")
    with mock.patch("requests.post", return_value=_response(status_code=400)) as post:
        connector.revoke("already-revoked-refresh-token")
    post.assert_called_once()


def test_gmail_list_folders_maps_system_and_user_labels():
    connector = GmailConnector("https://app.example.com/iris/mailbox/callback")
    payload = {"labels": [
        {"id": "INBOX", "name": "INBOX", "type": "system"},
        {"id": "Label_1", "name": "Facturas", "type": "user"},
    ]}
    with mock.patch("requests.get", return_value=_response(payload)):
        folders = connector.list_folders("access-token")

    assert [(f.provider_id, f.display_name, f.folder_type) for f in folders] == [
        ("INBOX", "INBOX", "system"),
        ("Label_1", "Facturas", "user"),
    ]


def test_gmail_missing_env_vars_raise_clear_error(monkeypatch):
    monkeypatch.delenv("GMAIL_CLIENT_ID", raising=False)
    with pytest.raises(ValueError, match="GMAIL_CLIENT_ID"):
        GmailConnector("https://app.example.com/iris/mailbox/callback")


# --------------------------------------------------------------- Microsoft Graph

def test_graph_authorize_url_uses_mail_read_scope():
    connector = GraphConnector("https://app.example.com/iris/mailbox/callback")
    url = connector.authorize_url("state123", full_message_mode=False)
    assert "Mail.Read" in url
    assert "state=state123" in url


def test_graph_exchange_code_returns_token_set():
    connector = GraphConnector("https://app.example.com/iris/mailbox/callback")
    with mock.patch("requests.post", return_value=_response({
        "access_token": "access-1", "refresh_token": "refresh-1",
        "expires_in": 3600, "scope": "Mail.Read",
    })), mock.patch("requests.get", return_value=_response({
        "mail": "victim@company.com", "userPrincipalName": "victim@company.onmicrosoft.com",
    })):
        token_set = connector.exchange_code("auth-code")

    assert token_set.refresh_token == "refresh-1"
    assert token_set.account_email == "victim@company.com"


def test_graph_exchange_code_falls_back_to_upn_when_mail_is_null():
    connector = GraphConnector("https://app.example.com/iris/mailbox/callback")
    with mock.patch("requests.post", return_value=_response({
        "access_token": "access-1", "refresh_token": "refresh-1", "expires_in": 3600,
    })), mock.patch("requests.get", return_value=_response({
        "mail": None, "userPrincipalName": "victim@company.onmicrosoft.com",
    })):
        token_set = connector.exchange_code("auth-code")

    assert token_set.account_email == "victim@company.onmicrosoft.com"


def test_graph_list_new_bootstrap_paginates_to_delta_link_without_messages():
    connector = GraphConnector("https://app.example.com/iris/mailbox/callback")
    page1 = _response({"value": [{"id": "msg-1"}], "@odata.nextLink": "https://graph.microsoft.com/next"})
    page2 = _response({"value": [{"id": "msg-2"}], "@odata.deltaLink": "https://graph.microsoft.com/delta-final"})
    with mock.patch("requests.get", side_effect=[page1, page2]):
        refs, cursor = connector.list_new("access-token", cursor=None)

    # Bootstrap: nunca reporta mensajes, aunque la API los liste -- solo
    # captura el cursor final (sin backfill).
    assert refs == []
    assert cursor == "https://graph.microsoft.com/delta-final"


def test_graph_list_new_with_cursor_caches_headers_from_delta_response():
    connector = GraphConnector("https://app.example.com/iris/mailbox/callback")
    delta_response = _response({
        "value": [{
            "id": "msg-1",
            "internetMessageHeaders": [{"name": "From", "value": "a@b.com"}],
        }],
        "@odata.deltaLink": "https://graph.microsoft.com/delta-next",
    })
    with mock.patch("requests.get", return_value=delta_response) as get:
        refs, cursor = connector.list_new("access-token", cursor="https://graph.microsoft.com/delta-prev")

    assert len(refs) == 1
    assert refs[0].provider_message_id == "msg-1"
    assert cursor == "https://graph.microsoft.com/delta-next"

    # fetch_headers no debe hacer una llamada extra: ya tiene los headers
    # cacheados desde el propio delta.
    get.reset_mock()
    raw = connector.fetch_headers("access-token", refs[0])
    get.assert_not_called()
    assert raw == "From: a@b.com\r\n"


# El deltaLink de Graph es un token opaco que puede rebasar los 255
# caracteres que la columna `sync_cursor` permitía. Estos tests fijan que el
# conector lo devuelve intacto — cualquier recorte lo invalida, y un cursor
# inválido tira la sincronización incremental al bootstrap.

def _long_delta_link(length: int = 900) -> str:
    """Un deltaLink realista: URL de Graph más un token de estado largo.

    Los deltaLink reales llevan dentro un `$deltatoken` codificado cuyo tamaño
    depende del estado de la carpeta; 900 caracteres está dentro de lo que
    devuelve un buzón con actividad, y en todo caso lo que importa aquí es que
    pase de 255.
    """
    return (
        "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages/delta"
        "?$deltatoken=" + ("Ag0AAA" + "X" * length)
    )


def test_graph_bootstrap_preserves_a_delta_link_longer_than_255_chars():
    connector = GraphConnector("https://app.example.com/iris/mailbox/callback")
    delta_link = _long_delta_link()
    assert len(delta_link) > 255

    page = _response({"value": [], "@odata.deltaLink": delta_link})
    with mock.patch("requests.get", return_value=page):
        _refs, cursor = connector.list_new("access-token", cursor=None)

    assert cursor == delta_link


def test_graph_incremental_sync_preserves_a_long_delta_link_exactly():
    connector = GraphConnector("https://app.example.com/iris/mailbox/callback")
    previous = _long_delta_link(600)
    next_link = _long_delta_link(950)

    page = _response({"value": [{"id": "msg-1"}], "@odata.deltaLink": next_link})
    with mock.patch("requests.get", return_value=page) as get:
        refs, cursor = connector.list_new("access-token", cursor=previous)

    # El cursor anterior se usa como URL tal cual, sin reconstruirlo.
    assert get.call_args.args[0] == previous
    assert len(refs) == 1
    assert cursor == next_link
    assert len(cursor) > 255


def test_graph_expired_cursor_rebootstraps_instead_of_failing():
    """410 Gone: el deltaLink cayó fuera de la ventana de retención de Graph.

    La única salida es volver a capturar un cursor desde cero. No se pierde
    correo local: el bootstrap no hace backfill, solo marca el punto de
    partida, y los análisis ya ingeridos siguen donde estaban.
    """
    connector = GraphConnector("https://app.example.com/iris/mailbox/callback")
    fresh = _long_delta_link(400)

    gone = _response(status_code=410)
    bootstrap = _response({"value": [], "@odata.deltaLink": fresh})
    with mock.patch("requests.get", side_effect=[gone, bootstrap]):
        refs, cursor = connector.list_new("access-token", cursor=_long_delta_link(300))

    assert refs == []
    assert cursor == fresh


def test_graph_fetch_raw_returns_response_text_directly():
    connector = GraphConnector("https://app.example.com/iris/mailbox/callback")
    resp = _response(text="From: a@b.com\r\nSubject: Hi\r\n\r\nBody")
    with mock.patch("requests.get", return_value=resp):
        raw = connector.fetch_raw("access-token", MessageRef(provider_message_id="msg-1"))
    assert raw.startswith("From: a@b.com")


def test_graph_list_folders_maps_well_known_and_user_created():
    connector = GraphConnector("https://app.example.com/iris/mailbox/callback")
    payload = {"value": [
        {"id": "AAA1", "displayName": "Inbox", "wellKnownName": "inbox"},
        {"id": "BBB2", "displayName": "Clientes"},
    ]}
    with mock.patch("requests.get", return_value=_response(payload)):
        folders = connector.list_folders("access-token")

    assert [(f.provider_id, f.display_name, f.folder_type) for f in folders] == [
        ("AAA1", "Inbox", "system"),
        ("BBB2", "Clientes", "user"),
    ]


def test_graph_list_folders_paginates_via_next_link():
    connector = GraphConnector("https://app.example.com/iris/mailbox/callback")
    page1 = _response({
        "value": [{"id": "AAA1", "displayName": "Inbox", "wellKnownName": "inbox"}],
        "@odata.nextLink": "https://graph.microsoft.com/next-page",
    })
    page2 = _response({"value": [{"id": "BBB2", "displayName": "Clientes"}]})
    with mock.patch("requests.get", side_effect=[page1, page2]) as get:
        folders = connector.list_folders("access-token")

    assert [f.provider_id for f in folders] == ["AAA1", "BBB2"]
    assert get.call_args_list[1].args[0] == "https://graph.microsoft.com/next-page"


def test_graph_revoke_does_not_raise_platform_limitation():
    # Graph no tiene API de revocación por refresh_token -- debe degradar a
    # un no-op documentado, nunca lanzar.
    connector = GraphConnector("https://app.example.com/iris/mailbox/callback")
    connector.revoke("some-refresh-token")


# ---------------------------------------------------------------------- registry

def test_get_connector_returns_correct_implementation():
    assert isinstance(get_connector("gmail", "https://x/callback"), GmailConnector)
    assert isinstance(get_connector("microsoft", "https://x/callback"), GraphConnector)


def test_get_connector_rejects_unknown_provider():
    with pytest.raises(ValueError, match="yahoo"):
        get_connector("yahoo", "https://x/callback")
