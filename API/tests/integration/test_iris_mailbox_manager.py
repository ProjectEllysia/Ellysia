"""Tests de integración de IrisMailboxManager: OAuth state, CRUD, cuotas,
idempotencia y sync — con los conectores mockeados (ya cubiertos por
test_iris_mailbox_connectors.py) y sin red real.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest import mock

import pytest
from itsdangerous import BadSignature

import src.modules.features.iris.mailbox_managers as mailbox_managers_mod
from src.modules.features.iris.exceptions import (
    IrisMailboxConnectionNotFoundError,
    IrisMailboxInvalidProviderError,
    IrisMailboxOAuthStateError,
    IrisMailboxQuotaExceededError,
)
from src.modules.features.iris.mailbox_managers import IrisMailboxManager
from src.modules.features.iris.model import IrisMailboxConnection
from src.modules.features.iris.repositories import IrisAnalysisRepository, IrisMailboxConnectionRepository
from src.modules.features.iris.services.mailbox.base import MessageRef, TokenSet
from src.modules.infrastructure import UnitOfWork
from src.modules.shared import decrypt_at_rest, encrypt_at_rest, utcnow_naive

pytestmark = pytest.mark.integration


class _FakeTaskQueue:
    def __init__(self):
        self.submitted = []

    def submit(self, **kwargs):
        self.submitted.append(kwargs)


class _FakeConnector:
    """Doble de MailboxConnector totalmente controlado por el test."""

    def __init__(self, revoke_raises=False, refresh_raises_reauth=False):
        self.revoked_tokens = []
        self._revoke_raises = revoke_raises
        self._refresh_raises_reauth = refresh_raises_reauth

    def authorize_url(self, state, full_message_mode):
        return f"https://provider.example/authorize?state={state}"

    def exchange_code(self, code):
        return TokenSet(
            refresh_token="new-refresh-token", access_token="new-access-token",
            access_token_expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            scopes="mail.read", account_email="victim@example.com",
        )

    def refresh(self, refresh_token):
        if self._refresh_raises_reauth:
            import requests
            resp = mock.Mock(status_code=401)
            error = requests.HTTPError(response=resp)
            raise error
        return TokenSet(
            refresh_token=refresh_token, access_token="refreshed-access-token",
            access_token_expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            scopes="mail.read", account_email="victim@example.com",
        )

    def list_new(self, access_token, cursor):
        if cursor is None:
            return [], "cursor-1"
        return [MessageRef(provider_message_id="msg-1")], "cursor-2"

    def fetch_headers(self, access_token, message_ref):
        return "From: a@b.com\r\nSubject: Hi\r\n"

    def fetch_raw(self, access_token, message_ref):
        return "From: a@b.com\r\nSubject: Hi\r\n\r\nBody"

    def revoke(self, refresh_token):
        self.revoked_tokens.append(refresh_token)
        if self._revoke_raises:
            raise RuntimeError("provider is down")


def _connection(user_id, **overrides) -> IrisMailboxConnection:
    defaults = dict(
        user_id=user_id, provider="gmail", account_email="victim@example.com",
        scopes="gmail.metadata", refresh_token_enc=encrypt_at_rest("old-refresh-token", purpose="iris_mailbox"),
        status="active",
    )
    defaults.update(overrides)
    return IrisMailboxConnection(**defaults)


def _save(app, connection: IrisMailboxConnection) -> int:
    with app.app_context():
        with UnitOfWork() as uow:
            IrisMailboxConnectionRepository(uow).save(connection)
            return connection.id


# ------------------------------------------------------------------- OAuth state

def test_state_roundtrips(app):
    with app.app_context():
        state = IrisMailboxManager._sign_state(
            user_id=1, provider="gmail", full_message_mode=False, folder=None,
        )
        claims = IrisMailboxManager._verify_state(state)
    assert claims["user_id"] == 1
    assert claims["provider"] == "gmail"


def test_tampered_state_is_rejected(app):
    with app.app_context():
        state = IrisMailboxManager._sign_state(
            user_id=1, provider="gmail", full_message_mode=False, folder=None,
        )
        with pytest.raises(IrisMailboxOAuthStateError):
            IrisMailboxManager._verify_state(state + "tampered")


def test_expired_state_is_rejected(app, monkeypatch):
    with app.app_context():
        serializer = IrisMailboxManager._state_serializer()
        state = serializer.dumps({"user_id": 1, "provider": "gmail",
                                   "full_message_mode": False, "folder": None})

        def _loads_expired(self, *args, **kwargs):
            from itsdangerous import SignatureExpired
            raise SignatureExpired("expired")

        monkeypatch.setattr("itsdangerous.URLSafeTimedSerializer.loads", _loads_expired)
        with pytest.raises(IrisMailboxOAuthStateError):
            IrisMailboxManager._verify_state(state)


# ------------------------------------------------------------------- connect

def test_start_connect_rejects_unknown_provider(app, regular_user):
    with app.app_context():
        with pytest.raises(IrisMailboxInvalidProviderError):
            IrisMailboxManager().start_connect(regular_user.id, "yahoo")


def test_start_connect_enforces_quota(app, regular_user, monkeypatch):
    monkeypatch.setattr(mailbox_managers_mod.CR, "get_iris_max_connections_per_user", lambda: 1)
    with app.app_context():
        _save(app, _connection(regular_user.id, account_email="a@gmail.com"))
        with pytest.raises(IrisMailboxQuotaExceededError):
            IrisMailboxManager().start_connect(regular_user.id, "gmail")


def test_start_connect_returns_authorize_url(app, regular_user):
    with app.app_context():
        with mock.patch.object(mailbox_managers_mod, "get_connector", return_value=_FakeConnector()):
            url = IrisMailboxManager().start_connect(regular_user.id, "gmail")
    assert url.startswith("https://provider.example/authorize?state=")


# ------------------------------------------------------------------- callback

def test_handle_callback_creates_connection(app, regular_user):
    with app.app_context():
        state = IrisMailboxManager._sign_state(
            user_id=regular_user.id, provider="gmail", full_message_mode=False, folder=None,
        )
        with mock.patch.object(mailbox_managers_mod, "get_connector", return_value=_FakeConnector()):
            connection_id = IrisMailboxManager().handle_callback(state, "auth-code")

        with UnitOfWork() as uow:
            conn = IrisMailboxConnectionRepository(uow).get_by_id(connection_id)
            assert conn.account_email == "victim@example.com"
            assert conn.status == "active"
            # El refresh token nunca se guarda en claro.
            assert conn.refresh_token_enc != "new-refresh-token"
            assert decrypt_at_rest(conn.refresh_token_enc, purpose="iris_mailbox") == "new-refresh-token"


def test_handle_callback_reconnect_updates_existing_row(app, regular_user):
    with app.app_context():
        existing_id = _save(app, _connection(regular_user.id, status="reauth_required"))

        state = IrisMailboxManager._sign_state(
            user_id=regular_user.id, provider="gmail", full_message_mode=False, folder=None,
        )
        with mock.patch.object(mailbox_managers_mod, "get_connector", return_value=_FakeConnector()):
            connection_id = IrisMailboxManager().handle_callback(state, "auth-code")

        assert connection_id == existing_id
        with UnitOfWork() as uow:
            conn = IrisMailboxConnectionRepository(uow).get_by_id(existing_id)
            assert conn.status == "active"
            assert conn.last_error is None


def test_handle_callback_invalid_state_raises(app):
    with app.app_context():
        with pytest.raises(IrisMailboxOAuthStateError):
            IrisMailboxManager().handle_callback("not-a-real-state", "auth-code")


# ------------------------------------------------------------------- CRUD

def test_list_connections_only_returns_own(app, regular_user, admin_user):
    with app.app_context():
        _save(app, _connection(regular_user.id, account_email="mine@gmail.com"))
        _save(app, _connection(admin_user.id, account_email="theirs@gmail.com"))

        mine = IrisMailboxManager.list_connections(regular_user.id)
        assert [c.account_email for c in mine] == ["mine@gmail.com"]


def test_update_connection_requires_ownership(app, regular_user, admin_user):
    with app.app_context():
        connection_id = _save(app, _connection(admin_user.id))
        with pytest.raises(IrisMailboxConnectionNotFoundError):
            IrisMailboxManager().update_connection(connection_id, regular_user.id, status="paused")


def test_update_connection_rejects_invalid_status(app, regular_user):
    with app.app_context():
        connection_id = _save(app, _connection(regular_user.id))
        with pytest.raises(ValueError):
            IrisMailboxManager().update_connection(connection_id, regular_user.id, status="not-a-real-status")


def test_delete_connection_revokes_then_deletes_even_if_revoke_fails(app, regular_user):
    with app.app_context():
        connection_id = _save(app, _connection(regular_user.id))
        fake_connector = _FakeConnector(revoke_raises=True)
        with mock.patch.object(mailbox_managers_mod, "get_connector", return_value=fake_connector):
            IrisMailboxManager().delete_connection(connection_id, regular_user.id)

        assert fake_connector.revoked_tokens == ["old-refresh-token"]
        with UnitOfWork() as uow:
            assert IrisMailboxConnectionRepository(uow).get_by_id(connection_id) is None


# ------------------------------------------------------------------- sync

def test_sync_connection_ingests_new_messages_and_advances_cursor(app, regular_user):
    with app.app_context():
        connection_id = _save(app, _connection(regular_user.id, sync_cursor="cursor-0"))

        with mock.patch.object(mailbox_managers_mod, "get_connector", return_value=_FakeConnector()):
            IrisMailboxManager()._sync_connection(connection_id)

        with UnitOfWork() as uow:
            conn = IrisMailboxConnectionRepository(uow).get_by_id(connection_id)
            assert conn.sync_cursor == "cursor-2"
            assert conn.ingested_today == 1
            assert conn.last_error is None

            analyses = IrisAnalysisRepository(uow).get_by_user(regular_user.id)
            assert len(analyses) == 1
            assert analyses[0].connection_id == connection_id
            assert analyses[0].source_message_uid == "msg-1"


def test_sync_connection_stops_at_daily_quota(app, regular_user, monkeypatch):
    monkeypatch.setattr(mailbox_managers_mod.CR, "get_iris_max_ingested_per_day", lambda: 0)
    with app.app_context():
        connection_id = _save(app, _connection(regular_user.id, sync_cursor="cursor-0"))

        with mock.patch.object(mailbox_managers_mod, "get_connector", return_value=_FakeConnector()):
            IrisMailboxManager()._sync_connection(connection_id)

        with UnitOfWork() as uow:
            assert IrisAnalysisRepository(uow).get_by_user(regular_user.id) == []


def test_sync_connection_marks_reauth_required_on_revoked_token(app, regular_user):
    with app.app_context():
        connection_id = _save(app, _connection(
            regular_user.id,
            access_token_enc=None, access_token_expires_at=None,
        ))
        fake_connector = _FakeConnector(refresh_raises_reauth=True)
        with mock.patch.object(mailbox_managers_mod, "get_connector", return_value=fake_connector):
            IrisMailboxManager()._sync_connection(connection_id)

        with UnitOfWork() as uow:
            conn = IrisMailboxConnectionRepository(uow).get_by_id(connection_id)
            assert conn.status == "reauth_required"
            assert conn.last_error


def test_sync_connection_reuses_cached_unexpired_access_token(app, regular_user):
    with app.app_context():
        connection_id = _save(app, _connection(
            regular_user.id,
            access_token_enc=encrypt_at_rest("cached-access-token", purpose="iris_mailbox"),
            access_token_expires_at=utcnow_naive() + timedelta(minutes=30),
            sync_cursor="cursor-0",
        ))

        captured_tokens = []

        class _CapturingConnector(_FakeConnector):
            def list_new(self, access_token, cursor):
                captured_tokens.append(access_token)
                return super().list_new(access_token, cursor)

        with mock.patch.object(mailbox_managers_mod, "get_connector", return_value=_CapturingConnector()):
            IrisMailboxManager()._sync_connection(connection_id)

        assert captured_tokens == ["cached-access-token"]


def test_sync_connection_skips_paused_connection(app, regular_user):
    with app.app_context():
        connection_id = _save(app, _connection(regular_user.id, status="paused"))
        with mock.patch.object(mailbox_managers_mod, "get_connector") as get_connector:
            IrisMailboxManager()._sync_connection(connection_id)
        get_connector.assert_not_called()


def test_trigger_sync_submits_task_with_correct_category(app, regular_user):
    with app.app_context():
        connection_id = _save(app, _connection(regular_user.id))
        fake_queue = _FakeTaskQueue()
        IrisMailboxManager(task_queue=fake_queue).trigger_sync(connection_id, regular_user.id)

    assert len(fake_queue.submitted) == 1
    assert fake_queue.submitted[0]["category"] == "iris.ingest"
    assert fake_queue.submitted[0]["args"] == (connection_id,)
