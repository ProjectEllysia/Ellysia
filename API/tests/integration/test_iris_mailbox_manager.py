"""Tests de integración de IrisMailboxManager: OAuth state, CRUD, cuotas,
idempotencia y sync — con los conectores mockeados (ya cubiertos por
test_iris_mailbox_connectors.py) y sin red real.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest import mock

import pytest
from itsdangerous import BadSignature

import src.modules.system.config_reading as CR
import src.modules.features.iris.managers.mailbox as mailbox_managers_mod
import src.modules.features.iris.services.mailbox.locks as mailbox_locks_mod
from src.modules.features.iris.exceptions import (
    IrisMailboxConnectionNotFoundError,
    IrisMailboxInvalidProviderError,
    IrisMailboxOAuthStateError,
    IrisMailboxQuotaExceededError,
)
import src.modules.features.iris.managers.analysis as analysis_managers_mod
from src.modules.features.iris.managers.mailbox import IrisMailboxManager
from src.modules.features.iris.model import IrisAnalysis, IrisMailboxConnection, IrisMailboxInbox
from src.modules.features.iris.repositories import (
    IrisAnalysisRepository, IrisMailboxConnectionRepository, IrisMailboxInboxRepository,
)
from src.modules.features.iris.services.mailbox.base import MessageRef, TokenSet
from src.modules.infrastructure import UnitOfWork
from src.modules.shared import decrypt_at_rest, encrypt_at_rest, utcnow_naive

pytestmark = pytest.mark.integration


class _FakeStateRedis:
    """Doble en memoria de RedisConnectionFactory.decoded() -- solo el
    subconjunto que _consume_state usa (SET NX EX)."""

    def __init__(self):
        self._keys: set[str] = set()

    def set(self, key, value, nx=False, ex=None):
        if nx and key in self._keys:
            return None
        self._keys.add(key)
        return True


class _FakeStateRedisFactory:
    """Doble de RedisConnectionFactory expuesto solo dentro del namespace de
    mailbox_managers -- parchear el classmethod real afectaría también a
    TaskQueue (usa la misma clase para su HistoryStore), que estos tests no
    dobla."""

    def __init__(self):
        self._redis = _FakeStateRedis()

    def decoded(self):
        return self._redis


@pytest.fixture(autouse=True)
def _fake_state_redis():
    """El consumo de state (single-use) usa Redis; los tests no levantan uno
    real (ver conftest.py, que solo mockea .ping()/.close() de create_app),
    así que se dobla aquí -- misma idea que _FakeTaskQueue de abajo."""
    with mock.patch.object(mailbox_managers_mod, "RedisConnectionFactory", _FakeStateRedisFactory()):
        yield


class _FakeLockRedis:
    """Doble en memoria de RedisConnectionFactory.decoded() para
    MailboxSyncLock (B02): SET NX EX más los dos scripts Lua de
    renovación/liberación condicionados al token del titular."""

    def __init__(self):
        self._values: dict[str, str] = {}

    def set(self, key, value, nx=False, ex=None):
        if nx and key in self._values:
            return None
        self._values[key] = value
        return True

    def eval(self, script, numkeys, key, token, *rest):
        if self._values.get(key) != token:
            return 0
        if "del(" in script or "\"del\"" in script:
            self._values.pop(key, None)
        return 1

    def expire_orphan(self, key):
        """Ayuda de test: simula que Redis expiró el lock por su cuenta."""
        self._values.pop(key, None)


class _FakeLockRedisFactory:
    def __init__(self):
        self.redis = _FakeLockRedis()

    def decoded(self):
        return self.redis


@pytest.fixture(autouse=True)
def _fake_lock_redis():
    """``MailboxSyncLock`` (B02) importa su propio ``RedisConnectionFactory``
    en el namespace de ``locks.py`` -- se dobla aquí para todos los tests de
    este fichero, ya que ``_sync_connection`` adquiere el lock siempre."""
    factory = _FakeLockRedisFactory()
    with mock.patch.object(mailbox_locks_mod, "RedisConnectionFactory", factory):
        yield factory


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


class _QueueTestConnector(_FakeConnector):
    """Doble para los tests de checkpoint (B01): lista un lote fijo de
    mensajes y puede fallar la ingesta de ids concretos un número de veces
    controlado antes de empezar a tener éxito -- simula un fallo transitorio
    (el mensaje se recupera) o uno permanente (nunca se agota el contador)."""

    def __init__(self, refs, cursor_after="cursor-2", fail_times=None):
        super().__init__()
        self._refs = refs
        self._cursor_after = cursor_after
        self._fail_times = dict(fail_times or {})
        self._attempts_used: dict[str, int] = {}

    def list_new(self, access_token, cursor):
        if cursor is None:
            return [], "cursor-1"
        return self._refs, self._cursor_after

    def fetch_headers(self, access_token, message_ref):
        remaining = self._fail_times.get(message_ref.provider_message_id, 0)
        used = self._attempts_used.get(message_ref.provider_message_id, 0)
        if used < remaining:
            self._attempts_used[message_ref.provider_message_id] = used + 1
            raise RuntimeError(f"fallo transitorio en {message_ref.provider_message_id}")
        return f"From: a@b.com\r\nSubject: {message_ref.provider_message_id}\r\n"


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
    monkeypatch.setattr(
        mailbox_managers_mod.CR, "iris_config",
        lambda: CR.IrisConfig(max_connections_per_user=1),
    )
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


def test_handle_callback_rejects_replayed_state(app, regular_user):
    """El state es de un solo uso: una segunda llamada con el mismo state
    (firma y TTL todavía válidos) debe rechazarse, no repetir el canje."""
    with app.app_context():
        state = IrisMailboxManager._sign_state(
            user_id=regular_user.id, provider="gmail", full_message_mode=False, folder=None,
        )
        with mock.patch.object(mailbox_managers_mod, "get_connector", return_value=_FakeConnector()):
            IrisMailboxManager().handle_callback(state, "auth-code")
            with pytest.raises(IrisMailboxOAuthStateError):
                IrisMailboxManager().handle_callback(state, "auth-code")


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


def test_delete_connection_with_associated_analyses_succeeds(app, regular_user):
    """El FK IrisAnalysis.connection_id lleva ondelete=SET NULL: borrar una
    conexión que ya tiene análisis asociados (el caso normal tras un sondeo)
    no debe fallar por integridad, y el histórico de análisis sobrevive con
    connection_id a NULL.
    """
    with app.app_context():
        connection_id = _save(app, _connection(regular_user.id))

        with UnitOfWork() as uow:
            analysis = IrisAnalysis(
                user_id=regular_user.id, raw_headers="From: a@b.com\r\nSubject: Hi\r\n",
                status="finished", connection_id=connection_id, source_message_uid="msg-1",
            )
            IrisAnalysisRepository(uow).save(analysis)
            analysis_id = analysis.id

        fake_connector = _FakeConnector()
        with mock.patch.object(mailbox_managers_mod, "get_connector", return_value=fake_connector):
            IrisMailboxManager().delete_connection(connection_id, regular_user.id)

        with UnitOfWork() as uow:
            assert IrisMailboxConnectionRepository(uow).get_by_id(connection_id) is None
            surviving = IrisAnalysisRepository(uow).get_by_id(analysis_id)
            assert surviving is not None
            assert surviving.connection_id is None


# ------------------------------------------------------------------- sync

def test_sync_connection_ingests_new_messages_and_advances_cursor(app, regular_user):
    with app.app_context():
        connection_id = _save(app, _connection(regular_user.id, sync_cursor="cursor-0"))

        fake_queue = _FakeTaskQueue()
        with mock.patch.object(mailbox_managers_mod, "get_connector", return_value=_FakeConnector()), \
             mock.patch.object(analysis_managers_mod.TaskQueue, "get_instance", return_value=fake_queue):
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
            # La ingesta automática usa el asunto del correo como título, no
            # el opaco "Auto (<cuenta>)".
            assert analyses[0].title == "Hi"


def test_sync_connection_uses_subject_as_title_in_full_message_mode(app, regular_user):
    with app.app_context():
        connection_id = _save(app, _connection(
            regular_user.id, sync_cursor="cursor-0", full_message_mode=True,
        ))

        fake_queue = _FakeTaskQueue()
        with mock.patch.object(mailbox_managers_mod, "get_connector", return_value=_FakeConnector()), \
             mock.patch.object(analysis_managers_mod.TaskQueue, "get_instance", return_value=fake_queue):
            IrisMailboxManager()._sync_connection(connection_id)

        with UnitOfWork() as uow:
            analyses = IrisAnalysisRepository(uow).get_by_user(regular_user.id)
            assert len(analyses) == 1
            assert analyses[0].title == "Hi"


def test_sync_connection_stops_at_daily_quota(app, regular_user, monkeypatch):
    monkeypatch.setattr(
        mailbox_managers_mod.CR, "iris_config",
        lambda: CR.IrisConfig(max_ingested_per_day=0),
    )
    with app.app_context():
        connection_id = _save(app, _connection(regular_user.id, sync_cursor="cursor-0"))

        with mock.patch.object(mailbox_managers_mod, "get_connector", return_value=_FakeConnector()):
            IrisMailboxManager()._sync_connection(connection_id)

        with UnitOfWork() as uow:
            assert IrisAnalysisRepository(uow).get_by_user(regular_user.id) == []

            # B01: la cuota agotada deja el mensaje en cola para el próximo
            # sondeo -- confirmar el cursor ahora lo perdería para siempre.
            conn = IrisMailboxConnectionRepository(uow).get_by_id(connection_id)
            assert conn.sync_cursor == "cursor-0"
            pending = IrisMailboxInboxRepository(uow).get_pending(connection_id)
            assert [entry.provider_message_id for entry in pending] == ["msg-1"]
            assert pending[0].attempts == 0


# --------------------------------------------------------- B01: checkpoint por mensaje

def test_sync_connection_defers_cursor_and_pending_message_when_quota_is_hit(app, regular_user, monkeypatch):
    with app.app_context():
        connection_id = _save(app, _connection(regular_user.id, sync_cursor="cursor-0"))
        refs = [MessageRef(provider_message_id="msg-1"), MessageRef(provider_message_id="msg-2")]
        connector = _QueueTestConnector(refs)

        fake_queue = _FakeTaskQueue()
        monkeypatch.setattr(
            mailbox_managers_mod.CR, "iris_config",
            lambda: CR.IrisConfig(max_ingested_per_day=1),
        )
        with mock.patch.object(mailbox_managers_mod, "get_connector", return_value=connector), \
             mock.patch.object(analysis_managers_mod.TaskQueue, "get_instance", return_value=fake_queue):
            IrisMailboxManager()._sync_connection(connection_id)

        with UnitOfWork() as uow:
            conn = IrisMailboxConnectionRepository(uow).get_by_id(connection_id)
            # msg-2 se quedó fuera por cuota: el cursor no se confirma.
            assert conn.sync_cursor == "cursor-0"
            assert conn.ingested_today == 1
            pending = IrisMailboxInboxRepository(uow).get_pending(connection_id)
            assert [entry.provider_message_id for entry in pending] == ["msg-2"]

        # Próximo sondeo con cuota libre: el proveedor vuelve a listar el
        # mismo lote (el cursor no avanzó) pero msg-1 nunca se duplica.
        monkeypatch.setattr(
            mailbox_managers_mod.CR, "iris_config",
            lambda: CR.IrisConfig(max_ingested_per_day=10),
        )
        with mock.patch.object(mailbox_managers_mod, "get_connector", return_value=connector), \
             mock.patch.object(analysis_managers_mod.TaskQueue, "get_instance", return_value=fake_queue):
            IrisMailboxManager()._sync_connection(connection_id)

        with UnitOfWork() as uow:
            conn = IrisMailboxConnectionRepository(uow).get_by_id(connection_id)
            assert conn.sync_cursor == "cursor-2"
            analyses = IrisAnalysisRepository(uow).get_by_user(regular_user.id)
            assert sorted(a.source_message_uid for a in analyses) == ["msg-1", "msg-2"]
            assert IrisMailboxInboxRepository(uow).get_pending(connection_id) == []


def test_sync_connection_retries_transient_failure_without_duplicating_prior_success(app, regular_user):
    with app.app_context():
        connection_id = _save(app, _connection(regular_user.id, sync_cursor="cursor-0"))
        refs = [MessageRef(provider_message_id="msg-1"), MessageRef(provider_message_id="msg-2")]
        connector = _QueueTestConnector(refs, fail_times={"msg-2": 1})

        fake_queue = _FakeTaskQueue()
        with mock.patch.object(mailbox_managers_mod, "get_connector", return_value=connector), \
             mock.patch.object(analysis_managers_mod.TaskQueue, "get_instance", return_value=fake_queue):
            IrisMailboxManager()._sync_connection(connection_id)

        with UnitOfWork() as uow:
            conn = IrisMailboxConnectionRepository(uow).get_by_id(connection_id)
            assert conn.sync_cursor == "cursor-0"
            analyses = IrisAnalysisRepository(uow).get_by_user(regular_user.id)
            assert [a.source_message_uid for a in analyses] == ["msg-1"]
            pending = IrisMailboxInboxRepository(uow).get_pending(connection_id)
            assert [entry.provider_message_id for entry in pending] == ["msg-2"]
            assert pending[0].attempts == 1
            assert "fallo transitorio" in pending[0].last_error

        # El proveedor todavía no ve el cursor avanzar, así que vuelve a
        # devolver ambos mensajes -- msg-2 ahora sí se ingiere (ya no falla)
        # y msg-1 (aceptado en el sondeo anterior) nunca se duplica.
        with mock.patch.object(mailbox_managers_mod, "get_connector", return_value=connector), \
             mock.patch.object(analysis_managers_mod.TaskQueue, "get_instance", return_value=fake_queue):
            IrisMailboxManager()._sync_connection(connection_id)

        with UnitOfWork() as uow:
            conn = IrisMailboxConnectionRepository(uow).get_by_id(connection_id)
            assert conn.sync_cursor == "cursor-2"
            analyses = IrisAnalysisRepository(uow).get_by_user(regular_user.id)
            assert sorted(a.source_message_uid for a in analyses) == ["msg-1", "msg-2"]
            assert IrisMailboxInboxRepository(uow).get_pending(connection_id) == []


def test_sync_connection_moves_permanently_failing_message_to_dead_after_max_attempts(app, regular_user, monkeypatch):
    monkeypatch.setattr(
        mailbox_managers_mod.CR, "iris_config",
        lambda: CR.IrisConfig(max_inbox_attempts=2),
    )
    with app.app_context():
        connection_id = _save(app, _connection(regular_user.id, sync_cursor="cursor-0"))
        connector = _QueueTestConnector(
            [MessageRef(provider_message_id="msg-broken")], fail_times={"msg-broken": 999},
        )

        with mock.patch.object(mailbox_managers_mod, "get_connector", return_value=connector):
            IrisMailboxManager()._sync_connection(connection_id)
            IrisMailboxManager()._sync_connection(connection_id)

        with UnitOfWork() as uow:
            conn = IrisMailboxConnectionRepository(uow).get_by_id(connection_id)
            # La entrada "dead" ya no bloquea el avance del cursor.
            assert conn.sync_cursor == "cursor-2"

            repo = IrisMailboxInboxRepository(uow)
            assert repo.get_pending(connection_id) == []
            entries = repo.get_all_by_field("connection_id", connection_id)
            assert len(entries) == 1
            assert entries[0].status == "dead"
            assert entries[0].attempts == 2
            assert "fallo transitorio" in entries[0].last_error
            assert IrisAnalysisRepository(uow).get_by_user(regular_user.id) == []


def test_sync_connection_resolves_inbox_entry_for_already_ingested_message(app, regular_user):
    """Simula un fallo entre el commit del análisis y el borrado de su
    entrada en el inbox (p.ej. el proceso muere justo ahí): el siguiente
    sondeo debe resolver la entrada sin duplicar el análisis ni tratarlo
    como un fallo real."""
    with app.app_context():
        connection_id = _save(app, _connection(regular_user.id, sync_cursor="cursor-0"))

        with UnitOfWork() as uow:
            IrisAnalysisRepository(uow).save(IrisAnalysis(
                raw_headers="From: a@b.com\r\nSubject: Hi\r\n", user_id=regular_user.id,
                status="finished", connection_id=connection_id, source_message_uid="msg-1",
            ))
            IrisMailboxInboxRepository(uow).save(
                IrisMailboxInbox(connection_id=connection_id, provider_message_id="msg-1")
            )

        connector = _QueueTestConnector([], cursor_after="cursor-2")
        with mock.patch.object(mailbox_managers_mod, "get_connector", return_value=connector):
            IrisMailboxManager()._sync_connection(connection_id)

        with UnitOfWork() as uow:
            assert IrisMailboxInboxRepository(uow).get_pending(connection_id) == []
            analyses = IrisAnalysisRepository(uow).get_by_user(regular_user.id)
            assert len(analyses) == 1
            conn = IrisMailboxConnectionRepository(uow).get_by_id(connection_id)
            assert conn.sync_cursor == "cursor-2"


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


# --------------------------------------------------------- B02: lock de sync

def test_sync_connection_is_a_no_op_when_lock_already_held(app, regular_user, _fake_lock_redis):
    with app.app_context():
        connection_id = _save(app, _connection(regular_user.id, sync_cursor="cursor-0"))
        # Simula que otro worker ya sostiene el lock de esta conexión.
        _fake_lock_redis.redis.set(f"iris:mailbox-sync:{connection_id}", "other-token", nx=True, ex=900)

        with mock.patch.object(mailbox_managers_mod, "get_connector") as get_connector:
            IrisMailboxManager()._sync_connection(connection_id)
        get_connector.assert_not_called()

        with UnitOfWork() as uow:
            conn = IrisMailboxConnectionRepository(uow).get_by_id(connection_id)
            assert conn.sync_cursor == "cursor-0"
            assert conn.sync_started_at is None


def test_sync_connection_recovers_from_an_orphaned_lock(app, regular_user, _fake_lock_redis):
    """Un lock huérfano (worker muerto a mitad de sync, sin liberar) se
    autorrecupera por TTL en vez de bloquear la conexión para siempre."""
    with app.app_context():
        connection_id = _save(app, _connection(regular_user.id, sync_cursor="cursor-0"))
        key = f"iris:mailbox-sync:{connection_id}"
        _fake_lock_redis.redis.set(key, "stale-token", nx=True, ex=900)
        _fake_lock_redis.redis.expire_orphan(key)  # Redis ya lo habría expirado solo

        fake_queue = _FakeTaskQueue()
        with mock.patch.object(mailbox_managers_mod, "get_connector", return_value=_FakeConnector()), \
             mock.patch.object(analysis_managers_mod.TaskQueue, "get_instance", return_value=fake_queue):
            IrisMailboxManager()._sync_connection(connection_id)

        with UnitOfWork() as uow:
            conn = IrisMailboxConnectionRepository(uow).get_by_id(connection_id)
            assert conn.sync_cursor == "cursor-2"


def test_sync_connection_releases_lock_even_when_token_refresh_fails(app, regular_user, _fake_lock_redis):
    with app.app_context():
        connection_id = _save(app, _connection(
            regular_user.id, access_token_enc=None, access_token_expires_at=None,
        ))
        fake_connector = _FakeConnector(refresh_raises_reauth=True)
        with mock.patch.object(mailbox_managers_mod, "get_connector", return_value=fake_connector):
            IrisMailboxManager()._sync_connection(connection_id)

        key = f"iris:mailbox-sync:{connection_id}"
        assert key not in _fake_lock_redis.redis._values

        with UnitOfWork() as uow:
            conn = IrisMailboxConnectionRepository(uow).get_by_id(connection_id)
            assert conn.sync_started_at is None


def test_sync_connection_marks_sync_started_during_and_clears_after(app, regular_user):
    with app.app_context():
        connection_id = _save(app, _connection(regular_user.id, sync_cursor="cursor-0"))
        captured = {}

        class _CapturingConnector(_FakeConnector):
            def fetch_headers(self, access_token, message_ref):
                with UnitOfWork() as uow:
                    conn = IrisMailboxConnectionRepository(uow).get_by_id(connection_id)
                    captured["sync_started_at"] = conn.sync_started_at
                    captured["sync_job_id"] = conn.sync_job_id
                return super().fetch_headers(access_token, message_ref)

        fake_queue = _FakeTaskQueue()
        with mock.patch.object(mailbox_managers_mod, "get_connector", return_value=_CapturingConnector()), \
             mock.patch.object(analysis_managers_mod.TaskQueue, "get_instance", return_value=fake_queue):
            IrisMailboxManager()._sync_connection(connection_id, job_id="job-123")

        assert captured["sync_started_at"] is not None
        assert captured["sync_job_id"] == "job-123"

        with UnitOfWork() as uow:
            conn = IrisMailboxConnectionRepository(uow).get_by_id(connection_id)
            assert conn.sync_started_at is None
            assert conn.sync_job_id is None


def test_execute_sync_connection_passes_the_current_job_id(app, regular_user):
    """``execute_sync_connection`` es el entry point real de TaskQueue --
    fuera de un worker RQ, ``job_context()`` no-opea y ``job.id`` es None."""
    with app.app_context():
        connection_id = _save(app, _connection(regular_user.id))
        with mock.patch.object(
            mailbox_managers_mod.IrisMailboxManager, "_sync_connection",
        ) as sync_connection:
            IrisMailboxManager.execute_sync_connection(connection_id)
        sync_connection.assert_called_once_with(connection_id, job_id=None)
