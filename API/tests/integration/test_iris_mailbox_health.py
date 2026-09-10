"""Salud y observabilidad de una conexión de buzón.

Antes, ``last_sync_at`` se actualizaba igual tanto si el sync no encontraba
nada nuevo como si dejaba mensajes atascados por una cuota agotada o un
fallo transitorio -- un administrador no podía distinguir "todo tranquilo"
de "Iris está atascado" sin mirar los logs del servidor. Estos tests fijan
justo esa distinción: ``last_success_at`` solo avanza cuando la cola de
checkpoint (``IrisMailboxInbox``) queda vacía, y los recuentos en vivo
(pendientes/reintentando/``dead``/aceptados) dan el resto del cuadro sin
necesidad de logs.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest import mock

import pytest

import src.modules.system.config_reading as CR
import src.modules.features.iris.managers.analysis as analysis_managers_mod
import src.modules.features.iris.managers.mailbox as mailbox_managers_mod
import src.modules.features.iris.services.mailbox.locks as mailbox_locks_mod
from src.modules.features.iris.exceptions import IrisMailboxConnectionNotFoundError
from src.modules.features.iris.managers.mailbox import IrisMailboxManager
from src.modules.features.iris.model import IrisAnalysis, IrisMailboxConnection, IrisMailboxInbox
from src.modules.features.iris.repositories import (
    IrisAnalysisRepository, IrisMailboxConnectionRepository, IrisMailboxInboxRepository,
)
from src.modules.features.iris.services.mailbox.base import MessageRef, TokenSet
from src.modules.infrastructure import UnitOfWork
from src.modules.shared import encrypt_at_rest

pytestmark = pytest.mark.integration


class _FakeLockRedis:
    """Doble en memoria de RedisConnectionFactory.decoded() para
    MailboxSyncLock: SET NX EX más el script Lua de liberación
    condicionada al token del titular -- ver test_iris_mailbox_manager.py,
    de donde se copia este doble, ya que _sync_connection adquiere el lock
    siempre."""

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


class _FakeLockRedisFactory:
    def __init__(self):
        self.redis = _FakeLockRedis()

    def decoded(self):
        return self.redis


@pytest.fixture(autouse=True)
def _fake_lock_redis():
    """Sin este doble, cada _sync_connection() intentaría adquirir el lock
    de MailboxSyncLock contra un Redis real, que la suite bloquea a
    propósito (ver conftest.py)."""
    with mock.patch.object(mailbox_locks_mod, "RedisConnectionFactory", _FakeLockRedisFactory()):
        yield


class _FakeTaskQueue:
    def submit(self, **kwargs):
        pass


class _FakeConnector:
    """Doble de MailboxConnector: lista un lote fijo de mensajes y puede
    fallar la ingesta de ids concretos un número de veces controlado."""

    def __init__(self, refs=None, cursor_after="cursor-2", fail_times=None):
        self._refs = refs if refs is not None else []
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

    def fetch_raw(self, access_token, message_ref):
        raise NotImplementedError

    def refresh(self, refresh_token):
        return TokenSet(
            refresh_token=refresh_token, access_token="access-token",
            access_token_expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            scopes="gmail.metadata", account_email="victim@example.com",
        )


def _connection(user_id, **overrides) -> IrisMailboxConnection:
    defaults = dict(
        user_id=user_id, provider="gmail", account_email="victim@example.com",
        scopes="gmail.metadata", refresh_token="refresh-token",
        status="active", sync_cursor="cursor-0",
    )
    defaults.update(overrides)
    return IrisMailboxConnection(**defaults)


def _save(app, connection: IrisMailboxConnection) -> int:
    with app.app_context():
        with UnitOfWork() as uow:
            IrisMailboxConnectionRepository(uow).save(connection)
            return connection.id


def _reload(app, connection_id) -> IrisMailboxConnection:
    with app.app_context():
        with UnitOfWork() as uow:
            return IrisMailboxConnectionRepository(uow).get_by_id(connection_id)


def _sync(app, connector, connection_id):
    with app.app_context():
        with mock.patch.object(mailbox_managers_mod, "get_connector", return_value=connector), \
             mock.patch.object(analysis_managers_mod.TaskQueue, "get_instance", return_value=_FakeTaskQueue()):
            IrisMailboxManager()._sync_connection(connection_id)


def _health(app, connection_id, user_id) -> dict:
    with app.app_context():
        return IrisMailboxManager().get_connection_health(connection_id, user_id)


# ------------------------------------------------------- repositorio: recuentos en vivo

def test_count_pending_and_dead_reflect_the_real_table(app, regular_user):
    connection_id = _save(app, _connection(regular_user.id))
    with app.app_context():
        with UnitOfWork() as uow:
            repo = IrisMailboxInboxRepository(uow)
            repo.save(IrisMailboxInbox(connection_id=connection_id, provider_message_id="msg-1"))
            repo.save(IrisMailboxInbox(
                connection_id=connection_id, provider_message_id="msg-2", attempts=2,
            ))
            repo.save(IrisMailboxInbox(
                connection_id=connection_id, provider_message_id="msg-3", status="dead", attempts=5,
            ))

        with UnitOfWork() as uow:
            repo = IrisMailboxInboxRepository(uow)
            assert repo.count_pending(connection_id) == 2
            assert repo.count_retrying(connection_id) == 1  # solo msg-2 (pending, attempts>=1)
            assert repo.count_dead(connection_id) == 1


def test_oldest_pending_created_at_picks_the_earliest_row(app, regular_user):
    connection_id = _save(app, _connection(regular_user.id))
    with app.app_context():
        with UnitOfWork() as uow:
            repo = IrisMailboxInboxRepository(uow)
            repo.save(IrisMailboxInbox(connection_id=connection_id, provider_message_id="msg-1"))
            first_id = repo.get_pending(connection_id)[0].id
            repo.save(IrisMailboxInbox(connection_id=connection_id, provider_message_id="msg-2"))

        with UnitOfWork() as uow:
            repo = IrisMailboxInboxRepository(uow)
            oldest = repo.oldest_pending_created_at(connection_id)
            first_entry = repo.get_by_id(first_id)
            assert oldest == first_entry.created_at


def test_oldest_pending_created_at_is_none_without_pending_rows(app, regular_user):
    connection_id = _save(app, _connection(regular_user.id))
    with app.app_context():
        with UnitOfWork() as uow:
            assert IrisMailboxInboxRepository(uow).oldest_pending_created_at(connection_id) is None


def test_count_by_connection_counts_accepted_analyses(app, regular_user):
    connection_id = _save(app, _connection(regular_user.id))
    with app.app_context():
        with UnitOfWork() as uow:
            repo = IrisAnalysisRepository(uow)
            repo.save(IrisAnalysis(
                raw_headers="From: a@b.com", user_id=regular_user.id,
                connection_id=connection_id, source_message_uid="msg-1",
            ))
            repo.save(IrisAnalysis(
                raw_headers="From: a@b.com", user_id=regular_user.id,
                connection_id=connection_id, source_message_uid="msg-2",
            ))

        with UnitOfWork() as uow:
            assert IrisAnalysisRepository(uow).count_by_connection(connection_id) == 2


# --------------------------------------------- distinguir "tranquilo" de "atascado"

def test_a_clean_sync_advances_last_success_and_leaves_no_pending(app, regular_user):
    connection_id = _save(app, _connection(regular_user.id))

    _sync(app, _FakeConnector(refs=[]), connection_id)

    reloaded = _reload(app, connection_id)
    assert reloaded.last_sync_at is not None
    assert reloaded.last_success_at is not None
    assert reloaded.last_sync_duration_ms is not None

    health = _health(app, connection_id, regular_user.id)
    assert health["messages_pending"] == 0
    assert health["last_success_at"] == reloaded.last_success_at


def test_a_sync_stuck_on_quota_advances_last_sync_but_not_last_success(app, regular_user, monkeypatch):
    """El escenario del issue: el sync corre y no revienta, pero dejó un
    mensaje sin ingerir por cuota agotada -- eso NO es "todo tranquilo"."""
    monkeypatch.setattr(
        mailbox_managers_mod.CR, "iris_config",
        lambda: CR.IrisConfig(max_ingested_per_day=0),
    )
    connection_id = _save(app, _connection(regular_user.id))

    _sync(app, _FakeConnector(refs=[MessageRef(provider_message_id="msg-1")]), connection_id)

    reloaded = _reload(app, connection_id)
    assert reloaded.last_sync_at is not None
    assert reloaded.last_success_at is None  # nunca ha terminado limpio
    assert reloaded.sync_cursor == "cursor-0"  # sin confirmar -- queda pendiente

    health = _health(app, connection_id, regular_user.id)
    assert health["messages_pending"] == 1
    assert health["messages_discovered_total"] == 1
    assert health["messages_accepted_total"] == 0


def test_a_later_clean_sync_finally_sets_last_success_after_being_stuck(app, regular_user, monkeypatch):
    """Una vez se libera la cuota y la cola se vacía, last_success_at pasa
    a reflejar ese momento -- no se queda huérfano por el sync atascado."""
    monkeypatch.setattr(
        mailbox_managers_mod.CR, "iris_config",
        lambda: CR.IrisConfig(max_ingested_per_day=0),
    )
    connection_id = _save(app, _connection(regular_user.id))
    connector = _FakeConnector(refs=[MessageRef(provider_message_id="msg-1")])
    _sync(app, connector, connection_id)
    assert _reload(app, connection_id).last_success_at is None

    monkeypatch.setattr(
        mailbox_managers_mod.CR, "iris_config",
        lambda: CR.IrisConfig(max_ingested_per_day=10),
    )
    _sync(app, connector, connection_id)

    reloaded = _reload(app, connection_id)
    assert reloaded.last_success_at is not None
    assert reloaded.sync_cursor == "cursor-2"

    health = _health(app, connection_id, regular_user.id)
    assert health["messages_pending"] == 0
    assert health["messages_accepted_total"] == 1


def test_messages_discovered_total_accumulates_across_syncs(app, regular_user):
    connection_id = _save(app, _connection(regular_user.id))

    _sync(app, _FakeConnector(refs=[MessageRef(provider_message_id="msg-1")]), connection_id)
    assert _reload(app, connection_id).messages_discovered_total == 1

    connector = _FakeConnector(
        refs=[MessageRef(provider_message_id="msg-2"), MessageRef(provider_message_id="msg-3")],
        cursor_after="cursor-3",
    )
    _sync(app, connector, connection_id)
    assert _reload(app, connection_id).messages_discovered_total == 3


def test_a_dead_lettered_message_shows_up_as_dead_not_pending(app, regular_user, monkeypatch):
    monkeypatch.setattr(
        mailbox_managers_mod.CR, "iris_config",
        lambda: CR.IrisConfig(max_inbox_attempts=1),
    )
    connection_id = _save(app, _connection(regular_user.id))
    connector = _FakeConnector(
        refs=[MessageRef(provider_message_id="msg-broken")], fail_times={"msg-broken": 999},
    )

    _sync(app, connector, connection_id)

    health = _health(app, connection_id, regular_user.id)
    assert health["messages_pending"] == 0
    assert health["messages_dead"] == 1
    # Con la cola sin pendientes (el dead-letter ya no bloquea), el cursor sí
    # se confirma y el sync cuenta como "limpio".
    assert health["last_success_at"] is not None


def test_sync_error_records_duration_without_a_success_timestamp(app, regular_user):
    connection_id = _save(app, _connection(regular_user.id))

    class _BrokenConnector(_FakeConnector):
        def list_new(self, access_token, cursor):
            if cursor is None:
                return [], "cursor-1"
            raise RuntimeError("el proveedor no responde")

    _sync(app, _BrokenConnector(), connection_id)

    reloaded = _reload(app, connection_id)
    assert reloaded.last_error is not None
    assert reloaded.last_success_at is None
    assert reloaded.last_sync_duration_ms is not None


# ---------------------------------------------------------------- get_connection_health()

def test_get_connection_health_requires_ownership(app, regular_user, admin_user):
    connection_id = _save(app, _connection(admin_user.id))
    with pytest.raises(IrisMailboxConnectionNotFoundError):
        _health(app, connection_id, regular_user.id)


def test_get_connection_health_reports_cursor_established(app, regular_user):
    connection_id = _save(app, _connection(regular_user.id, sync_cursor=None))
    assert _health(app, connection_id, regular_user.id)["cursor_established"] is False

    _save(app, _connection(regular_user.id, account_email="b@gmail.com", sync_cursor="abc"))
    other_id = _save(app, _connection(regular_user.id, account_email="c@gmail.com", sync_cursor="abc"))
    assert _health(app, other_id, regular_user.id)["cursor_established"] is True
