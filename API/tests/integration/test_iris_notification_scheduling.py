"""Tests de integración del chequeo periódico de notificaciones de Iris
(M08): digests diarios pendientes y avisos de conexión atascada.

Cubre las dos consultas nuevas de ``repositories.py`` (``get_due_for_digest``,
``get_newly_stuck_connections``) y ``services/notifications/scheduling.py``,
que las usa para encolar los jobs correspondientes -- ver
``test_iris_notifications.py`` para el contenido de esos jobs una vez
encolados, y ``test_iris_mailbox_scheduling.py`` para cómo se engancha este
chequeo al scheduler de buzones de Iris.
"""

from __future__ import annotations

from datetime import timedelta
from unittest import mock

import pytest

import src.modules.features.iris.services.notifications.scheduling as scheduling_mod
from src.modules.features.iris.model import IrisMailboxConnection, IrisNotificationPreference
from src.modules.features.iris.repositories import (
    IrisMailboxConnectionRepository, IrisNotificationPreferenceRepository,
)
from src.modules.infrastructure import UnitOfWork
from src.modules.shared import encrypt_at_rest, utcnow_naive

pytestmark = pytest.mark.integration


def _save_connection(app, user_id: int, **overrides) -> int:
    defaults = dict(
        user_id=user_id, provider="gmail", account_email="victim@example.com",
        scopes="gmail.metadata",
        refresh_token_enc=encrypt_at_rest("token", purpose="iris_mailbox"),
        status="active",
    )
    defaults.update(overrides)
    with app.app_context():
        with UnitOfWork() as uow:
            connection = IrisMailboxConnection(**defaults)
            IrisMailboxConnectionRepository(uow).save(connection)
            return connection.id


def _reload_connection(app, connection_id: int) -> IrisMailboxConnection:
    with app.app_context():
        with UnitOfWork() as uow:
            return IrisMailboxConnectionRepository(uow).get_by_id(connection_id)


def _save_preference(app, user_id: int, **overrides) -> None:
    with app.app_context():
        with UnitOfWork() as uow:
            IrisNotificationPreferenceRepository(uow).save(
                IrisNotificationPreference(user_id=user_id, **overrides)
            )


# --------------------------------------------------------- repository: digest

def test_get_due_for_digest_includes_never_sent(app, regular_user):
    _save_preference(app, regular_user.id, digest_enabled=True)

    with app.app_context():
        with UnitOfWork() as uow:
            due = IrisNotificationPreferenceRepository(uow).get_due_for_digest(24)

    assert [p.user_id for p in due] == [regular_user.id]


def test_get_due_for_digest_excludes_recently_sent(app, regular_user):
    _save_preference(app, regular_user.id, digest_enabled=True,
                     digest_last_sent_at=utcnow_naive() - timedelta(hours=1))

    with app.app_context():
        with UnitOfWork() as uow:
            due = IrisNotificationPreferenceRepository(uow).get_due_for_digest(24)

    assert due == []


def test_get_due_for_digest_includes_stale_digest(app, regular_user):
    _save_preference(app, regular_user.id, digest_enabled=True,
                     digest_last_sent_at=utcnow_naive() - timedelta(hours=25))

    with app.app_context():
        with UnitOfWork() as uow:
            due = IrisNotificationPreferenceRepository(uow).get_due_for_digest(24)

    assert [p.user_id for p in due] == [regular_user.id]


def test_get_due_for_digest_excludes_disabled(app, regular_user):
    _save_preference(app, regular_user.id, digest_enabled=False)

    with app.app_context():
        with UnitOfWork() as uow:
            due = IrisNotificationPreferenceRepository(uow).get_due_for_digest(24)

    assert due == []


# --------------------------------------------------- repository: stuck connections

def test_get_newly_stuck_connections_flags_a_stale_success(app, regular_user):
    connection_id = _save_connection(
        app, regular_user.id, last_sync_at=utcnow_naive(),
        last_success_at=utcnow_naive() - timedelta(minutes=200),
    )

    with app.app_context():
        with UnitOfWork() as uow:
            stuck = IrisMailboxConnectionRepository(uow).get_newly_stuck_connections(180)

    assert [c.id for c in stuck] == [connection_id]


def test_get_newly_stuck_connections_ignores_a_recent_success(app, regular_user):
    _save_connection(
        app, regular_user.id, last_sync_at=utcnow_naive(),
        last_success_at=utcnow_naive() - timedelta(minutes=10),
    )

    with app.app_context():
        with UnitOfWork() as uow:
            stuck = IrisMailboxConnectionRepository(uow).get_newly_stuck_connections(180)

    assert stuck == []


def test_get_newly_stuck_connections_ignores_a_brand_new_connection(app, regular_user):
    """Nunca ha tenido un sync limpio, pero se acaba de crear -- no está
    atascada, solo no ha tenido tiempo de intentarlo (ver el umbral contra
    created_at en vez de contra un last_success_at inexistente)."""
    _save_connection(app, regular_user.id, last_sync_at=utcnow_naive(), last_success_at=None)

    with app.app_context():
        with UnitOfWork() as uow:
            stuck = IrisMailboxConnectionRepository(uow).get_newly_stuck_connections(180)

    assert stuck == []


def test_get_newly_stuck_connections_flags_an_old_connection_that_never_succeeded(app, regular_user):
    connection_id = _save_connection(
        app, regular_user.id, last_sync_at=utcnow_naive(), last_success_at=None,
        created_at=utcnow_naive() - timedelta(minutes=200),
    )

    with app.app_context():
        with UnitOfWork() as uow:
            stuck = IrisMailboxConnectionRepository(uow).get_newly_stuck_connections(180)

    assert [c.id for c in stuck] == [connection_id]


def test_get_newly_stuck_connections_ignores_one_never_synced(app, regular_user):
    """last_sync_at nulo significa "aún no ha tenido su primer sondeo",
    distinto de "atascada"."""
    _save_connection(
        app, regular_user.id, last_sync_at=None, last_success_at=None,
        created_at=utcnow_naive() - timedelta(minutes=200),
    )

    with app.app_context():
        with UnitOfWork() as uow:
            stuck = IrisMailboxConnectionRepository(uow).get_newly_stuck_connections(180)

    assert stuck == []


def test_get_newly_stuck_connections_ignores_one_already_alerted(app, regular_user):
    _save_connection(
        app, regular_user.id, last_sync_at=utcnow_naive(),
        last_success_at=utcnow_naive() - timedelta(minutes=200),
        stuck_alert_sent_at=utcnow_naive(),
    )

    with app.app_context():
        with UnitOfWork() as uow:
            stuck = IrisMailboxConnectionRepository(uow).get_newly_stuck_connections(180)

    assert stuck == []


def test_get_newly_stuck_connections_ignores_inactive_connections(app, regular_user):
    _save_connection(
        app, regular_user.id, status="paused", last_sync_at=utcnow_naive(),
        last_success_at=utcnow_naive() - timedelta(minutes=200),
    )

    with app.app_context():
        with UnitOfWork() as uow:
            stuck = IrisMailboxConnectionRepository(uow).get_newly_stuck_connections(180)

    assert stuck == []


# ------------------------------------------------------------- check_and_notify

def test_send_due_digests_enqueues_one_job_per_due_user(app, regular_user, admin_user):
    _save_preference(app, regular_user.id, digest_enabled=True)
    _save_preference(app, admin_user.id, digest_enabled=False)

    with mock.patch.object(scheduling_mod, "IrisDigestNotifyManager") as fake_digest:
        with app.app_context():
            scheduling_mod._send_due_digests()

    fake_digest.enqueue_for.assert_called_once_with(regular_user.id)


def test_notify_stuck_connections_marks_before_enqueuing(app, regular_user):
    connection_id = _save_connection(
        app, regular_user.id, last_sync_at=utcnow_naive(),
        last_success_at=utcnow_naive() - timedelta(minutes=200),
    )

    with mock.patch.object(scheduling_mod, "IrisStuckSyncNotifyManager") as fake_stuck:
        with app.app_context():
            scheduling_mod._notify_stuck_connections()

    fake_stuck.enqueue_for.assert_called_once_with(connection_id)
    assert _reload_connection(app, connection_id).stuck_alert_sent_at is not None


def test_notify_stuck_connections_does_not_reenqueue_next_pass(app, regular_user):
    _save_connection(
        app, regular_user.id, last_sync_at=utcnow_naive(),
        last_success_at=utcnow_naive() - timedelta(minutes=200),
    )

    with app.app_context():
        with mock.patch.object(scheduling_mod, "IrisStuckSyncNotifyManager") as fake_stuck:
            scheduling_mod._notify_stuck_connections()
            scheduling_mod._notify_stuck_connections()

    assert fake_stuck.enqueue_for.call_count == 1
