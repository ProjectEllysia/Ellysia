"""Tests de integración de IrisMailboxScheduler -- sondeo periódico de
conexiones de buzón y (M08) chequeo periódico de notificaciones."""

from __future__ import annotations

from unittest import mock

import pytest

import src.modules.features.iris.services.mailbox.scheduling as scheduling_mod
from src.modules.features.iris.managers.mailbox import IrisMailboxManager
from src.modules.features.iris.model import IrisMailboxConnection
from src.modules.features.iris.repositories import IrisMailboxConnectionRepository
from src.modules.features.iris.services.mailbox.scheduling import IrisMailboxScheduler
from src.modules.infrastructure import UnitOfWork
from src.modules.shared import encrypt_at_rest

pytestmark = pytest.mark.integration


def _connection(user_id: int, account_email: str) -> IrisMailboxConnection:
    return IrisMailboxConnection(
        user_id=user_id, provider="gmail", account_email=account_email,
        scopes="gmail.metadata",
        refresh_token="token",
        status="active",
    )


def test_poll_connections_continues_after_one_connection_fails_to_enqueue(app, regular_user, admin_user):
    """B02: ``submit_sync()`` puede levantar (p.ej. ya hay un job "started"
    con el mismo job_id determinista para esa conexión) -- eso no debe
    impedir que el resto de conexiones vencidas se encolen en el mismo
    sondeo. Antes de este fix, una excepción a mitad del bucle abortaba el
    resto silenciosamente (solo quedaba en el log del ``scheduler_job``
    exterior)."""
    with app.app_context():
        with UnitOfWork() as uow:
            repo = IrisMailboxConnectionRepository(uow)
            repo.save(_connection(regular_user.id, "a@gmail.com"))
            repo.save(_connection(admin_user.id, "b@gmail.com"))

        calls = []

        def _fake_submit_sync(self, connection_id):
            calls.append(connection_id)
            if len(calls) == 1:
                raise RuntimeError("ya hay una tarea en ejecución")

        with mock.patch.object(IrisMailboxManager, "submit_sync", _fake_submit_sync):
            IrisMailboxScheduler._poll_connections()

        assert len(calls) == 2


def test_run_notifications_delegates_to_check_and_notify(app):
    """El job de notificaciones (M08) es una costura fina -- toda la lógica
    vive en ``services/notifications/scheduling.check_and_notify``; aquí
    solo se comprueba que el scheduler la invoca."""
    with app.app_context():
        with mock.patch.object(scheduling_mod, "check_and_notify") as fake_check:
            IrisMailboxScheduler._run_notifications()

        fake_check.assert_called_once_with()


def test_run_retention_delegates_to_run_retention(app):
    """El job de retención (M09/B17/B19) es igual de fino -- toda la lógica
    vive en ``services/retention.run_retention``."""
    with app.app_context():
        with mock.patch.object(scheduling_mod, "run_retention") as fake_retention:
            IrisMailboxScheduler._run_retention()

        fake_retention.assert_called_once_with()
