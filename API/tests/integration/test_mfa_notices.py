"""Pruebas de los recordatorios periódicos para activar MFA."""

from datetime import timedelta
from unittest import mock

import pyotp
import pytest

from src.modules.infrastructure.unit_of_work import UnitOfWork
from src.modules.shared import utcnow_naive
from src.modules.tools.herald import SendResult
from src.modules.users.model import User
from src.modules.users.services.mfa_notices import send_mfa_reminders

pytestmark = pytest.mark.integration


def _enable_totp(client, headers):
    setup = client.post("/users/mfa/totp/setup", headers=headers).get_json()
    code = pyotp.TOTP(setup["secret"]).now()
    client.post("/users/mfa/totp/confirm", headers=headers, json={"code": code})


@pytest.fixture()
def mailer():
    value = mock.Mock()
    value.send.return_value = SendResult(ok=True)
    with mock.patch(
        "src.modules.users.services.mfa_notices.build_mailer",
        return_value=value,
    ):
        yield value


def test_sends_to_verified_user_without_mfa_and_records_timestamp(app, regular_user, mailer):
    with app.app_context():
        result = send_mfa_reminders()

        with UnitOfWork() as uow:
            user = uow.session.get(User, regular_user.id)
            sent_at = user.last_mfa_reminder_at

    assert result == {"sent": 1, "failed": 0}
    assert sent_at is not None
    assert mailer.send.call_args.args[0].to == f"user{regular_user.id}@ellysia.test"
    assert "#mfa" in mailer.send.call_args.args[0].html_body
    assert mailer.send.call_args.args[0].subject.startswith("Activa la autenticación")


def test_does_not_repeat_before_configured_interval(app, regular_user, mailer):
    with app.app_context():
        assert send_mfa_reminders() == {"sent": 1, "failed": 0}
        assert send_mfa_reminders() == {"sent": 0, "failed": 0}

    assert mailer.send.call_count == 1


def test_excludes_users_with_confirmed_mfa(client, app, regular_user, auth_headers, mailer):
    _enable_totp(client, auth_headers(regular_user))

    with app.app_context():
        result = send_mfa_reminders()

    assert result == {"sent": 0, "failed": 0}
    mailer.send.assert_not_called()


def test_excludes_unverified_users(app, make_user, mailer):
    make_user(unverified=True)

    with app.app_context():
        result = send_mfa_reminders()

    assert result == {"sent": 0, "failed": 0}
    mailer.send.assert_not_called()


def test_failed_delivery_does_not_mark_user_and_does_not_stop_batch(app, make_user):
    first = make_user()
    second = make_user()
    mailer = mock.Mock()
    mailer.send.side_effect = [RuntimeError("relay caído"), SendResult(ok=True)]

    with mock.patch(
        "src.modules.users.services.mfa_notices.build_mailer",
        return_value=mailer,
    ), app.app_context():
        result = send_mfa_reminders()

        with UnitOfWork() as uow:
            uow.session.expire_all()
            first_user = uow.session.get(User, first.id)
            second_user = uow.session.get(User, second.id)
            first_sent_at = first_user.last_mfa_reminder_at
            second_sent_at = second_user.last_mfa_reminder_at

    assert result == {"sent": 1, "failed": 1}
    assert first_sent_at is None
    assert second_sent_at is not None


def test_due_reminder_is_sent_again_after_interval(app, regular_user, mailer):
    with app.app_context():
        with UnitOfWork() as uow:
            user = uow.session.get(User, regular_user.id)
            user.last_mfa_reminder_at = utcnow_naive() - timedelta(days=31)

        result = send_mfa_reminders()

    assert result == {"sent": 1, "failed": 0}
    assert mailer.send.call_count == 1
