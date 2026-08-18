"""Tests de integración de IrisPhishingNotifyManager: el correo de alerta
cuando la ingesta automática de buzón clasifica un correo como Phishing.

Cubre el contrato del aviso: solo análisis de buzón con veredicto Phishing
notifican (los manuales los pidió el propio usuario, que ya ve el informe),
el correo va al dueño del análisis y su contenido incluye el asunto — el
mismo que ahora se usa como título del análisis.
"""

from __future__ import annotations

from unittest import mock

import pytest

import src.modules.features.iris.managers.notifications as notifications_mod
from src.modules.features.iris.managers import IrisManager
from src.modules.features.iris.managers.notifications import IrisPhishingNotifyManager
from src.modules.features.iris.model import IrisAnalysis, IrisMailboxConnection
from src.modules.features.iris.repositories import IrisAnalysisRepository, IrisMailboxConnectionRepository
from src.modules.infrastructure import UnitOfWork
from src.modules.shared import encrypt_at_rest

pytestmark = pytest.mark.integration


class _FakeTaskQueue:
    def __init__(self):
        self.submitted = []

    def submit(self, **kwargs):
        self.submitted.append(kwargs)


def _save_connection(app, user_id: int) -> int:
    with app.app_context():
        with UnitOfWork() as uow:
            connection = IrisMailboxConnection(
                user_id=user_id, provider="gmail", account_email="victim@example.com",
                scopes="gmail.metadata",
                refresh_token_enc=encrypt_at_rest("token", purpose="iris_mailbox"),
                status="active",
            )
            IrisMailboxConnectionRepository(uow).save(connection)
            return connection.id


def _save_analysis(app, user_id: int, *, verdict: str, connection_id=None, title="Tu factura",
                   total_score=10.0) -> int:
    with app.app_context():
        with UnitOfWork() as uow:
            analysis = IrisAnalysis(
                raw_headers="From: attacker@evil.tk\nSubject: Tu factura\n",
                user_id=user_id, status="finished", verdict=verdict,
                total_score=total_score, title=title, connection_id=connection_id,
            )
            IrisAnalysisRepository(uow).save(analysis)
            return analysis.id


# ------------------------------------------------------------------- enqueue

def test_enqueue_for_submits_job_with_iris_notify_category(app):
    fake_queue = _FakeTaskQueue()
    with mock.patch.object(notifications_mod.TaskQueue, "get_instance", return_value=fake_queue):
        IrisPhishingNotifyManager.enqueue_for(42)

    assert len(fake_queue.submitted) == 1
    job = fake_queue.submitted[0]
    assert job["category"] == "iris.notify"
    assert job["args"] == (42,)
    assert job["external_id"] == "iris-phishing-notify:42"
    assert job["func"] is IrisPhishingNotifyManager.execute_notify_phishing


# --------------------------------------------------------------- _run_notify

def test_run_notify_sends_email_to_owner_of_mailbox_phishing(app, regular_user):
    connection_id = _save_connection(app, regular_user.id)
    analysis_id = _save_analysis(app, regular_user.id, verdict="Phishing",
                                 connection_id=connection_id, title="Tu factura")

    mailer = mock.Mock()
    with mock.patch.object(notifications_mod, "build_mailer", return_value=mailer):
        with app.app_context():
            IrisPhishingNotifyManager._run_notify(analysis_id)

    assert mailer.send.call_count == 1
    message = mailer.send.call_args.args[0]
    assert message.to == f"user{regular_user.id}@ellysia.test"
    assert message.subject == "[Iris] Ten cuidado con el correo: Tu factura"
    assert "Tu factura" in message.html_body
    assert "Tu factura" in message.text_body
    assert "#" + str(analysis_id) in message.html_body


def test_run_notify_skips_manual_analysis(app, regular_user):
    analysis_id = _save_analysis(app, regular_user.id, verdict="Phishing", connection_id=None)

    mailer = mock.Mock()
    with mock.patch.object(notifications_mod, "build_mailer", return_value=mailer):
        with app.app_context():
            IrisPhishingNotifyManager._run_notify(analysis_id)

    mailer.send.assert_not_called()


def test_run_notify_skips_non_phishing_verdict(app, regular_user):
    connection_id = _save_connection(app, regular_user.id)
    analysis_id = _save_analysis(app, regular_user.id, verdict="Suspicious",
                                 connection_id=connection_id)

    mailer = mock.Mock()
    with mock.patch.object(notifications_mod, "build_mailer", return_value=mailer):
        with app.app_context():
            IrisPhishingNotifyManager._run_notify(analysis_id)

    mailer.send.assert_not_called()


def test_run_notify_tolerates_missing_user_and_analysis(app):
    mailer = mock.Mock()
    with mock.patch.object(notifications_mod, "build_mailer", return_value=mailer):
        with app.app_context():
            IrisPhishingNotifyManager._run_notify(999999)
            IrisPhishingNotifyManager._run_notify(_save_analysis(app, 999999, verdict="Phishing",
                                                                  connection_id=1, title="Sin dueño real"))

    mailer.send.assert_not_called()


# --------------------------------------------------- disparo desde IrisManager

def test_phishing_trigger_enqueues_only_for_mailbox_analyses(app, regular_user):
    connection_id = _save_connection(app, regular_user.id)
    mailbox_id = _save_analysis(app, regular_user.id, verdict="Phishing", connection_id=connection_id)
    manual_id = _save_analysis(app, regular_user.id, verdict="Phishing", connection_id=None)
    suspicious_id = _save_analysis(app, regular_user.id, verdict="Suspicious", connection_id=connection_id)

    fake_queue = _FakeTaskQueue()
    with mock.patch.object(notifications_mod.TaskQueue, "get_instance", return_value=fake_queue):
        with app.app_context():
            IrisManager()._enqueue_phishing_notification(mailbox_id, "Phishing")
            IrisManager()._enqueue_phishing_notification(manual_id, "Phishing")
            IrisManager()._enqueue_phishing_notification(suspicious_id, "Suspicious")
            IrisManager()._enqueue_phishing_notification(mailbox_id, "Legitimate")

    assert [job["args"] for job in fake_queue.submitted] == [(mailbox_id,)]


def test_phishing_trigger_never_raises_when_queue_is_down(app, regular_user):
    """Un fallo de Redis al encolar no debe tumbar el análisis ya finalizado."""
    connection_id = _save_connection(app, regular_user.id)
    analysis_id = _save_analysis(app, regular_user.id, verdict="Phishing", connection_id=connection_id)

    class _BrokenQueue:
        def submit(self, **kwargs):
            raise RuntimeError("redis is down")

    with mock.patch.object(notifications_mod.TaskQueue, "get_instance", return_value=_BrokenQueue()):
        with app.app_context():
            IrisManager()._enqueue_phishing_notification(analysis_id, "Phishing")

        with UnitOfWork() as uow:
            analysis = IrisAnalysisRepository(uow).get_by_id(analysis_id)
            assert analysis is not None
            assert analysis.status == "finished"
