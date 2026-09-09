"""Tests de integración de las notificaciones de Iris: el correo de alerta
cuando la ingesta automática de buzón clasifica un correo como Phishing
(``IrisPhishingNotifyManager``), el digest diario que agrupa los que no
eran de alta confianza (``IrisDigestNotifyManager``), y los dos avisos
operativos de M08 -- reautenticación (``IrisReauthNotifyManager``) y
conexión atascada (``IrisStuckSyncNotifyManager``).

Cubre el contrato del aviso de phishing: solo análisis de buzón con
veredicto Phishing notifican (los manuales los pidió el propio usuario, que
ya ve el informe), el correo va al dueño del análisis y su contenido incluye
el asunto -- el mismo que ahora se usa como título del análisis. Y el de
M08: un veredicto de alta confianza (``total_score`` en o por debajo de
``iris.criticalPhishingScoreThreshold``, 20 por defecto) siempre notifica al
momento; uno por encima de ese umbral respeta el silenciado temporal y el
digest diario del usuario.
"""

from __future__ import annotations

from datetime import timedelta
from unittest import mock

import pytest

import src.modules.features.iris.managers.notifications as notifications_mod
from src.modules.features.iris.managers import IrisManager
from src.modules.features.iris.managers.notifications import (
    IrisDigestNotifyManager, IrisNotificationPreferenceManager,
    IrisPhishingNotifyManager, IrisReauthNotifyManager, IrisStuckSyncNotifyManager,
)
from src.modules.features.iris.model import IrisAnalysis, IrisMailboxConnection, IrisNotificationPreference
from src.modules.features.iris.repositories import (
    IrisAnalysisRepository, IrisMailboxConnectionRepository, IrisNotificationPreferenceRepository,
)
from src.modules.infrastructure import UnitOfWork
from src.modules.shared import encrypt_at_rest, utcnow_naive

pytestmark = pytest.mark.integration


class _FakeTaskQueue:
    def __init__(self):
        self.submitted = []

    def submit(self, **kwargs):
        self.submitted.append(kwargs)


def _save_connection(app, user_id: int, **overrides) -> int:
    defaults = dict(
        user_id=user_id, provider="gmail", account_email="victim@example.com",
        scopes="gmail.metadata",
        refresh_token="token",
        status="active",
    )
    defaults.update(overrides)
    with app.app_context():
        with UnitOfWork() as uow:
            connection = IrisMailboxConnection(**defaults)
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
                finished_at=utcnow_naive(),
            )
            IrisAnalysisRepository(uow).save(analysis)
            return analysis.id


def _save_preference(app, user_id: int, **overrides) -> None:
    with app.app_context():
        with UnitOfWork() as uow:
            IrisNotificationPreferenceRepository(uow).save(
                IrisNotificationPreference(user_id=user_id, **overrides)
            )


def _reload_preference(app, user_id: int) -> IrisNotificationPreference:
    with app.app_context():
        with UnitOfWork() as uow:
            return IrisNotificationPreferenceRepository(uow).get_by_user_id(user_id)


def _reload_connection(app, connection_id: int) -> IrisMailboxConnection:
    with app.app_context():
        with UnitOfWork() as uow:
            return IrisMailboxConnectionRepository(uow).get_by_id(connection_id)


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


# ===================================================================== M08
# Preferencias de notificación: silenciado, digest y los dos avisos operativos.

# ------------------------------------------- IrisNotificationPreferenceManager

def test_get_or_default_returns_defaults_without_persisting(app, regular_user):
    preference = IrisNotificationPreferenceManager.get_or_default(regular_user.id)

    assert preference.digest_enabled is False
    assert preference.muted_until is None
    assert preference.notify_reauth_required is True
    assert preference.notify_sync_stuck is True
    assert _reload_preference(app, regular_user.id) is None


def test_update_creates_the_row_on_first_touch(app, regular_user):
    with app.app_context():
        IrisNotificationPreferenceManager.update(regular_user.id, digest_enabled=True)

    reloaded = _reload_preference(app, regular_user.id)
    assert reloaded is not None
    assert reloaded.digest_enabled is True
    assert reloaded.notify_reauth_required is True  # sin tocar -- valor por defecto


def test_update_only_touches_fields_that_were_passed(app, regular_user):
    _save_preference(app, regular_user.id, digest_enabled=True, notify_sync_stuck=False)

    with app.app_context():
        IrisNotificationPreferenceManager.update(regular_user.id, notify_reauth_required=False)

    reloaded = _reload_preference(app, regular_user.id)
    assert reloaded.digest_enabled is True  # sin tocar
    assert reloaded.notify_sync_stuck is False  # sin tocar
    assert reloaded.notify_reauth_required is False  # el único cambio


def test_muted_for_minutes_sets_a_future_muted_until(app, regular_user):
    before = utcnow_naive()
    with app.app_context():
        IrisNotificationPreferenceManager.update(regular_user.id, muted_for_minutes=60)

    reloaded = _reload_preference(app, regular_user.id)
    assert reloaded.muted_until is not None
    assert reloaded.muted_until > before + timedelta(minutes=59)


def test_muted_for_minutes_zero_clears_an_active_mute(app, regular_user):
    _save_preference(app, regular_user.id, muted_until=utcnow_naive() + timedelta(hours=1))

    with app.app_context():
        IrisNotificationPreferenceManager.update(regular_user.id, muted_for_minutes=0)

    assert _reload_preference(app, regular_user.id).muted_until is None


# --------------------------------- IrisPhishingNotifyManager respeta M08

def test_critical_phishing_ignores_an_active_mute(app, regular_user):
    """total_score=10 está por debajo del umbral de alta confianza (20) --
    debe notificar de inmediato aunque el usuario esté silenciado."""
    connection_id = _save_connection(app, regular_user.id)
    analysis_id = _save_analysis(app, regular_user.id, verdict="Phishing",
                                 connection_id=connection_id, total_score=10.0)
    _save_preference(app, regular_user.id, muted_until=utcnow_naive() + timedelta(hours=1))

    mailer = mock.Mock()
    with mock.patch.object(notifications_mod, "build_mailer", return_value=mailer):
        with app.app_context():
            IrisPhishingNotifyManager._run_notify(analysis_id)

    mailer.send.assert_called_once()


def test_critical_phishing_ignores_digest_enabled(app, regular_user):
    connection_id = _save_connection(app, regular_user.id)
    analysis_id = _save_analysis(app, regular_user.id, verdict="Phishing",
                                 connection_id=connection_id, total_score=10.0)
    _save_preference(app, regular_user.id, digest_enabled=True)

    mailer = mock.Mock()
    with mock.patch.object(notifications_mod, "build_mailer", return_value=mailer):
        with app.app_context():
            IrisPhishingNotifyManager._run_notify(analysis_id)

    mailer.send.assert_called_once()


def test_non_critical_phishing_is_silenced_while_muted(app, regular_user):
    """total_score=35 está por encima del umbral de alta confianza (20) --
    un silenciado activo lo suprime por completo."""
    connection_id = _save_connection(app, regular_user.id)
    analysis_id = _save_analysis(app, regular_user.id, verdict="Phishing",
                                 connection_id=connection_id, total_score=35.0)
    _save_preference(app, regular_user.id, muted_until=utcnow_naive() + timedelta(hours=1))

    mailer = mock.Mock()
    with mock.patch.object(notifications_mod, "build_mailer", return_value=mailer):
        with app.app_context():
            IrisPhishingNotifyManager._run_notify(analysis_id)

    mailer.send.assert_not_called()


def test_non_critical_phishing_sends_once_mute_has_expired(app, regular_user):
    connection_id = _save_connection(app, regular_user.id)
    analysis_id = _save_analysis(app, regular_user.id, verdict="Phishing",
                                 connection_id=connection_id, total_score=35.0)
    _save_preference(app, regular_user.id, muted_until=utcnow_naive() - timedelta(minutes=1))

    mailer = mock.Mock()
    with mock.patch.object(notifications_mod, "build_mailer", return_value=mailer):
        with app.app_context():
            IrisPhishingNotifyManager._run_notify(analysis_id)

    mailer.send.assert_called_once()


def test_non_critical_phishing_is_deferred_to_the_digest(app, regular_user):
    connection_id = _save_connection(app, regular_user.id)
    analysis_id = _save_analysis(app, regular_user.id, verdict="Phishing",
                                 connection_id=connection_id, total_score=35.0)
    _save_preference(app, regular_user.id, digest_enabled=True)

    mailer = mock.Mock()
    with mock.patch.object(notifications_mod, "build_mailer", return_value=mailer):
        with app.app_context():
            IrisPhishingNotifyManager._run_notify(analysis_id)

    mailer.send.assert_not_called()


def test_non_critical_phishing_sends_normally_without_preferences(app, regular_user):
    """Sin fila de preferencias (usuario que nunca las ha tocado), un
    Phishing no crítico se comporta como antes de M08: se notifica."""
    connection_id = _save_connection(app, regular_user.id)
    analysis_id = _save_analysis(app, regular_user.id, verdict="Phishing",
                                 connection_id=connection_id, total_score=35.0)

    mailer = mock.Mock()
    with mock.patch.object(notifications_mod, "build_mailer", return_value=mailer):
        with app.app_context():
            IrisPhishingNotifyManager._run_notify(analysis_id)

    mailer.send.assert_called_once()


# ------------------------------------------------- IrisReauthNotifyManager

def test_reauth_notify_sends_to_connection_owner(app, regular_user):
    connection_id = _save_connection(app, regular_user.id, status="reauth_required")

    mailer = mock.Mock()
    with mock.patch.object(notifications_mod, "build_mailer", return_value=mailer):
        with app.app_context():
            IrisReauthNotifyManager._run_notify(connection_id)

    mailer.send.assert_called_once()
    message = mailer.send.call_args.args[0]
    assert "victim@example.com" in message.subject


def test_reauth_notify_skips_if_connection_recovered(app, regular_user):
    """El job pudo tardar en ejecutarse -- si para entonces la conexión ya
    volvió a estar activa (el usuario la reconectó), no hay nada que avisar."""
    connection_id = _save_connection(app, regular_user.id, status="active")

    mailer = mock.Mock()
    with mock.patch.object(notifications_mod, "build_mailer", return_value=mailer):
        with app.app_context():
            IrisReauthNotifyManager._run_notify(connection_id)

    mailer.send.assert_not_called()


def test_reauth_notify_respects_preference(app, regular_user):
    connection_id = _save_connection(app, regular_user.id, status="reauth_required")
    _save_preference(app, regular_user.id, notify_reauth_required=False)

    mailer = mock.Mock()
    with mock.patch.object(notifications_mod, "build_mailer", return_value=mailer):
        with app.app_context():
            IrisReauthNotifyManager._run_notify(connection_id)

    mailer.send.assert_not_called()


def test_mark_reauth_required_notifies_only_on_the_transition(app, regular_user):
    """Ver IrisMailboxManager._mark_reauth_required: solo la primera llamada
    (active -> reauth_required) debe encolar el aviso; reintentos
    posteriores mientras sigue en ese estado no deben repetirlo."""
    from src.modules.features.iris.managers.mailbox import IrisMailboxManager

    connection_id = _save_connection(app, regular_user.id, status="active")

    fake_queue = _FakeTaskQueue()
    with mock.patch.object(notifications_mod.TaskQueue, "get_instance", return_value=fake_queue):
        with app.app_context():
            IrisMailboxManager._mark_reauth_required(connection_id, "token revocado")
            IrisMailboxManager._mark_reauth_required(connection_id, "token revocado otra vez")

    reauth_jobs = [j for j in fake_queue.submitted if j["category"] == "iris.notify"]
    assert len(reauth_jobs) == 1
    assert reauth_jobs[0]["args"] == (connection_id,)


# ---------------------------------------------- IrisStuckSyncNotifyManager

def test_stuck_sync_notify_sends_to_connection_owner(app, regular_user):
    connection_id = _save_connection(app, regular_user.id)

    mailer = mock.Mock()
    with mock.patch.object(notifications_mod, "build_mailer", return_value=mailer):
        with app.app_context():
            IrisStuckSyncNotifyManager._run_notify(connection_id)

    mailer.send.assert_called_once()


def test_stuck_sync_notify_respects_preference(app, regular_user):
    connection_id = _save_connection(app, regular_user.id)
    _save_preference(app, regular_user.id, notify_sync_stuck=False)

    mailer = mock.Mock()
    with mock.patch.object(notifications_mod, "build_mailer", return_value=mailer):
        with app.app_context():
            IrisStuckSyncNotifyManager._run_notify(connection_id)

    mailer.send.assert_not_called()


# --------------------------------------------------- IrisDigestNotifyManager

def test_digest_notify_skips_if_not_enabled(app, regular_user):
    mailer = mock.Mock()
    with mock.patch.object(notifications_mod, "build_mailer", return_value=mailer):
        with app.app_context():
            IrisDigestNotifyManager._run_notify(regular_user.id)

    mailer.send.assert_not_called()


def test_digest_notify_advances_last_sent_without_sending_when_nothing_to_report(app, regular_user):
    _save_preference(app, regular_user.id, digest_enabled=True)

    mailer = mock.Mock()
    with mock.patch.object(notifications_mod, "build_mailer", return_value=mailer):
        with app.app_context():
            IrisDigestNotifyManager._run_notify(regular_user.id)

    mailer.send.assert_not_called()
    assert _reload_preference(app, regular_user.id).digest_last_sent_at is not None


def test_digest_notify_sends_one_email_with_all_non_critical_analyses(app, regular_user):
    connection_id = _save_connection(app, regular_user.id)
    _save_preference(app, regular_user.id, digest_enabled=True)
    first_id = _save_analysis(app, regular_user.id, verdict="Phishing", connection_id=connection_id,
                              title="Factura pendiente", total_score=30.0)
    second_id = _save_analysis(app, regular_user.id, verdict="Phishing", connection_id=connection_id,
                               title="Verifica tu cuenta", total_score=40.0)
    # Un crítico no debe colarse en el digest -- ya se notificó al momento.
    _save_analysis(app, regular_user.id, verdict="Phishing", connection_id=connection_id,
                   title="Alerta urgente", total_score=5.0)

    mailer = mock.Mock()
    with mock.patch.object(notifications_mod, "build_mailer", return_value=mailer):
        with app.app_context():
            IrisDigestNotifyManager._run_notify(regular_user.id)

    mailer.send.assert_called_once()
    message = mailer.send.call_args.args[0]
    assert "2" in message.subject
    assert f"#{first_id}" in message.html_body
    assert f"#{second_id}" in message.html_body
    assert _reload_preference(app, regular_user.id).digest_last_sent_at is not None


def test_digest_notify_does_not_advance_last_sent_when_send_fails(app, regular_user):
    connection_id = _save_connection(app, regular_user.id)
    _save_preference(app, regular_user.id, digest_enabled=True)
    _save_analysis(app, regular_user.id, verdict="Phishing", connection_id=connection_id,
                   total_score=30.0)

    mailer = mock.Mock()
    mailer.send.side_effect = RuntimeError("smtp is down")
    with mock.patch.object(notifications_mod, "build_mailer", return_value=mailer):
        with app.app_context():
            IrisDigestNotifyManager._run_notify(regular_user.id)

    assert _reload_preference(app, regular_user.id).digest_last_sent_at is None


def test_digest_notify_only_includes_analyses_since_last_digest(app, regular_user):
    connection_id = _save_connection(app, regular_user.id)
    _save_preference(app, regular_user.id, digest_enabled=True,
                     digest_last_sent_at=utcnow_naive())
    old_id = _save_analysis(app, regular_user.id, verdict="Phishing", connection_id=connection_id,
                            total_score=30.0)
    # Retrocede el finished_at del análisis "viejo" para que quede antes del
    # último digest -- _save_analysis lo pone a "ahora" por defecto.
    with app.app_context():
        with UnitOfWork() as uow:
            repo = IrisAnalysisRepository(uow)
            old_analysis = repo.get_by_id(old_id)
            old_analysis.finished_at = utcnow_naive() - timedelta(days=2)
            repo.update(old_analysis)

    mailer = mock.Mock()
    with mock.patch.object(notifications_mod, "build_mailer", return_value=mailer):
        with app.app_context():
            IrisDigestNotifyManager._run_notify(regular_user.id)

    mailer.send.assert_not_called()
