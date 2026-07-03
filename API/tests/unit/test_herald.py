"""Tests unitarios del módulo herald (envío de correo transversal)."""

from __future__ import annotations

import pytest

import src.modules.system.config_reading as CR
from src.modules.herald import (
    EmailConfigurationError,
    EmailConnectionError,
    EmailMessage,
    EmailStrategy,
    Mailer,
    SendResult,
    build_mailer,
)
from src.modules.herald.factory import _build_strategy
from src.modules.herald.strategies import SmtpStrategy

pytestmark = pytest.mark.unit


class FakeEmailStrategy(EmailStrategy):
    """Estrategia en memoria: captura los mensajes enviados sin usar red."""

    name = "fake"

    def __init__(self, fail_for: set[str] | None = None) -> None:
        self.sent: list[EmailMessage] = []
        self._fail_for = fail_for or set()

    def send(self, message: EmailMessage) -> SendResult:
        if message.to in self._fail_for:
            raise EmailConnectionError("fallo simulado", host="fake")
        self.sent.append(message)
        return SendResult(ok=True, provider_message_id=f"fake-{len(self.sent)}")


# ─────────────────────────────────────────────────────────────────────────
# EmailMessage — validación
# ─────────────────────────────────────────────────────────────────────────

def test_email_message_rejects_invalid_recipient():
    with pytest.raises(ValueError):
        EmailMessage(to="not-an-email", subject="hola", html_body="<p>hi</p>")


def test_email_message_rejects_empty_subject():
    with pytest.raises(ValueError):
        EmailMessage(to="a@b.com", subject="", html_body="<p>hi</p>")


def test_email_message_rejects_empty_html_body():
    with pytest.raises(ValueError):
        EmailMessage(to="a@b.com", subject="hola", html_body="")


def test_email_message_accepts_valid_data():
    msg = EmailMessage(to="a@b.com", subject="hola", html_body="<p>hi</p>")
    assert msg.to == "a@b.com"


# ─────────────────────────────────────────────────────────────────────────
# Mailer — send / send_bulk
# ─────────────────────────────────────────────────────────────────────────

def test_mailer_send_delegates_to_strategy():
    strategy = FakeEmailStrategy()
    mailer = Mailer(strategy)
    msg = EmailMessage(to="a@b.com", subject="hola", html_body="<p>hi</p>")

    result = mailer.send(msg)

    assert result.ok is True
    assert strategy.sent == [msg]


def test_mailer_send_propagates_strategy_error():
    strategy = FakeEmailStrategy(fail_for={"bad@b.com"})
    mailer = Mailer(strategy)
    msg = EmailMessage(to="bad@b.com", subject="hola", html_body="<p>hi</p>")

    with pytest.raises(EmailConnectionError):
        mailer.send(msg)


def test_mailer_send_bulk_isolates_individual_failures():
    """Un destinatario inválido no debe abortar el resto de una campaña."""
    strategy = FakeEmailStrategy(fail_for={"bad@b.com"})
    mailer = Mailer(strategy)
    messages = [
        EmailMessage(to="good1@b.com", subject="hola", html_body="<p>hi</p>"),
        EmailMessage(to="bad@b.com", subject="hola", html_body="<p>hi</p>"),
        EmailMessage(to="good2@b.com", subject="hola", html_body="<p>hi</p>"),
    ]

    results = mailer.send_bulk(messages)

    assert [r.ok for r in results] == [True, False, True]
    assert results[1].error is not None
    assert [m.to for m in strategy.sent] == ["good1@b.com", "good2@b.com"]


# ─────────────────────────────────────────────────────────────────────────
# Config: bloque 'email' / estrategia por módulo
# ─────────────────────────────────────────────────────────────────────────

def test_get_email_config_reads_smtp_block():
    cfg = CR.get_email_config()
    assert cfg["defaultStrategy"] == "smtp"
    assert cfg["strategies"]["smtp"]["host"] == "smtp-relay.brevo.com"


def test_get_email_strategy_for_module_override():
    assert CR.get_email_strategy_for("aegis") == "smtp"


def test_get_email_strategy_for_unknown_module_falls_back_to_default():
    assert CR.get_email_strategy_for("unknown-module") == "smtp"


def test_get_email_strategy_for_no_module_returns_default():
    assert CR.get_email_strategy_for() == "smtp"


def test_get_smtp_environment_reads_env(monkeypatch):
    monkeypatch.setenv("SMTP_USERNAME", "user@brevo")
    monkeypatch.setenv("SMTP_PASSWORD", "secret")

    creds = CR.get_smtp_environment()

    assert creds == {"username": "user@brevo", "password": "secret"}


def test_get_smtp_environment_missing_var_raises(monkeypatch):
    monkeypatch.delenv("SMTP_USERNAME", raising=False)
    monkeypatch.delenv("SMTP_PASSWORD", raising=False)

    with pytest.raises(ValueError):
        CR.get_smtp_environment()


# ─────────────────────────────────────────────────────────────────────────
# Factory — build_mailer
# ─────────────────────────────────────────────────────────────────────────

def test_build_strategy_unknown_name_raises_configuration_error():
    with pytest.raises(EmailConfigurationError):
        _build_strategy("carrier-pigeon")


def test_build_strategy_smtp_uses_config_and_env(monkeypatch):
    monkeypatch.setenv("SMTP_USERNAME", "user@brevo")
    monkeypatch.setenv("SMTP_PASSWORD", "secret")

    strategy = _build_strategy("smtp")

    assert isinstance(strategy, SmtpStrategy)
    assert strategy.host == "smtp-relay.brevo.com"
    assert strategy.port == 587
    assert strategy.use_tls is True
    assert strategy.username == "user@brevo"


def test_build_mailer_returns_mailer_with_smtp_strategy(monkeypatch):
    monkeypatch.setenv("SMTP_USERNAME", "user@brevo")
    monkeypatch.setenv("SMTP_PASSWORD", "secret")

    mailer = build_mailer("aegis")

    assert isinstance(mailer, Mailer)
    assert isinstance(mailer.strategy, SmtpStrategy)
