"""
Tests de SmtpStrategy contra un servidor SMTP local real (aiosmtpd).

No requiere red externa: aiosmtpd levanta un servidor en un puerto efímero
de loopback que captura los mensajes recibidos, permitiendo verificar
conexión, cabeceras y cuerpo sin depender de un proveedor cloud.
"""

from __future__ import annotations

import socket

import pytest

aiosmtpd_controller = pytest.importorskip("aiosmtpd.controller")
Controller = aiosmtpd_controller.Controller

from src.modules.herald.exceptions import EmailConnectionError, EmailSendError
from src.modules.herald.inputs import EmailMessage
from src.modules.herald.strategies import SmtpStrategy

pytestmark = pytest.mark.unit


def _free_port() -> int:
    """Reserva un puerto libre de loopback.

    ``Controller`` no resuelve puertos efímeros (``port=0``) internamente:
    su chequeo de arranque se conecta al puerto tal cual se le pasó, así que
    hace falta reservarlo nosotros mismos antes de arrancar el servidor.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class _CapturingHandler:
    """Acepta cualquier mensaje y lo guarda para inspección."""

    def __init__(self) -> None:
        self.messages: list[dict] = []

    async def handle_DATA(self, server, session, envelope):
        self.messages.append(
            {
                "mail_from": envelope.mail_from,
                "rcpt_tos": list(envelope.rcpt_tos),
                "content": envelope.content.decode("utf-8", errors="replace"),
            }
        )
        return "250 Message accepted for delivery"


class _RejectingHandler:
    """Rechaza cualquier destinatario, simulando un correo inexistente."""

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        return "550 no such user"


@pytest.fixture
def smtp_server():
    handler = _CapturingHandler()
    controller = Controller(handler, hostname="127.0.0.1", port=_free_port())
    controller.start()
    try:
        yield controller, handler
    finally:
        controller.stop()


@pytest.fixture
def rejecting_smtp_server():
    controller = Controller(_RejectingHandler(), hostname="127.0.0.1", port=_free_port())
    controller.start()
    try:
        yield controller
    finally:
        controller.stop()


def test_smtp_strategy_sends_message_to_local_server(smtp_server):
    controller, handler = smtp_server
    strategy = SmtpStrategy(
        host=controller.hostname,
        port=controller.port,
        from_address="noreply@seq.test",
        from_name="SeQ Awareness",
        use_tls=False,
    )
    message = EmailMessage(
        to="empleado@empresa.test",
        to_name="Empleado",
        subject="Concienciación: Phishing",
        html_body="<p>Contenido de la píldora</p>",
        reply_to="seguridad@empresa.test",
    )

    result = strategy.send(message)

    assert result.ok is True
    assert result.provider_message_id
    assert len(handler.messages) == 1

    received = handler.messages[0]
    assert received["mail_from"] == "noreply@seq.test"
    assert received["rcpt_tos"] == ["empleado@empresa.test"]
    assert "Contenido de la píldora" in received["content"]
    assert "Reply-To: seguridad@empresa.test" in received["content"]


def test_smtp_strategy_raises_connection_error_when_server_unreachable():
    strategy = SmtpStrategy(
        host="127.0.0.1",
        port=1,  # puerto reservado, sin listener
        from_address="noreply@seq.test",
        use_tls=False,
        timeout=2,
    )
    message = EmailMessage(to="a@b.com", subject="hola", html_body="<p>hi</p>")

    with pytest.raises(EmailConnectionError):
        strategy.send(message)


def test_smtp_strategy_raises_connection_error_when_tls_required_but_unsupported(smtp_server):
    """El servidor de prueba no anuncia STARTTLS: forzar TLS debe fallar limpio."""
    controller, _ = smtp_server
    strategy = SmtpStrategy(
        host=controller.hostname,
        port=controller.port,
        from_address="noreply@seq.test",
        use_tls=True,
    )
    message = EmailMessage(to="a@b.com", subject="hola", html_body="<p>hi</p>")

    with pytest.raises(EmailConnectionError):
        strategy.send(message)


def test_smtp_strategy_raises_send_error_when_recipient_rejected(rejecting_smtp_server):
    controller = rejecting_smtp_server
    strategy = SmtpStrategy(
        host=controller.hostname,
        port=controller.port,
        from_address="noreply@seq.test",
        use_tls=False,
    )
    message = EmailMessage(to="ghost@empresa.test", subject="hola", html_body="<p>hi</p>")

    with pytest.raises(EmailSendError):
        strategy.send(message)
