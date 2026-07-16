"""
herald.inputs
─────────────
Dataclasses de tránsito del envío de correo.

    — EmailMessage: contrato de entrada que recibe ``Mailer.send``. Agnóstico
      al backend: cada estrategia lo traduce a su API nativa (SMTP, …).
    — SendResult: contrato de salida de un envío individual.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class EmailMessage:
    """
    Correo a enviar, agnóstico al proveedor.

    Attributes:
        to: Dirección del destinatario.
        subject: Asunto del correo.
        html_body: Cuerpo en HTML.
        to_name: Nombre visible del destinatario (opcional).
        text_body: Cuerpo en texto plano (opcional). Si no se indica, la
            estrategia SMTP genera uno a partir del HTML.
        reply_to: Dirección de respuesta alternativa (opcional).
    """

    to: str
    subject: str
    html_body: str
    to_name: str | None = None
    text_body: str | None = None
    reply_to: str | None = None

    def __post_init__(self) -> None:
        if not self.to or "@" not in self.to:
            raise ValueError(f"'to' debe ser una dirección de correo válida: {self.to!r}")
        if not self.subject:
            raise ValueError("'subject' no puede estar vacío")
        if not self.html_body:
            raise ValueError("'html_body' no puede estar vacío")


@dataclass
class SendResult:
    """
    Resultado de un envío individual.

    ``ok`` indica éxito. ``error`` contiene el mensaje de fallo cuando ``ok``
    es False — usado por ``Mailer.send_bulk`` para no abortar el resto del
    lote ante un destinatario inválido o un envío rechazado.
    """

    ok: bool
    provider_message_id: str | None = None
    error: str | None = None
