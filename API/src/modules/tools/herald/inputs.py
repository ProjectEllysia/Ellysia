"""
herald.inputs
─────────────
Dataclasses de tránsito del envío de correo.

    — EmailMessage: contrato de entrada que recibe ``Mailer.send``. Agnóstico
      al backend: cada estrategia lo traduce a su API nativa (SMTP, …).
    — InlineImage: imagen incrustada en el cuerpo HTML y referenciada con
      ``cid:``.
    — SendResult: contrato de salida de un envío individual.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class InlineImage:
    """
    Imagen incrustada en el cuerpo del correo y referenciada desde el HTML
    como ``<img src="cid:{content_id}">``.

    Frente a un ``<img>`` a una URL externa, la imagen viaja dentro del
    mensaje: no hace falta publicarla en un endpoint accesible sin
    autenticación, y no se cae cuando el cliente bloquea contenido remoto.

    Attributes:
        content_id: Identificador con el que el HTML la referencia, *sin* los
            ángulos del Content-ID (``logo``, no ``<logo>``).
        data: Bytes de la imagen.
        mimetype: Tipo MIME completo ('image/png').
    """

    content_id: str
    data: bytes
    mimetype: str

    def __post_init__(self) -> None:
        if not self.content_id or "<" in self.content_id or ">" in self.content_id:
            raise ValueError(
                f"'content_id' debe ser un identificador sin ángulos: {self.content_id!r}"
            )
        if not self.data:
            raise ValueError("'data' no puede estar vacío")
        if not self.mimetype.startswith("image/") or self.mimetype.count("/") != 1:
            raise ValueError(f"'mimetype' debe ser un tipo de imagen: {self.mimetype!r}")

    @property
    def mime_parts(self) -> tuple[str, str]:
        """El mimetype partido en ``(maintype, subtype)``."""
        maintype, subtype = self.mimetype.split("/", 1)
        return maintype, subtype


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
        inline_images: Imágenes incrustadas que el HTML referencia con
            ``cid:``. Tupla (no lista) porque el mensaje es inmutable.
    """

    to: str
    subject: str
    html_body: str
    to_name: str | None = None
    text_body: str | None = None
    reply_to: str | None = None
    inline_images: tuple[InlineImage, ...] = ()

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
