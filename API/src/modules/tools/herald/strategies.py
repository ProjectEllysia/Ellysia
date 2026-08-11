"""
herald.strategies
──────────────────
Estrategias de envío de correo inyectables en ``Mailer``.

Cada estrategia traduce un ``EmailMessage`` a la API nativa de un proveedor y
ejecuta el envío, devolviendo un ``SendResult``. Así el resto de la
plataforma es agnóstica a si detrás hay un relay SMTP directo o (más
adelante) la API de un proveedor transaccional.

    — EmailStrategy: contrato abstracto.
    — SmtpStrategy: envío vía relay SMTP (Brevo, SES, o cualquier proveedor
      que exponga un endpoint SMTP — la mayoría lo hacen).
"""

from __future__ import annotations

import logging
import re
import smtplib
from abc import ABC, abstractmethod
from email.message import EmailMessage as MimeMessage
from email.utils import make_msgid
from typing import Optional

from .exceptions import EmailConfigurationError, EmailConnectionError, EmailSendError
from .inputs import EmailMessage, SendResult

logger = logging.getLogger(__name__)

_TAG_RE = re.compile(r"<[^>]+>")


def _html_to_text(html: str) -> str:
    """Fallback de texto plano cuando el mensaje no trae uno explícito."""
    text = _TAG_RE.sub(" ", html)
    return re.sub(r"\s+", " ", text).strip()


class EmailStrategy(ABC):
    """Contrato de una estrategia de envío de correo.

    ``register``/``resolve`` (B4) centralizan lo que ``herald.factory`` hacía
    con una cadena ``if/elif`` por nombre — hoy con una sola rama, pero el
    propio docstring del módulo ya anticipa una segunda (una API
    transaccional), que se dará de alta junto a su clase en vez de abrir
    esta factory.
    """

    #: Nombre legible de la estrategia (para logs y configuración).
    name: str = "email"

    _registry: dict[str, type["EmailStrategy"]] = {}

    @classmethod
    def register(cls, name: str):
        def decorator(subclass: type["EmailStrategy"]) -> type["EmailStrategy"]:
            cls._registry[name] = subclass
            return subclass
        return decorator

    @classmethod
    def resolve(cls, name: str, overrides: dict) -> "EmailStrategy":
        """Instancia la estrategia ``name`` con credenciales de entorno/config."""
        strategy_cls = cls._registry.get(name)
        if strategy_cls is None:
            raise EmailConfigurationError(f"estrategia desconocida: '{name}'")
        return strategy_cls.from_config(overrides)

    @classmethod
    def from_config(cls, overrides: dict) -> "EmailStrategy":
        """Construye esta estrategia a partir de las credenciales de entorno
        (``.env``) y las ``overrides`` de ``SecOpsConfig.json``
        (``tools.herald.modules.<módulo>``).

        No es ``@abstractmethod``: un doble de test que construye la
        estrategia directamente (sin pasar por ``resolve``/config real) no
        tiene por qué implementarlo — solo lo necesitan las estrategias
        registradas de verdad (ver ``tests/unit/test_herald.py::FakeEmailStrategy``)."""
        raise NotImplementedError

    @abstractmethod
    def send(self, message: EmailMessage) -> SendResult:
        """
        Envía ``message`` y devuelve el resultado.

        Raises:
            EmailConnectionError: Si falla la comunicación con el proveedor.
            EmailSendError: Si el proveedor rechaza el mensaje.
        """


@EmailStrategy.register("smtp")
class SmtpStrategy(EmailStrategy):
    """Estrategia que envía correo vía un relay SMTP."""

    name = "smtp"

    @classmethod
    def from_config(cls, overrides: dict) -> "SmtpStrategy":
        import src.modules.system.config_reading as CR
        try:
            creds = CR.get_smtp_environment()
        except ValueError as exc:
            # get_smtp_environment lanza ValueError pelado; aquí dentro es un
            # fallo de configuración y debe salir como tal.
            raise EmailConfigurationError(str(exc)) from exc
        return cls(
            host=overrides.get("host", "localhost"),
            port=int(overrides.get("port", 587)),
            from_address=overrides.get("fromAddress") or creds.get("username", ""),
            from_name=overrides.get("fromName"),
            use_tls=bool(overrides.get("useTls", True)),
            username=creds.get("username"),
            password=creds.get("password"),
        )

    def __init__(
        self,
        host: str,
        port: int,
        from_address: str,
        from_name: Optional[str] = None,
        use_tls: bool = True,
        username: Optional[str] = None,
        password: Optional[str] = None,
        timeout: int = 30,
    ) -> None:
        self.host = host
        self.port = port
        self.from_address = from_address
        self.from_name = from_name
        self.use_tls = use_tls
        self.username = username
        self.password = password
        self.timeout = timeout
        logger.info("[herald/smtp] cliente host=%s:%d from=%s", host, port, from_address)

    def _build_mime(self, message: EmailMessage) -> MimeMessage:
        mime = MimeMessage()
        mime["Subject"] = message.subject
        mime["From"] = (
            f"{self.from_name} <{self.from_address}>" if self.from_name else self.from_address
        )
        mime["To"] = f"{message.to_name} <{message.to}>" if message.to_name else message.to
        mime["Message-ID"] = make_msgid()
        if message.reply_to:
            mime["Reply-To"] = message.reply_to

        mime.set_content(message.text_body or _html_to_text(message.html_body))
        mime.add_alternative(message.html_body, subtype="html")
        return mime

    def send(self, message: EmailMessage) -> SendResult:
        mime = self._build_mime(message)

        try:
            with smtplib.SMTP(self.host, self.port, timeout=self.timeout) as client:
                if self.use_tls:
                    client.starttls()
                if self.username:
                    client.login(self.username, self.password or "")
                client.send_message(mime)
        except (
            smtplib.SMTPRecipientsRefused,
            smtplib.SMTPResponseException,
            smtplib.SMTPSenderRefused,
        ) as exc:
            logger.error("[herald/smtp] envío rechazado a %s: %s", message.to, exc)
            raise EmailSendError(str(exc), recipient=message.to) from exc
        except (smtplib.SMTPException, OSError) as exc:
            logger.error(
                "[herald/smtp] error de conexión con %s: %s", self.host, exc, exc_info=True
            )
            raise EmailConnectionError(str(exc), host=self.host) from exc

        return SendResult(ok=True, provider_message_id=mime["Message-ID"])
