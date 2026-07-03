"""
src.modules.herald — Envío de correo transversal.

Módulo compartido, hermano de ``scribe``: cualquier módulo (Aegis, ...)
construye un ``EmailMessage`` y se lo pasa a un ``Mailer``, que delega en una
estrategia de envío inyectada (SMTP hoy; APIs de proveedores transaccionales
más adelante). La estrategia se decide por módulo desde ``SecOpsConfig.json``
mediante ``build_mailer``. Aegis depende de herald; herald no conoce a Aegis.

Uso típico:
    >>> from src.modules.herald import build_mailer, EmailMessage
    >>> mailer = build_mailer("aegis")
    >>> result = mailer.send(EmailMessage(
    ...     to="user@example.com", subject="...", html_body="...",
    ... ))
"""

from .inputs import EmailMessage, SendResult
from .strategies import EmailStrategy, SmtpStrategy
from .mailer import Mailer
from .factory import build_mailer
from .exceptions import (
    EmailConnectionError,
    EmailSendError,
    EmailConfigurationError,
)

__all__ = [
    "EmailMessage",
    "SendResult",
    "EmailStrategy",
    "SmtpStrategy",
    "Mailer",
    "build_mailer",
    "EmailConnectionError",
    "EmailSendError",
    "EmailConfigurationError",
]
