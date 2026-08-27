"""
src.modules.tools.herald — Envío de correo transversal.

Módulo compartido, hermano de ``scribe``: cualquier módulo (Aegis, ...)
construye un ``EmailMessage`` y se lo pasa a un ``Mailer``, que delega en una
estrategia de envío inyectada (SMTP hoy; APIs de proveedores transaccionales
más adelante). La estrategia se decide por módulo desde ``SecOpsConfig.json``
mediante ``build_mailer``. Aegis depende de herald; herald no conoce a Aegis.

El cuerpo se compone con ``render_email``, que renderiza las plantillas Jinja
de ``templates/`` sobre una envoltura de marca común — ningún módulo vuelve a
concatenar HTML a mano.

Uso típico:
    >>> from src.modules.tools.herald import build_mailer, render_email, EmailMessage
    >>> html, text = render_email("campaign", pill_title="…", link="…")
    >>> mailer = build_mailer("aegis")
    >>> result = mailer.send(EmailMessage(
    ...     to="user@example.com", subject="...", html_body=html, text_body=text,
    ... ))
"""

from .inputs import EmailMessage, InlineImage, SendResult
from .strategies import EmailStrategy, SmtpStrategy
from .mailer import Mailer
from .factory import build_mailer
from .rendering import render_email
from .branding import LOGO_CONTENT_ID, apply_white_label, default_brand
from .exceptions import (
    EmailConnectionError,
    EmailSendError,
    EmailConfigurationError,
)

__all__ = [
    "EmailMessage",
    "InlineImage",
    "SendResult",
    "EmailStrategy",
    "SmtpStrategy",
    "Mailer",
    "build_mailer",
    "render_email",
    "apply_white_label",
    "default_brand",
    "LOGO_CONTENT_ID",
    "EmailConnectionError",
    "EmailSendError",
    "EmailConfigurationError",
]
