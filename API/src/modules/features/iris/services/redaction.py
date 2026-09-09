"""
services/redaction.py — redacción de PII en las vistas de Iris que pueden
salir del panel autenticado (M09).

Hoy la única de esas vistas es el PDF exportable de un análisis
(``services/reports.py::IrisPDFCreator.append_raw_headers``), que hasta
ahora volcaba el raw completo del correo tal cual -- incluyendo cualquier
dirección de correo, teléfono o número con forma de tarjeta que apareciera
en cabeceras de reenvío, listas de distribución o el cuerpo (en modo
``full_message_mode``). No se redacta el remitente/destinatario/responder-a
ya mostrados en la "Vista Previa del Correo": esos son la evidencia del
informe, no PII que ocultar -- ``keep_emails`` es precisamente para
preservarlos.
"""

from __future__ import annotations

import re
from typing import Iterable

_EMAIL_RE = re.compile(r"[\w.+-]+@[\w.-]+\.\w+")

# Números con forma de tarjeta antes que teléfono: una tarjeta de 16 dígitos
# agrupados en cuatro coincidiría también con el patrón de teléfono si este
# se aplicara primero, dejando fragmentos sin redactar.
_CREDIT_CARD_RE = re.compile(r"(?<!\d)(?:\d[ -]?){13,16}\d(?!\d)")
_PHONE_RE = re.compile(r"(?<!\d)(?:\+?\d[\d\-\s()]{7,14}\d)(?!\d)")


def redact_pii(text: str, *, keep_emails: Iterable[str] = ()) -> str:
    """Redacta emails, teléfonos y números con forma de tarjeta de ``text``.

    Args:
        text: Texto a redactar (normalmente el raw MIME/cabeceras de un
            análisis).
        keep_emails: Direcciones que no se redactan aunque aparezcan en
            ``text`` -- las ya mostradas en la vista previa estructurada del
            informe (remitente, destinatario, responder-a, return-path), que
            son la evidencia del análisis, no PII incidental. Comparación
            insensible a mayúsculas.

    Returns:
        str: ``text`` con cada coincidencia sustituida -- un email no
            conservado se enmascara como ``x***@dominio`` (conserva el
            dominio, útil para ver "era del mismo remitente" sin revelar la
            dirección completa); teléfonos y tarjetas se sustituyen por una
            etiqueta fija.
    """
    keep = {email.lower() for email in keep_emails if email}

    def _mask_email(match: re.Match) -> str:
        address = match.group(0)
        if address.lower() in keep:
            return address
        local, _, domain = address.partition("@")
        return f"{local[:1]}***@{domain}"

    redacted = _EMAIL_RE.sub(_mask_email, text)
    redacted = _CREDIT_CARD_RE.sub("[tarjeta redactada]", redacted)
    redacted = _PHONE_RE.sub("[teléfono redactado]", redacted)
    return redacted
