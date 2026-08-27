"""
herald.branding
───────────────
Proyección del white-labeling (``shared._white_label``) sobre un correo.

El concepto — niveles, logo, validación — es del producto entero y vive en
``shared``. Aquí solo se traduce al vocabulario de un correo: qué claves de
``brand`` consumen las plantillas y cómo viaja el logo dentro del mensaje.

Un módulo que ofrezca white-labeling guarda los ajustes donde le convenga y
hace::

    brand, images = apply_white_label(default_brand(), white_label)
    html, text = render_email("campaign", brand=brand, …)
    mailer.send(EmailMessage(…, inline_images=images))

herald no sabe de qué módulo salen los ajustes, igual que no sabe de qué
módulo sale el resto del contexto de la plantilla.
"""

from __future__ import annotations

import src.modules.system.config_reading as CR
from src.modules.shared import WhiteLabel, WhiteLabelLevel

from .inputs import InlineImage


#: Content-ID con el que las plantillas referencian el logo del cliente.
LOGO_CONTENT_ID = "brand-logo"

#: Marca por defecto del producto. La config solo declara lo que quiera cambiar.
DEFAULT_BRAND: dict[str, str] = {
    "productName": "Ellysia",
    "accentColor": "#d4a04a",
    "logoUrl": "",
    "supportEmail": "",
    "footerNote": "",
    #: Logo del cliente que se pinta *además* de la marca del producto
    #: (nivel LOGO). En el nivel FULL no se usa: ahí el logo del cliente ocupa
    #: directamente el sitio de la marca, en ``logoUrl``.
    "customerLogoUrl": "",
    "whiteLabelLevel": WhiteLabelLevel.NONE.value,
}


def default_brand() -> dict[str, str]:
    """La marca del producto para esta instancia: los defaults más la config."""
    return {**DEFAULT_BRAND, **CR.herald_config().branding}


def apply_white_label(
    base_brand: dict[str, str],
    white_label: WhiteLabel,
) -> tuple[dict[str, str], tuple[InlineImage, ...]]:
    """
    Aplica los ajustes de white-labeling sobre la marca de un correo.

    Args:
        base_brand: Marca del producto (normalmente ``default_brand()``).
        white_label: Ajustes del cliente.

    Returns:
        ``(brand, inline_images)`` — el contexto ``brand`` para
        ``render_email`` y las imágenes a adjuntar al ``EmailMessage``. En el
        nivel NONE devuelve la marca intacta y ninguna imagen, de modo que el
        correo sale byte a byte como saldría sin white-labeling.
    """
    level = white_label.effective_level
    brand = {**base_brand, "whiteLabelLevel": level.value}
    if level is WhiteLabelLevel.NONE:
        return brand, ()

    decoded = white_label.decoded_logo()
    images: tuple[InlineImage, ...] = ()
    logo_url = ""
    if decoded is not None:
        mimetype, data = decoded
        images = (InlineImage(content_id=LOGO_CONTENT_ID, data=data, mimetype=mimetype),)
        logo_url = f"cid:{LOGO_CONTENT_ID}"

    if level is WhiteLabelLevel.LOGO:
        brand["customerLogoUrl"] = logo_url
        return brand, images

    # FULL: el logo del cliente ocupa el sitio de la marca del producto en vez
    # de sumarse a ella — pintarlo en los dos sitios lo repetiría en la misma
    # pantalla. El nombre sustituye también al del pie ("enviado desde …"), y
    # el correo de soporte y la nota de pie de la instancia se vacían: son de
    # la marca que aquí se está retirando.
    brand.update(
        productName=white_label.brand_name,
        logoUrl=logo_url,
        customerLogoUrl="",
        supportEmail="",
        footerNote="",
    )
    return brand, images
