"""
Tests del white-labeling transversal: el concepto (``shared._white_label``) y
su proyección a un correo (``tools.herald.branding``).

Ningún módulo de features aparece aquí a propósito: estas piezas no conocen a
sus consumidores.
"""

from __future__ import annotations

import base64

import pytest
from marshmallow import Schema, ValidationError

from src.modules.shared import (
    WhiteLabel,
    WhiteLabelLevel,
    WhiteLabelSchemaMixin,
    validate_logo_data_uri,
)
from src.modules.shared._white_label import MAX_LOGO_BYTES
from src.modules.tools.herald.branding import (
    LOGO_CONTENT_ID,
    apply_white_label,
)

pytestmark = pytest.mark.unit


_PNG_BYTES = bytes.fromhex(
    "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4"
    "890000000a49444154789c6360000002000100ffff03000006000557bfabd400"
    "00000049454e44ae426082"
)
_PNG_URI = "data:image/png;base64," + base64.b64encode(_PNG_BYTES).decode()

_BASE_BRAND = {
    "productName": "Ellysia",
    "accentColor": "#d4a04a",
    "logoUrl": "https://cdn.ellysia.test/logo.png",
    "supportEmail": "soporte@ellysia.test",
    "footerNote": "Ellysia S.L.",
    "customerLogoUrl": "",
    "whiteLabelLevel": "none",
}


class _ProfileSchema(WhiteLabelSchemaMixin, Schema):
    """Esquema mínimo, como el que declararía cualquier módulo consumidor."""


# ── Validación del logo ─────────────────────────────────────────────────────

def test_validate_logo_data_uri_accepts_png():
    mimetype, data = validate_logo_data_uri(_PNG_URI)
    assert mimetype == "image/png"
    assert data == _PNG_BYTES


@pytest.mark.parametrize(
    "value",
    [
        "",
        "https://cdn.empresa.test/logo.png",
        "data:image/svg+xml;base64," + base64.b64encode(b"<svg/>").decode(),
        "data:text/html;base64," + base64.b64encode(b"<h1>hi</h1>").decode(),
        "data:image/png;base64,no-es-base64!!",
    ],
)
def test_validate_logo_data_uri_rejects_invalid(value):
    with pytest.raises(ValueError):
        validate_logo_data_uri(value)


def test_validate_logo_data_uri_rejects_oversized_logo():
    oversized = "data:image/png;base64," + base64.b64encode(b"\x00" * (MAX_LOGO_BYTES + 1)).decode()
    with pytest.raises(ValueError, match="máximo"):
        validate_logo_data_uri(oversized)


def test_schema_mixin_rejects_invalid_logo_and_level():
    with pytest.raises(ValidationError):
        _ProfileSchema().load({"brandLogo": "javascript:alert(1)"})
    with pytest.raises(ValidationError):
        _ProfileSchema().load({"whiteLabelLevel": "parcial"})


def test_schema_mixin_defaults_to_no_white_label():
    assert _ProfileSchema().load({}) == {"whiteLabelLevel": "none", "brandLogo": ""}


# ── Degradación de nivel ────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "level, logo, brand_name, expected",
    [
        (WhiteLabelLevel.NONE, _PNG_URI, "ACME", WhiteLabelLevel.NONE),
        (WhiteLabelLevel.LOGO, _PNG_URI, "ACME", WhiteLabelLevel.LOGO),
        # Sin logo, "añadir imagen corporativa" no añade nada.
        (WhiteLabelLevel.LOGO, "", "ACME", WhiteLabelLevel.NONE),
        (WhiteLabelLevel.FULL, _PNG_URI, "ACME", WhiteLabelLevel.FULL),
        # Sin nombre no hay con qué sustituir la marca: baja un escalón.
        (WhiteLabelLevel.FULL, _PNG_URI, "", WhiteLabelLevel.LOGO),
        (WhiteLabelLevel.FULL, "", "", WhiteLabelLevel.NONE),
    ],
)
def test_effective_level_degrades_when_data_is_missing(level, logo, brand_name, expected):
    assert WhiteLabel(level=level, logo=logo, brand_name=brand_name).effective_level is expected


def test_from_stored_tolerates_nulls_and_unknown_levels():
    white_label = WhiteLabel.from_stored(None, None, None)
    assert white_label.level is WhiteLabelLevel.NONE
    assert WhiteLabel.from_stored("inventado", _PNG_URI, "ACME").level is WhiteLabelLevel.NONE


def test_decoded_logo_returns_none_for_corrupt_stored_logo():
    """Un logo corrupto en BD no debe tumbar un envío en curso."""
    assert WhiteLabel(level=WhiteLabelLevel.LOGO, logo="data:image/png;base64,??").decoded_logo() is None


# ── Proyección sobre el correo ──────────────────────────────────────────────

def test_apply_white_label_none_leaves_brand_untouched():
    brand, images = apply_white_label(_BASE_BRAND, WhiteLabel())

    assert images == ()
    assert brand["productName"] == "Ellysia"
    assert brand["logoUrl"] == "https://cdn.ellysia.test/logo.png"
    assert brand["customerLogoUrl"] == ""
    assert brand["whiteLabelLevel"] == "none"


def test_apply_white_label_logo_adds_customer_logo_and_keeps_product_brand():
    brand, images = apply_white_label(
        _BASE_BRAND,
        WhiteLabel(level=WhiteLabelLevel.LOGO, logo=_PNG_URI, brand_name="ACME"),
    )

    assert brand["customerLogoUrl"] == f"cid:{LOGO_CONTENT_ID}"
    assert brand["productName"] == "Ellysia"
    assert brand["logoUrl"] == "https://cdn.ellysia.test/logo.png"
    assert brand["supportEmail"] == "soporte@ellysia.test"
    assert len(images) == 1
    assert images[0].content_id == LOGO_CONTENT_ID
    assert images[0].data == _PNG_BYTES


def test_apply_white_label_full_replaces_product_brand():
    brand, images = apply_white_label(
        _BASE_BRAND,
        WhiteLabel(level=WhiteLabelLevel.FULL, logo=_PNG_URI, brand_name="ACME"),
    )

    assert brand["productName"] == "ACME"
    assert brand["logoUrl"] == f"cid:{LOGO_CONTENT_ID}"
    # Sin duplicar: en FULL el logo ya está en la cabecera.
    assert brand["customerLogoUrl"] == ""
    assert brand["supportEmail"] == ""
    assert brand["footerNote"] == ""
    assert len(images) == 1
    assert "Ellysia" not in " ".join(str(value) for value in brand.values())


def test_apply_white_label_full_without_logo_drops_product_logo():
    """Sin logo propio, la cabecera cae al nombre — nunca al logo del producto."""
    brand, images = apply_white_label(
        _BASE_BRAND,
        WhiteLabel(level=WhiteLabelLevel.FULL, brand_name="ACME"),
    )

    assert brand["logoUrl"] == ""
    assert brand["productName"] == "ACME"
    assert images == ()
