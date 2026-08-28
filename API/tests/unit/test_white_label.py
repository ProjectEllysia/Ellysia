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
    validate_brand_color,
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
_COLOR = "#1a73e8"

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


def test_validate_logo_data_uri_accepts_wrapped_base64():
    """Base64 partido en líneas (RFC 2045) es válido y hay codificadores que lo
    generan solos — ``base64.encodebytes``, sin ir más lejos. El regex ya lo
    admitía; lo que fallaba era la decodificación con ``validate=True``."""
    wrapped = "data:image/png;base64," + base64.encodebytes(_PNG_BYTES).decode()

    mimetype, data = validate_logo_data_uri(wrapped)

    assert mimetype == "image/png"
    assert data == _PNG_BYTES


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
    assert _ProfileSchema().load({}) == {
        "whiteLabelLevel": "none", "brandLogo": "", "brandColor": "",
    }


# ── Validación del color ────────────────────────────────────────────────────

def test_validate_brand_color_normalizes_case():
    assert validate_brand_color("#1A73E8") == "#1a73e8"


@pytest.mark.parametrize(
    "value",
    ["", "1a73e8", "#1a73e", "#1a73e88", "rojo", "red", "#12345g",
     # El color acaba dentro de un atributo style: nada de CSS libre.
     "#fff; background:url(http://x)"],
)
def test_validate_brand_color_rejects_anything_but_six_hex_digits(value):
    with pytest.raises(ValueError):
        validate_brand_color(value)


def test_schema_mixin_rejects_an_invalid_color():
    with pytest.raises(ValidationError):
        _ProfileSchema().load({"brandColor": "red"})


# ── Degradación de nivel ────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "level, logo, color, brand_name, expected",
    [
        (WhiteLabelLevel.NONE, _PNG_URI, _COLOR, "ACME", WhiteLabelLevel.NONE),
        (WhiteLabelLevel.COLOR, "", _COLOR, "ACME", WhiteLabelLevel.COLOR),
        # Sin color, "aplicar color corporativo" no aplica nada.
        (WhiteLabelLevel.COLOR, _PNG_URI, "", "ACME", WhiteLabelLevel.NONE),
        (WhiteLabelLevel.LOGO, _PNG_URI, _COLOR, "ACME", WhiteLabelLevel.LOGO),
        # Sin logo baja al escalón de color, que sí puede aplicarse.
        (WhiteLabelLevel.LOGO, "", _COLOR, "ACME", WhiteLabelLevel.COLOR),
        (WhiteLabelLevel.LOGO, "", "", "ACME", WhiteLabelLevel.NONE),
        (WhiteLabelLevel.FULL, _PNG_URI, _COLOR, "ACME", WhiteLabelLevel.FULL),
        # Sin nombre no hay con qué sustituir la marca: baja un escalón.
        (WhiteLabelLevel.FULL, _PNG_URI, _COLOR, "", WhiteLabelLevel.LOGO),
        # Y sigue bajando hasta encontrar un escalón que se sostenga.
        (WhiteLabelLevel.FULL, "", _COLOR, "", WhiteLabelLevel.COLOR),
        (WhiteLabelLevel.FULL, "", "", "", WhiteLabelLevel.NONE),
    ],
)
def test_effective_level_degrades_when_data_is_missing(level, logo, color, brand_name, expected):
    settings = WhiteLabel(level=level, logo=logo, color=color, brand_name=brand_name)
    assert settings.effective_level is expected


def test_from_stored_tolerates_nulls_and_unknown_levels():
    white_label = WhiteLabel.from_stored(None, None, None, None)
    assert white_label.level is WhiteLabelLevel.NONE
    assert WhiteLabel.from_stored("inventado", _PNG_URI, _COLOR, "ACME").level is WhiteLabelLevel.NONE


def test_capped_to_lowers_the_level_but_keeps_the_settings():
    """Bajar de plan no borra lo guardado: solo deja de aplicarse."""
    settings = WhiteLabel(
        level=WhiteLabelLevel.FULL, logo=_PNG_URI, color=_COLOR, brand_name="ACME",
    )
    capped = settings.capped_to(WhiteLabelLevel.COLOR)

    assert capped.level is WhiteLabelLevel.COLOR
    assert capped.logo == _PNG_URI
    assert capped.color == _COLOR


@pytest.mark.parametrize(
    "allowance, expected",
    [(None, "full"), (0, "none"), (1, "color"), (2, "logo"), (3, "full"), (9, "full")],
)
def test_from_allowance_maps_the_plan_value_to_a_level(allowance, expected):
    assert WhiteLabelLevel.from_allowance(allowance).value == expected


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


def test_apply_white_label_color_only_swaps_the_accent():
    brand, images = apply_white_label(
        _BASE_BRAND,
        WhiteLabel(level=WhiteLabelLevel.COLOR, logo=_PNG_URI, color=_COLOR, brand_name="ACME"),
    )

    assert brand["accentColor"] == _COLOR
    assert brand["productName"] == "Ellysia"
    # El logo puede estar guardado y este escalón todavía no lo usa.
    assert brand["customerLogoUrl"] == ""
    assert images == ()


def test_apply_white_label_logo_adds_customer_logo_and_keeps_product_brand():
    brand, images = apply_white_label(
        _BASE_BRAND,
        WhiteLabel(level=WhiteLabelLevel.LOGO, logo=_PNG_URI, color=_COLOR, brand_name="ACME"),
    )

    assert brand["accentColor"] == _COLOR

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
        WhiteLabel(level=WhiteLabelLevel.FULL, logo=_PNG_URI, color=_COLOR, brand_name="ACME"),
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
        WhiteLabel(level=WhiteLabelLevel.FULL, color=_COLOR, brand_name="ACME"),
    )

    assert brand["logoUrl"] == ""
    assert brand["productName"] == "ACME"
    assert images == ()
