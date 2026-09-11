"""Conversor de ``.msg`` de Outlook: la evidencia sobrevive a la conversión.

Cubre el criterio de cierre: muestras de Outlook con cuerpo RTF, HTML,
adjuntos en línea y Unicode conservan evidencia equivalente a un ``.eml``.
Las muestras se generan aquí (``tests/_iris_msg_fixtures.py``) en vez de guardarse como
binarios, para que cada test diga qué contiene su ``.msg``.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from src.modules.features.iris.managers.analysis import IrisManager
from src.modules.features.iris.services.msg_converter import (
    MAX_EMBEDDING_DEPTH,
    MsgConversionError,
    convert_msg_to_eml,
    decompress_rtf,
    is_msg,
    rtf_to_text,
)
from src.modules.features.iris.services.parsers import parse_raw_message

from _iris_msg_fixtures import build_cfb, build_msg, compress_rtf

pytestmark = pytest.mark.unit

_TRANSPORT_HEADERS = (
    "Received: from mail.evil.example (mail.evil.example [198.51.100.7]) by mx.example.com "
    "with ESMTPS id x1; Mon, 07 Sep 2026 09:30:00 +0000\r\n"
    "Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=evil.example; dmarc=fail\r\n"
    'From: "Banco Ejemplo" <alertas@evil.example>\r\n'
    "To: cliente@example.com\r\n"
    "Subject: =?utf-8?q?Verificaci=C3=B3n_urgente?=\r\n"
    "Date: Mon, 07 Sep 2026 09:30:00 +0000\r\n"
    "Message-ID: <x1@evil.example>\r\n"
    "MIME-Version: 1.0\r\n"
    'Content-Type: multipart/alternative; boundary="original"\r\n'
)
_HTML = ('<html><body><p>Su cuenta será bloqueada. Verifique aquí: '
         '<a href="https://login.evil.example/verify">https://banco.example</a></p>'
         '<img src="cid:logo123"></body></html>')


# ------------------------------------------------------------- RTF

def test_rtf_decompression_round_trips_and_honours_the_uncompressed_variant():
    raw = b"{\\rtf1\\ansi Hola mundo\\par}"

    assert decompress_rtf(compress_rtf(raw)) == raw
    mela = b"".join([(len(raw) + 12).to_bytes(4, "little"), len(raw).to_bytes(4, "little"),
                     b"MELA", b"\x00" * 4, raw])
    assert decompress_rtf(mela) == raw


def test_rtf_decompression_is_capped_whatever_the_header_says():
    raw = b"A" * 5000

    assert len(decompress_rtf(compress_rtf(raw), max_bytes=1000)) == 1000


def test_rtf_to_text_keeps_the_readable_text():
    rtf = (b"{\\rtf1\\ansi{\\fonttbl{\\f0 Arial;}}{\\*\\generator Word;}"
           b"Pulse aqu\\'ed: https://evil.example/login\\par Caf\\u233? y m\\'e1s}")

    text = rtf_to_text(rtf)

    assert "Pulse aquí: https://evil.example/login" in text
    assert "Café y más" in text
    assert "Arial" not in text and "Word" not in text


# ------------------------------------------------------ correo recibido

def test_a_received_msg_keeps_its_original_transport_headers_and_bodies():
    data = build_msg(
        subject="Verificación urgente", transport_headers=_TRANSPORT_HEADERS,
        body="Su cuenta será bloqueada. Verifique aquí: https://login.evil.example/verify",
        html=_HTML,
        attachments=[
            {"filename": "logo.png", "data": b"\x89PNG\r\n\x1a\nfake", "mime": "image/png", "content_id": "logo123"},
            {"filename": "factura_ñ.pdf", "data": b"%PDF-1.4 fake", "mime": "application/pdf"},
        ],
    )

    eml = convert_msg_to_eml(data)
    context = parse_raw_message(eml)

    assert context.headers["from"] == '"Banco Ejemplo" <alertas@evil.example>'
    assert "dmarc=fail" in context.headers["authentication-results"]
    assert len(context.received_headers) == 1
    assert "X-Iris-Source-Format: outlook-msg" in eml
    assert "boundary=\"original\"" not in eml
    assert [link.href for link in context.links] == ["https://login.evil.example/verify"]
    assert "bloqueada" in context.body_text
    by_name = {attachment.filename: attachment for attachment in context.attachments}
    assert by_name["factura_ñ.pdf"].content == b"%PDF-1.4 fake"
    assert by_name["logo.png"].content_type == "image/png"
    assert "Content-ID: <logo123>" in eml


def test_the_converted_msg_is_judged_like_the_equivalent_eml():
    """La prueba de equivalencia: el mismo correo, como .eml y como .msg,
    recibe el mismo veredicto y el mismo score del motor completo."""
    eml = (_TRANSPORT_HEADERS.replace('multipart/alternative; boundary="original"', "text/html; charset=utf-8")
           + "\r\n" + _HTML + "\r\n")
    msg = build_msg(transport_headers=_TRANSPORT_HEADERS, html=_HTML)

    direct = IrisManager.evaluate_raw(eml)
    converted = IrisManager.evaluate_raw(convert_msg_to_eml(msg))

    assert (converted["verdict"], converted["totalScore"]) == (direct["verdict"], direct["totalScore"])
    assert converted["gateReasons"] == direct["gateReasons"]


# ---------------------------------------------------- borrador o enviado

def test_without_transport_headers_the_basic_headers_are_rebuilt():
    data = build_msg(subject="Reunión mañana", sender_name="Ana Pérez", sender_email="ana@example.org",
                     body="Nos vemos a las diez.", message_id="<m1@example.org>",
                     submitted=datetime(2026, 9, 7, 9, 30, tzinfo=timezone.utc))

    context = parse_raw_message(convert_msg_to_eml(data))

    assert "ana@example.org" in context.headers["from"]
    assert context.headers["message-id"] == "<m1@example.org>"
    assert "07 Sep 2026 09:30:00" in context.headers["date"]
    assert context.body_text.strip() == "Nos vemos a las diez."


def test_an_rtf_only_body_is_turned_into_text():
    data = build_msg(subject="Aviso", sender_email="x@evil.example",
                     rtf=b"{\\rtf1\\ansi Entre en https://evil.example/login ahora\\par}")

    context = parse_raw_message(convert_msg_to_eml(data))

    assert "https://evil.example/login" in context.body_text
    assert [link.href for link in context.links] == ["https://evil.example/login"]


# ------------------------------------------------------------ reenvíos

def test_an_embedded_message_becomes_a_forward_the_parser_unwraps():
    """El «reenviar como adjunto» de Outlook incrusta el .msg original: tiene
    que llegar al parser como message/rfc822 para que se analicen los dos."""
    data = build_msg(
        subject="Fwd: sospechoso", sender_email="empleado@example.com", body="Mira esto.",
        embedded={"transport_headers": _TRANSPORT_HEADERS, "html": _HTML, "subject": "Verificación urgente"},
    )

    context = parse_raw_message(convert_msg_to_eml(data))

    assert context.unwrapped_from_forward
    assert context.headers["from"] == '"Banco Ejemplo" <alertas@evil.example>'
    assert context.wrapper_context is not None


def test_nesting_is_limited():
    embedded = {"subject": "nivel", "body": "x"}
    for _ in range(MAX_EMBEDDING_DEPTH):
        embedded = {"subject": "nivel", "body": "x", "embedded": embedded}

    with pytest.raises(MsgConversionError):
        convert_msg_to_eml(build_msg(subject="raíz", body="x", embedded=embedded))


# -------------------------------------------------------------- errores

def test_what_is_not_a_msg_is_rejected_with_a_clear_message():
    assert not is_msg(b"From: a@b.example\n")
    with pytest.raises(MsgConversionError):
        convert_msg_to_eml(b"From: a@b.example\nSubject: x\n\nhola")
    with pytest.raises(MsgConversionError):
        convert_msg_to_eml(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 100)
    with pytest.raises(MsgConversionError, match="no es un mensaje"):
        convert_msg_to_eml(build_cfb({"WordDocument": b"doc"}))
