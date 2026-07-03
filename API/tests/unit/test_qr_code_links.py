"""Tests unitarios de la regla QR Code Links (D1, quishing).

Cubre:
- Sin adjuntos de imagen -> neutral.
- Imagen sin código QR -> pass.
- QR que decodifica a una URL limpia -> pass.
- QR que decodifica a una URL sospechosa (dominio con TLD/typosquat/etc.,
  vía shared.analyze_url) -> fail, mismos tipos de finding que Body Links.
- QR con contenido no-URL (vCard, texto plano) -> ignorado (no es un
  vector de phishing relevante aquí).
"""

from __future__ import annotations

import io

import pytest
import qrcode

from src.modules.iris.services.parsers import Attachment, MessageContext
from src.modules.iris.services.rules.body_links_rules import check_qr_code_links

pytestmark = pytest.mark.unit


def _qr_png_bytes(payload: str) -> bytes:
    img = qrcode.make(payload)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _ctx_with_qr_image(payload: str, filename: str = "flyer.png",
                        from_header: str = "a@b.com") -> MessageContext:
    return MessageContext(
        headers={"from": from_header},
        attachments=[Attachment(
            filename=filename, content_type="image/png",
            size=0, content=_qr_png_bytes(payload),
        )],
    )


def test_neutral_when_no_image_attachments():
    ctx = MessageContext(headers={"from": "a@b.com"}, attachments=[])
    result = check_qr_code_links(ctx)
    assert result.verdict == "neutral"


def test_pass_when_image_has_no_qr_code():
    # A plain (non-QR) image -- decodeable, just no QR pattern in it.
    import numpy as np
    import cv2
    blank = np.zeros((50, 50, 3), dtype=np.uint8)
    ok, buf = cv2.imencode(".png", blank)
    assert ok
    ctx = MessageContext(
        headers={"from": "a@b.com"},
        attachments=[Attachment(filename="logo.png", content_type="image/png",
                                 size=0, content=buf.tobytes())],
    )
    result = check_qr_code_links(ctx)
    assert result.verdict == "pass"
    assert result.details["qr_count"] == 0


def test_pass_when_qr_decodes_to_clean_url():
    ctx = _ctx_with_qr_image("https://some-business.com/notes")
    result = check_qr_code_links(ctx)
    assert result.verdict == "pass"
    assert result.details["qr_count"] == 1


def test_fails_when_qr_decodes_to_shortener_url():
    ctx = _ctx_with_qr_image("http://bit.ly/abc123")
    result = check_qr_code_links(ctx)
    assert result.verdict == "fail"
    assert "shortener" in result.details["types"]
    assert result.details["qr_urls"] == ["http://bit.ly/abc123"]
    assert result.details["findings"][0]["source"] == "qr_code"
    assert result.details["findings"][0]["filename"] == "flyer.png"


def test_fails_when_qr_decodes_to_credential_harvest_path():
    ctx = _ctx_with_qr_image("http://random-host.tk/account/verify")
    result = check_qr_code_links(ctx)
    assert result.verdict == "fail"
    assert "insecure_credential_page" in result.details["types"]


def test_ignores_non_url_qr_payload():
    # A QR encoding plain text (not a URL) isn't a phishing vector here.
    ctx = _ctx_with_qr_image("BEGIN:VCARD\nFN:John Doe\nEND:VCARD")
    result = check_qr_code_links(ctx)
    assert result.verdict == "pass"
    assert result.details["qr_count"] == 0


def test_ignores_non_image_attachments():
    ctx = MessageContext(
        headers={"from": "a@b.com"},
        attachments=[Attachment(filename="doc.pdf", content_type="application/pdf",
                                 size=0, content=b"%PDF-1.4 fake")],
    )
    result = check_qr_code_links(ctx)
    assert result.verdict == "neutral"
