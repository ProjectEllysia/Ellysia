"""OCR local de imágenes: los límites del servicio y la regla que lo usa.

Tesseract no está —ni tiene por qué estar— en la máquina de los tests: el
motor se sustituye en su costura (``find_engine`` y ``subprocess.run`` del
servicio, o ``extract_text`` en la regla) y lo que se prueba es lo que Iris
hace a su alrededor: qué le llega al motor, qué no le llega nunca y qué se
hace con el texto que devuelve.
"""

from __future__ import annotations

import io
import subprocess
from unittest import mock

import cv2
import pytest
from PIL import Image

import src.modules.system.config_reading as CR
from src.modules.features.iris.services import ocr
from src.modules.features.iris.services.ocr import (
    OCR_FAILED,
    OCR_NO_ENGINE,
    OCR_NOT_IMAGE,
    OCR_OK,
    OCR_TIMEOUT,
    OCR_TOO_LARGE,
    OcrResult,
    extract_text,
)
from src.modules.features.iris.services.parsers import Attachment, MessageContext
from src.modules.features.iris.services.rules import body_content_rules
from src.modules.features.iris.services.rules.body_content_rules import check_image_text_phishing
from src.modules.features.iris.services.rules.body_links_rules import check_qr_code_links

pytestmark = pytest.mark.unit

_ENGINE = "/usr/bin/tesseract"


def _image(width: int = 120, height: int = 40, image_format: str = "PNG") -> bytes:
    buffer = io.BytesIO()
    Image.new("RGB", (width, height), "white").save(buffer, format=image_format)
    return buffer.getvalue()


def _extract(data: bytes, **overrides) -> OcrResult:
    return extract_text(data, **{"languages": "spa+eng", "max_pixels": 1_000_000, "timeout_seconds": 10, **overrides})


@pytest.fixture
def engine(monkeypatch):
    """Tesseract «instalado»: el mock es ``subprocess.run``."""
    run = mock.Mock(return_value=subprocess.CompletedProcess([], 0, stdout=b"Hola mundo\n", stderr=b""))
    monkeypatch.setattr(ocr, "find_engine", lambda: _ENGINE)
    monkeypatch.setattr(ocr.subprocess, "run", run)
    return run


# ------------------------------------------------------------- servicio

def test_the_engine_only_ever_sees_a_reencoded_png(engine):
    result = _extract(_image(image_format="JPEG"))

    assert result == OcrResult(OCR_OK, "Hola mundo")
    args, kwargs = engine.call_args
    assert args[0] == [_ENGINE, "stdin", "stdout", "-l", "spa+eng"]
    assert kwargs["input"].startswith(b"\x89PNG")
    assert kwargs["timeout"] == 10


def test_an_image_over_the_pixel_limit_never_reaches_the_engine(engine):
    """El tamaño se lee de la cabecera, sin decodificar: una imagen enorme
    se rechaza antes de ocupar memoria."""
    assert _extract(_image(2000, 1000), max_pixels=1_000_000).status == OCR_TOO_LARGE
    engine.assert_not_called()


def test_what_is_not_an_image_never_reaches_the_engine(engine):
    assert _extract(b"%PDF-1.4 no soy una imagen").status == OCR_NOT_IMAGE
    engine.assert_not_called()


def test_without_tesseract_installed(monkeypatch):
    monkeypatch.setattr(ocr, "find_engine", lambda: None)

    assert _extract(_image()) == OcrResult(OCR_NO_ENGINE)


def test_a_slow_engine_is_cut(engine):
    engine.side_effect = subprocess.TimeoutExpired("tesseract", 10)

    assert _extract(_image()).status == OCR_TIMEOUT


def test_an_engine_error_is_reported(engine):
    engine.return_value = subprocess.CompletedProcess([], 1, stdout=b"", stderr=b"Failed loading language 'spa'")

    assert _extract(_image()) == OcrResult(OCR_FAILED)


# ---------------------------------------------------------------- regla

def _config(monkeypatch, **fields):
    config = CR.IrisOcrConfig(**{"min_image_bytes": 0, **fields})
    monkeypatch.setattr(CR, "iris_ocr_config", lambda: config)


def _message(*images: bytes, sender: str = "avisos@evil.example") -> MessageContext:
    return MessageContext(headers={"from": sender}, attachments=[
        Attachment(filename=f"imagen{index}.png", content_type="image/png", size=len(data), content=data)
        for index, data in enumerate(images)
    ])


def _ocr_reads(monkeypatch, *results) -> mock.Mock:
    """La regla «lee» estas imágenes: textos (``OCR_OK``) u ``OcrResult``."""
    calls = mock.Mock(side_effect=[result if isinstance(result, OcrResult) else OcrResult(OCR_OK, result)
                                   for result in results])
    monkeypatch.setattr(body_content_rules, "extract_text", calls)
    return calls


def test_phishing_text_inside_an_image_fails_the_rule(monkeypatch):
    _config(monkeypatch)
    _ocr_reads(monkeypatch, "PayPal - Acción requerida\nYour account will be suspended. "
                            "Verify your password at http://198.51.100.7/login\nDudas: soporte@evil.example")

    result = check_image_text_phishing(_message(_image()))

    assert result.verdict == "fail" and result.score < 0
    assert {finding["type"] for finding in result.details["findings"]} == {
        "credential_request", "urgency", "brand_impersonation", "suspicious_url",
    }
    assert result.evidence[0]["locator"]["attachmentIndex"] == 0
    excerpt = result.details["ocr_texts"][0]["text"]
    assert "soporte@evil.example" not in excerpt and "@evil.example" in excerpt


def test_a_brand_named_from_its_own_domain_is_not_impersonation(monkeypatch):
    _config(monkeypatch)
    _ocr_reads(monkeypatch, "PayPal: verify your password")

    result = check_image_text_phishing(_message(_image(), sender="service@paypal.com"))

    assert {finding["type"] for finding in result.details["findings"]} == {"credential_request"}


def test_a_brand_alone_is_not_a_finding(monkeypatch):
    """Nombrar una marca en una imagen es corriente (un banner, un medio de
    pago); solo cuenta junto a una petición de credenciales."""
    _config(monkeypatch)
    _ocr_reads(monkeypatch, "Paga con PayPal en nuestra tienda")

    assert check_image_text_phishing(_message(_image())).verdict == "pass"


def test_an_image_without_text_passes(monkeypatch):
    _config(monkeypatch)
    _ocr_reads(monkeypatch, "")

    result = check_image_text_phishing(_message(_image()))

    assert result.verdict == "pass"
    assert result.details["ocr_texts"] == []


def test_a_qr_only_image_is_left_to_the_qr_rule(monkeypatch):
    """Un QR no tiene texto que leer: el OCR no aporta nada y la URL la
    decodifica, y la juzga, la regla de QR. Ninguna de las dos la cuenta dos veces."""
    _config(monkeypatch)
    _ocr_reads(monkeypatch, "")
    qr = cv2.QRCodeEncoder.create().encode("http://198.51.100.7/login")
    qr = cv2.resize(qr, None, fx=10, fy=10, interpolation=cv2.INTER_NEAREST)
    message = _message(cv2.imencode(".png", qr)[1].tobytes())

    assert check_image_text_phishing(message).verdict == "pass"
    assert check_qr_code_links(message).details["qr_urls"] == ["http://198.51.100.7/login"]


def test_without_tesseract_the_rule_is_neutral(monkeypatch):
    _config(monkeypatch)
    _ocr_reads(monkeypatch, OcrResult(OCR_NO_ENGINE))

    result = check_image_text_phishing(_message(_image()))

    assert (result.verdict, result.details["ocr"]) == ("neutral", OCR_NO_ENGINE)


def test_disabled_ocr_reads_nothing(monkeypatch):
    _config(monkeypatch, enabled=False)
    calls = _ocr_reads(monkeypatch)

    assert check_image_text_phishing(_message(_image())).verdict == "neutral"
    calls.assert_not_called()


def test_small_images_are_not_read(monkeypatch):
    """Píxeles de seguimiento, iconos y separadores no llevan texto."""
    _config(monkeypatch, min_image_bytes=100_000)
    calls = _ocr_reads(monkeypatch)

    assert check_image_text_phishing(_message(_image())).details["ocr"] == "no_images"
    calls.assert_not_called()


def test_only_the_first_images_are_read(monkeypatch):
    _config(monkeypatch, max_images=2)
    calls = _ocr_reads(monkeypatch, "", "")

    check_image_text_phishing(_message(_image(), _image(), _image(), _image()))

    assert calls.call_count == 2


def test_the_stored_excerpt_is_short(monkeypatch):
    _config(monkeypatch)
    _ocr_reads(monkeypatch, "texto " * 500)

    assert len(check_image_text_phishing(_message(_image())).details["ocr_texts"][0]["text"]) <= 400
