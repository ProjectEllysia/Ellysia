"""Evidencia anclada: cada hallazgo dice dónde está o por qué no se puede decir.

Cubre el contrato de ``services/evidence.py`` (tipos, locator, desactivación
de URLs), el envoltorio del registro de reglas que lo aplica, y las reglas de
más peso del catálogo, que tienen que producir evidencia real.
"""

from __future__ import annotations

import base64

import pytest

from src.modules.features.iris.services.evidence import (
    EVIDENCE_ATTACHMENT,
    EVIDENCE_URL,
    MAX_EXCERPT_LENGTH,
    anchor_result,
    defang,
    header_evidence,
    validate_evidence,
)
from src.modules.features.iris.services.parsers import parse_raw_message
from src.modules.features.iris.services.registry import RuleRegistry, RuleResult
from src.modules.features.iris.services.rules import iris_rules

pytestmark = pytest.mark.unit

#: Las reglas de mayor penalización del catálogo (ordenadas por su peso por
#: defecto). El corte en diez cae en un empate a -12, así que se cubren las
#: trece que llegan a ese peso.
_HIGHEST_WEIGHTED_RULES = [
    "Body Links", "QR Code Links", "Suspicious Attachments", "Unicode Evasion",
    "Recipient Domain Lookalike", "DMARC", "Encoded-Word Abuse", "Lookalike Sender Domain",
    "Auth Results Provenance", "Display Name Spoofing", "Domain Alignment",
    "Received Chain Temporal Inconsistency", "Self-Referencing In-Reply-To",
]


def _rule(name: str) -> dict:
    return next(rule_def for rule_def in iris_rules.get_rules() if rule_def["name"] == name)


def _html_message(html: str) -> str:
    return (
        "From: Soporte <soporte@corp.example>\r\nTo: victima@corp.example\r\nSubject: Aviso\r\n"
        "MIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n" + html + "\r\n"
    )


def _message_with_attachment(filename: str, content_type: str = "application/octet-stream",
                             payload: bytes = b"MZ\x90\x00") -> str:
    encoded = base64.b64encode(payload).decode()
    return (
        "From: a@corp.example\r\nTo: b@corp.example\r\nSubject: Factura\r\nMIME-Version: 1.0\r\n"
        "Content-Type: multipart/mixed; boundary=\"B\"\r\n\r\n"
        "--B\r\nContent-Type: text/plain\r\n\r\nAdjunto.\r\n"
        f"--B\r\nContent-Type: {content_type}\r\n"
        f"Content-Disposition: attachment; filename=\"{filename}\"\r\n"
        "Content-Transfer-Encoding: base64\r\n\r\n" + encoded + "\r\n--B--\r\n"
    )


# ------------------------------------------------------------------- defang

def test_defang_neutralises_urls_domains_and_addresses():
    text = defang("Visita https://evil.example.com/login o escribe a jefe@corp.example")
    assert text == "Visita hxxps://evil[.]example[.]com/login o escribe a jefe[@]corp[.]example"


def test_defang_leaves_ip_addresses_readable():
    """Una IP de la cadena Received es evidencia forense, no un enlace."""
    assert defang("from 203.0.113.9") == "from 203.0.113.9"


def test_defang_truncates_long_excerpts():
    excerpt = defang("a" * 1000)
    assert len(excerpt) == MAX_EXCERPT_LENGTH
    assert excerpt.endswith("…")


# ------------------------------------------------------------------- contrato

def test_validate_rejects_unknown_kinds_and_incomplete_locators():
    with pytest.raises(ValueError):
        validate_evidence({"kind": "screenshot", "locator": {}, "excerpt": "x"})
    with pytest.raises(ValueError):
        validate_evidence({"kind": "header", "locator": {"header": "from"}, "excerpt": "x"})
    with pytest.raises(ValueError):
        validate_evidence({"kind": "url", "locator": {}, "excerpt": "x"})
    validate_evidence({"kind": "url", "locator": {"linkIndex": 0}, "excerpt": "x"})


def test_header_evidence_skips_absent_headers_and_lists_every_received_hop():
    context = parse_raw_message(
        "Received: from b.example by c.example; Mon, 1 Jan 2026 10:00:00 +0000\r\n"
        "Received: from a.example by b.example; Mon, 1 Jan 2026 09:00:00 +0000\r\n"
        "From: x@corp.example\r\nSubject: hola\r\n"
    )
    items = header_evidence(context, ("from", "reply-to", "received"))
    assert [(item["locator"]["header"], item["locator"]["occurrence"]) for item in items] == [
        ("from", 0), ("received", 0), ("received", 1),
    ]


def test_a_passing_result_is_left_alone():
    result = RuleResult(score=0, verdict="pass")
    assert anchor_result(result, {"from": "a@corp.example"}, ("from",), "", "X") is result


def test_a_penalty_is_anchored_to_its_declared_headers():
    anchored = anchor_result(RuleResult(score=-5, verdict="fail"),
                             {"from": "Evil <a@evil.example>"}, ("from",), "", "X")
    assert anchored.evidence == [{
        "kind": "header", "locator": {"header": "from", "occurrence": 0},
        "excerpt": "Evil <a[@]evil[.]example>",
    }]


def test_a_penalty_on_absent_headers_says_the_signal_is_their_absence():
    anchored = anchor_result(RuleResult(score=-5, verdict="fail"), {}, ("list-unsubscribe",), "", "X")
    assert anchored.evidence == []
    assert "list-unsubscribe" in anchored.evidence_unavailable_reason


def test_an_unanchorable_rule_carries_its_declared_reason():
    anchored = anchor_result(RuleResult(score=-5, verdict="fail"), {}, (), "Motivo declarado.", "X")
    assert anchored.evidence_unavailable_reason == "Motivo declarado."


def test_invalid_self_provided_evidence_is_rejected():
    with pytest.raises(ValueError):
        anchor_result(RuleResult(score=-5, verdict="fail", evidence=[{"kind": "nope"}]), {}, (), "", "X")


# ------------------------------------------------------------------- registro

def test_a_rule_that_declares_nothing_cannot_be_registered():
    with pytest.raises(ValueError):
        RuleRegistry().register(name="Sin declarar", rule_id="iris.test.sin_declarar", severity="low")


def test_the_registry_anchors_through_its_wrapper_but_returns_the_original():
    registry = RuleRegistry()

    @registry.register(name="Falsa", evidence_headers=("from",), rule_id="iris.test.falsa", severity="low")
    def fake_rule(headers):
        return RuleResult(score=-5, verdict="fail")

    anchored = registry.get_rules()[0]["func"]({"from": "a@evil.example"})
    assert anchored.evidence[0]["locator"] == {"header": "from", "occurrence": 0}
    assert fake_rule({"from": "a@evil.example"}).evidence == []


def test_every_rule_in_the_catalog_declares_how_it_anchors():
    for rule_def in iris_rules.get_rules():
        assert (rule_def["evidence_headers"] or rule_def["is_self_anchoring"]
                or rule_def["unanchorable_reason"]), rule_def["name"]


def test_the_highest_weighted_rules_are_anchorable():
    """El criterio de cierre: las señales de más peso tienen evidencia
    clicable; ninguna se escuda en un motivo de no anclaje."""
    for name in _HIGHEST_WEIGHTED_RULES:
        rule_def = _rule(name)
        assert rule_def["evidence_headers"] or rule_def["is_self_anchoring"], name


# ------------------------------------------------ reglas que se anclan solas

def test_body_links_anchors_the_offending_link():
    context = parse_raw_message(_html_message(
        '<a href="https://corp.example/ok">ok</a> <a href="http://192.168.10.20/login">https://paypal.com</a>'
    ))
    result = _rule("Body Links")["func"](context)
    assert result.score < 0
    assert [item["locator"] for item in result.evidence] == [{"linkIndex": 1}]
    assert result.evidence[0]["excerpt"].startswith("hxxp://192.168.10.20/login")


def test_compromised_legitimate_domain_anchors_the_link():
    context = parse_raw_message(_html_message('<a href="https://legit.example/Ab3dE5fG7hJ9kL2">ver</a>'))
    result = _rule("Compromised Legitimate Domain")["func"](context)
    assert result.score < 0
    assert result.evidence[0]["locator"] == {"linkIndex": 0}


def test_suspicious_attachments_anchors_the_dangerous_attachment():
    context = parse_raw_message(_message_with_attachment("factura.pdf.exe"))
    result = _rule("Suspicious Attachments")["func"](context)
    assert result.score < 0
    item = result.evidence[0]
    assert item["kind"] == EVIDENCE_ATTACHMENT
    assert item["locator"]["attachmentIndex"] == 0
    assert item["locator"]["filename"] == "factura.pdf.exe"
    assert len(item["locator"]["sha256"]) == 64


def test_unicode_evasion_anchors_the_subject_with_a_bidi_control():
    context = parse_raw_message(
        "From: a@corp.example\r\nTo: b@corp.example\r\nSubject: factura‮fdp.exe\r\n\r\nx\r\n"
    )
    result = _rule("Unicode Evasion")["func"](context)
    assert result.score < 0
    assert {"header": "subject", "occurrence": 0} in [item["locator"] for item in result.evidence]


def test_received_temporal_inconsistency_anchors_both_hops():
    raw = (
        "Received: from b.example by c.example; Mon, 1 Jan 2026 10:00:00 +0000\r\n"
        "Received: from a.example by b.example; Mon, 1 Jan 2026 11:00:00 +0000\r\n"
        "From: x@corp.example\r\nSubject: hola\r\n\r\ncuerpo\r\n"
    )
    result = _rule("Received Chain Temporal Inconsistency")["func"](parse_raw_message(raw))
    assert result.score < 0
    assert [item["locator"]["occurrence"] for item in result.evidence] == [0, 1]


def test_qr_code_links_anchors_the_image_and_the_decoded_url():
    cv2 = pytest.importorskip("cv2")
    if not hasattr(cv2, "QRCodeEncoder"):
        pytest.skip("Esta build de OpenCV no trae QRCodeEncoder")
    from src.modules.features.iris.services.rules.body_links_rules import _decode_qr_urls

    url = "http://192.168.10.20/login"
    image = cv2.QRCodeEncoder.create().encode(url)
    image = cv2.resize(image, None, fx=8, fy=8, interpolation=cv2.INTER_NEAREST)
    image = cv2.copyMakeBorder(image, 40, 40, 40, 40, cv2.BORDER_CONSTANT, value=255)
    png = cv2.imencode(".png", image)[1].tobytes()
    if _decode_qr_urls(png) != [url]:
        pytest.skip("OpenCV no decodifica el QR generado en este entorno")

    context = parse_raw_message(_message_with_attachment("qr.png", "image/png", png))
    result = _rule("QR Code Links")["func"](context)

    assert result.score < 0
    assert [(item["kind"], item["locator"].get("source")) for item in result.evidence] == [
        (EVIDENCE_ATTACHMENT, None), (EVIDENCE_URL, "qr_code"),
    ]
