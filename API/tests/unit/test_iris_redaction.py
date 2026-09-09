"""Tests unitarios de ``services/redaction.py`` (M09): puro, sin BD."""

from __future__ import annotations

import pytest

from src.modules.features.iris.services.redaction import redact_pii

pytestmark = pytest.mark.unit


def test_redacts_an_email_not_in_keep_list():
    text = "Cc: bystander@example.com se incluyó por error."
    redacted = redact_pii(text)

    assert "bystander@example.com" not in redacted
    assert "@example.com" in redacted  # conserva el dominio


def test_keeps_emails_explicitly_listed():
    text = "From: attacker@evil.tk To: victim@example.com"
    redacted = redact_pii(text, keep_emails=["attacker@evil.tk", "victim@example.com"])

    assert "attacker@evil.tk" in redacted
    assert "victim@example.com" in redacted


def test_keep_emails_comparison_is_case_insensitive():
    text = "From: Attacker@Evil.TK"
    redacted = redact_pii(text, keep_emails=["attacker@evil.tk"])

    assert "Attacker@Evil.TK" in redacted


def test_redacts_a_phone_number():
    text = "Llámame al +34 612-345-678 si tienes dudas."
    redacted = redact_pii(text)

    assert "612-345-678" not in redacted
    assert "[teléfono redactado]" in redacted


def test_redacts_a_credit_card_like_number():
    text = "Tarjeta: 4111 1111 1111 1111 caducidad 12/29"
    redacted = redact_pii(text)

    assert "4111 1111 1111 1111" not in redacted
    assert "[tarjeta redactada]" in redacted


def test_does_not_touch_ip_addresses():
    """Las IPs son evidencia forense (cadena Received), no PII que ocultar."""
    text = "Received: from mail.evil.tk (203.0.113.42)"
    redacted = redact_pii(text)

    assert "203.0.113.42" in redacted


def test_leaves_clean_text_unchanged():
    text = "Subject: Factura pendiente\r\nDate: Mon, 1 Jan 2026 00:00:00 +0000"
    assert redact_pii(text) == text


def test_redacts_multiple_unrelated_emails_in_a_thread():
    text = "To: person1@example.com, person2@example.com, person3@example.com"
    redacted = redact_pii(text, keep_emails=["person1@example.com"])

    assert "person1@example.com" in redacted
    assert "person2@example.com" not in redacted
    assert "person3@example.com" not in redacted
