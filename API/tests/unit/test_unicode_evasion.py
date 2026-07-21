"""Tests unitarios de la regla Unicode Evasion (D4).

Cubre:
- Caracteres de control bidireccional (RLO/LRO) en Subject/From/filename.
- Mezcla de scripts confusables (cirílico/griego + latino) en display
  name/subject/dominio.
- Casos limpios (sin Unicode raro) -> pass.

Los caracteres bidi se escriben como escapes ``\\uXXXX`` explícitos, nunca
como glifos literales embebidos en el fuente -- lo contrario sería
precisamente el patrón "Trojan Source" (CVE-2021-42574) que esta misma
regla existe para detectar.
"""

from __future__ import annotations

import pytest

from src.modules.features.iris.services.parsers import Attachment, MessageContext
from src.modules.features.iris.services.rules.body_content_rules import check_unicode_evasion

pytestmark = pytest.mark.unit

RLO = chr(0x202E)


def test_unicode_evasion_passes_on_clean_message():
    ctx = MessageContext(headers={"from": "a@b.com", "subject": "Reunión de mañana"})
    result = check_unicode_evasion(ctx)
    assert result.verdict == "pass"
    assert result.score >= 0


def test_unicode_evasion_flags_rlo_in_subject():
    subject = f"Urgent invoice{RLO}fdp.exe"
    ctx = MessageContext(headers={"from": "a@b.com", "subject": subject})
    result = check_unicode_evasion(ctx)
    assert result.verdict == "fail"
    assert "bidi_control" in result.details["types"]
    assert result.score < 0


def test_unicode_evasion_flags_rlo_in_attachment_filename():
    filename = f"invoice{RLO}fdp.exe"
    ctx = MessageContext(
        headers={"from": "a@b.com", "subject": "Hi"},
        attachments=[Attachment(filename=filename, content_type="application/octet-stream", size=10)],
    )
    result = check_unicode_evasion(ctx)
    assert result.verdict == "fail"
    filename_findings = [f for f in result.details["findings"] if f.get("field") == "filename"]
    assert filename_findings
    assert filename_findings[0]["controls"] == ["RLO"]


def test_unicode_evasion_flags_mixed_cyrillic_latin_display_name():
    # "а" (Cyrillic 'а') mixed with Latin "pple" -> renders like "Apple".
    from_header = "аpple Support <support@aррle-help.com>"
    ctx = MessageContext(headers={"from": from_header, "subject": "Hi"})
    result = check_unicode_evasion(ctx)
    assert result.verdict == "fail"
    assert "mixed_script" in result.details["types"]
    scripts = {f["script"] for f in result.details["findings"] if f["type"] == "mixed_script"}
    assert "cyrillic" in scripts


def test_unicode_evasion_flags_mixed_greek_latin_subject():
    subject = "Verify your αccount now"  # Greek alpha mixed with Latin
    ctx = MessageContext(headers={"from": "a@b.com", "subject": subject})
    result = check_unicode_evasion(ctx)
    assert result.verdict == "fail"
    assert "mixed_script" in result.details["types"]


def test_unicode_evasion_does_not_flag_pure_non_latin_text():
    # Fully Cyrillic (no Latin mixed in) is normal multilingual mail, not
    # a homograph attack -- must not be flagged.
    ctx = MessageContext(headers={"from": "a@b.com", "subject": "Привет команда"})
    result = check_unicode_evasion(ctx)
    assert result.verdict == "pass"
