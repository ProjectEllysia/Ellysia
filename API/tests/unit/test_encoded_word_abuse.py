"""Tests unitarios de la regla Encoded-Word Abuse (D5).

Cubre:
- Bloques encoded-word (RFC 2047) encadenados y atomizados -> evasión de
  filtros de keywords.
- Charset exótico (UTF-7) -> vector de evasión histórico.
- Charsets mezclados dentro de la misma cabecera.
- Contenido que solo se revela como URL tras decodificar.
- Casos limpios (sin encoded-words, o pocos bloques largos legítimos).
"""

from __future__ import annotations

import pytest

from src.modules.iris.services.rules.body_content_rules import check_encoded_word_abuse

pytestmark = pytest.mark.unit


def test_passes_when_no_encoded_words():
    result = check_encoded_word_abuse({"subject": "Reunión de mañana", "from": "a@b.com"})
    assert result.verdict == "pass"


def test_passes_on_single_legitimate_encoded_block():
    # One long block for a genuinely accented subject -- normal, not evasion.
    result = check_encoded_word_abuse({
        "subject": "=?utf-8?B?UmV1bmnDs24gZGUgcHJveWVjdG8gcGFyYSBtYcOxYW5h?=",
        "from": "a@b.com",
    })
    assert result.verdict == "pass"


def test_flags_chained_atomized_encoded_words():
    subject = (
        "=?utf-8?Q?ve?= =?utf-8?Q?ri?= =?utf-8?Q?fy?= "
        "=?utf-8?Q?no?= =?utf-8?Q?w?="
    )
    result = check_encoded_word_abuse({"subject": subject, "from": "a@b.com"})
    assert result.verdict == "fail"
    assert "chained_encoded_words" in result.details["types"]


def test_flags_exotic_utf7_charset():
    result = check_encoded_word_abuse({
        "subject": "=?utf-7?Q?Some+ADw-thing?=",
        "from": "a@b.com",
    })
    assert result.verdict == "fail"
    assert "exotic_charset" in result.details["types"]


def test_flags_mixed_charsets_in_same_header():
    subject = "=?iso-8859-1?Q?abc?= =?windows-1252?Q?def?="
    result = check_encoded_word_abuse({"subject": subject, "from": "a@b.com"})
    assert result.verdict == "fail"
    assert "mixed_charsets" in result.details["types"]


def test_flags_url_revealed_only_after_decoding():
    # Base64 of "Please visit http://evil.example.com/login" -- the raw
    # header has no visible "http" substring.
    subject = "=?utf-8?B?UGxlYXNlIHZpc2l0IGh0dHA6Ly9ldmlsLmV4YW1wbGUuY29tL2xvZ2lu?="
    result = check_encoded_word_abuse({"subject": subject, "from": "a@b.com"})
    assert result.verdict == "fail"
    assert "decoded_reveals_url" in result.details["types"]


def test_does_not_flag_visible_url_already_in_raw_header():
    # The URL sits in plain text alongside an unrelated encoded-word block
    # -- already visible in the raw header, so this specific signal (which
    # only fires when decoding *reveals* a hidden URL) must not trigger.
    subject = "Check http://legit.com =?utf-8?B?w6nDqHRlc3Q=?="
    result = check_encoded_word_abuse({"subject": subject, "from": "a@b.com"})
    types = result.details.get("types", [])
    assert "decoded_reveals_url" not in types
