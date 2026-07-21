"""Tests unitarios del parser de cabeceras de correo (Iris)."""

import pytest

from src.modules.features.iris.services.parsers import parse_raw_headers

pytestmark = pytest.mark.unit


def test_parses_simple_headers():
    raw = "From: alice@example.com\nSubject: Hello world"
    headers = parse_raw_headers(raw)
    assert headers["from"] == "alice@example.com"
    assert headers["subject"] == "Hello world"


def test_keys_are_lowercased():
    headers = parse_raw_headers("FROM: a@b.com\nSUBJECT: Hi")
    assert "from" in headers
    assert "subject" in headers


def test_folds_continuation_lines():
    raw = "Received: from mail.example.com\n\tby mx.local with ESMTP"
    headers = parse_raw_headers(raw)
    assert headers["received"] == "from mail.example.com by mx.local with ESMTP"


def test_handles_crlf_line_endings():
    raw = "From: a@b.com\r\nSubject: Test\r\n"
    headers = parse_raw_headers(raw)
    assert headers["from"] == "a@b.com"
    assert headers["subject"] == "Test"


def test_last_occurrence_wins_for_duplicates():
    raw = "X-Spam: no\nX-Spam: yes"
    headers = parse_raw_headers(raw)
    assert headers["x-spam"] == "yes"


def test_empty_input_returns_empty_dict():
    assert parse_raw_headers("") == {}
