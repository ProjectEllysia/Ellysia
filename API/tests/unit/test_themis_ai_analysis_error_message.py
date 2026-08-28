"""Unit tests for how the PDF report reacts when the AI writer fails (#118).

``PrintingStrategy._append_ai_analysis`` used to catch every exception the
same way, rendering a generic "No se pudo generar análisis IA" paragraph
regardless of cause. A scan too large for the configured token budget now
gets its own, specific message instead of that generic fallback.
"""

from __future__ import annotations

import types

import pytest
from reportlab.lib.styles import getSampleStyleSheet

import src.modules.system.config_reading as CR
from src.modules.features.themis.services.reports.base import PrintingStrategy
from src.modules.shared.report_theme import ColorType, ReportTheme
from src.modules.tools.scribe import AIPayloadTooLargeError

pytestmark = pytest.mark.unit

_PALETTE = {
    ColorType.BLACK: "#121212", ColorType.DARK: "#333333", ColorType.MAIN: "#014f86",
    ColorType.SECONDARY: "#555b6e", ColorType.LIGHT: "#4a90e2", ColorType.WHITE: "#f5f5f5",
}
_FAKE_PROMPTS = {"nmap": {"system": "Eres un analista.", "userTemplate": "x"}}


class _FakeWriter:
    def __init__(self, exc: Exception):
        self._exc = exc

    def generate(self, scan, **kwargs):
        raise self._exc


class _MinimalPrintingStrategy(PrintingStrategy):
    """The smallest concrete subclass that satisfies the ABC — only
    ``_append_ai_analysis`` (inherited, not overridden) is under test."""

    def append_body(self, theme, elements, ai_report=False):
        raise NotImplementedError

    def get_filename_suffix(self) -> str:
        return "_Test.pdf"

    def get_picture_name(self, dark: bool = True) -> str:
        return "Test"

    def get_report_title(self) -> str:
        return "Test"


def _strategy(exc: Exception) -> _MinimalPrintingStrategy:
    scan = types.SimpleNamespace(id=1, scan_type="nmap")
    strategy = _MinimalPrintingStrategy(scan=scan)
    strategy.writer = _FakeWriter(exc)
    return strategy


def _theme() -> ReportTheme:
    return ReportTheme(getSampleStyleSheet(), _PALETTE)


def _rendered_text(elements: list) -> str:
    return " ".join(el.getPlainText() for el in elements if hasattr(el, "getPlainText"))


def test_payload_too_large_gets_a_specific_message(monkeypatch):
    monkeypatch.setattr(CR, "get_prompts_config", lambda: _FAKE_PROMPTS)
    strategy = _strategy(AIPayloadTooLargeError(estimated_tokens=99999, max_tokens=24000))
    elements: list = []

    strategy._append_ai_analysis(elements, _theme())

    text = _rendered_text(elements)
    assert "demasiados hallazgos" in text
    assert "No se pudo generar análisis IA" not in text


def test_other_failures_keep_the_generic_message(monkeypatch):
    monkeypatch.setattr(CR, "get_prompts_config", lambda: _FAKE_PROMPTS)
    strategy = _strategy(RuntimeError("boom"))
    elements: list = []

    strategy._append_ai_analysis(elements, _theme())

    text = _rendered_text(elements)
    assert "No se pudo generar análisis IA" in text
    assert "demasiados hallazgos" not in text
