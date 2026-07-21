"""Tests unitarios de HTMLExporter (aegis) — escapado HTML y validación de URL.

HTMLExporter genera un documento HTML descargable a partir de contenido de un
LLM y de feeds externos (INCIBE/CIRCL): ningún campo de texto ni URL puede
insertarse sin escapar/validar. Son funciones puras: no requieren BD ni red.
"""

import pytest

from src.modules.features.aegis.services.exporters import ExportData, HTMLExporter

pytestmark = pytest.mark.unit


def _export_html(**overrides) -> str:
    defaults = dict(
        subtitle="Titulo",
        company="ACME",
        language="es",
        generated_at="2026-01-01T00:00:00",
    )
    defaults.update(overrides)
    data = ExportData(**defaults)
    return HTMLExporter().export(data).content.decode()


class TestTextEscaping:
    def test_subtitle_script_tag_is_escaped(self):
        html_out = _export_html(subtitle="<script>alert(1)</script>")
        assert "<script>alert(1)</script>" not in html_out
        assert "&lt;script&gt;" in html_out

    def test_company_is_escaped(self):
        html_out = _export_html(company="<b>ACME</b>")
        assert "<b>ACME</b>" not in html_out

    def test_intro_paragraph_is_escaped(self):
        html_out = _export_html(intro="<img src=x onerror=alert(1)>")
        assert "<img src=x onerror=alert(1)>" not in html_out

    def test_closing_paragraph_is_escaped(self):
        html_out = _export_html(closing="<script>alert(1)</script>")
        assert "<script>alert(1)</script>" not in html_out

    def test_tip_headline_and_body_are_escaped(self):
        html_out = _export_html(tips=[{
            "headline": "<script>alert(1)</script>",
            "body": "<img src=x onerror=alert(2)>",
        }])
        assert "<script>alert(1)</script>" not in html_out
        assert "<img src=x onerror=alert(2)>" not in html_out

    def test_alert_title_description_and_source_are_escaped(self):
        html_out = _export_html(alerts=[{
            "title": "<script>alert(1)</script>",
            "description": "<b>desc</b>",
            "sourceLabel": "<i>src</i>",
            "severity": "alta",
            "url": "https://example.com",
        }])
        assert "<script>alert(1)</script>" not in html_out
        assert "<b>desc</b>" not in html_out
        assert "<i>src</i>" not in html_out

    def test_contact_email_is_escaped(self):
        html_out = _export_html(contact_email="<script>alert(1)</script>")
        assert "<script>alert(1)</script>" not in html_out

    def test_language_attribute_is_escaped(self):
        html_out = _export_html(language='"><script>alert(1)</script>')
        assert "<script>alert(1)</script>" not in html_out


class TestUrlSchemeValidation:
    def test_tip_link_javascript_scheme_is_blocked(self):
        html_out = _export_html(tips=[{
            "headline": "h", "body": "b",
            "links": [{"text": "click", "url": "javascript:alert(1)"}],
        }])
        assert "javascript:alert(1)" not in html_out
        assert "href='#'" in html_out

    def test_alert_url_javascript_scheme_is_blocked(self):
        html_out = _export_html(alerts=[{
            "title": "t", "description": "d", "sourceLabel": "s",
            "severity": "alta", "url": "javascript:alert(1)",
        }])
        assert "javascript:alert(1)" not in html_out

    def test_alert_url_data_scheme_is_blocked(self):
        html_out = _export_html(alerts=[{
            "title": "t", "description": "d", "sourceLabel": "s",
            "severity": "alta", "url": "data:text/html,<script>alert(1)</script>",
        }])
        assert "data:text/html" not in html_out

    def test_https_url_is_preserved(self):
        html_out = _export_html(tips=[{
            "headline": "h", "body": "b",
            "links": [{"text": "click", "url": "https://example.com/path"}],
        }])
        assert "href='https://example.com/path'" in html_out

    def test_url_with_quote_cannot_break_out_of_attribute(self):
        html_out = _export_html(tips=[{
            "headline": "h", "body": "b",
            "links": [{"text": "click", "url": "https://example.com/'onmouseover='alert(1)"}],
        }])
        assert "onmouseover=" not in html_out or "&#x27;onmouseover=&#x27;" in html_out
