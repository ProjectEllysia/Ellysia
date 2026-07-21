"""Tests unitarios del generador de PDF de informes Iris (``services/reports.py``)."""

from __future__ import annotations

import os

import pytest

from src.modules.features.iris.services.reports import IrisPDFCreator

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _redirect_output_dir(tmp_path, monkeypatch):
    """Evita escribir PDFs de prueba en el directorio real de salida."""
    import src.modules.features.iris.services.reports as reports_mod
    monkeypatch.setattr(
        reports_mod.CR, "get_directory_of", lambda *_args, **_kwargs: str(tmp_path)
    )


def _sample_report(**overrides):
    report = {
        "analysisId": 42,
        "title": "Correo de prueba",
        "status": "finished",
        "rawHeaders": "From: a@b.com\nTo: c@d.com\nSubject: Test\n",
        "totalScore": -25,
        "verdict": "Phishing",
        "startedAt": "2026-06-27T10:00:00",
        "finishedAt": "2026-06-27T10:01:00",
        "user": "tester",
        "rules": [
            {
                "ruleName": "SPF", "category": "authentication", "score": -10,
                "verdict": "fail", "details": {"domain": "x.com"},
                "recommendation": "Revisar el registro SPF del dominio.",
            },
            {
                "ruleName": "DKIM", "category": "authentication", "score": 5,
                "verdict": "pass", "details": {}, "recommendation": None,
            },
        ],
        "recommendations": ["Revisar el registro SPF del dominio."],
    }
    report.update(overrides)
    return report


def test_print_pdf_creates_a_file():
    creator = IrisPDFCreator(report=_sample_report())
    path = creator.print_pdf()
    assert os.path.exists(path)
    assert os.path.getsize(path) > 0
    assert path.endswith("42_Iris.pdf")


def test_print_pdf_without_path_data_does_not_fail():
    creator = IrisPDFCreator(report=_sample_report(), path=None)
    path = creator.print_pdf()
    assert os.path.exists(path)


def test_print_pdf_with_received_path():
    path_data = {
        "analysisId": 42,
        "available": True,
        "hopsCount": 2,
        "hops": [
            {"hop": 1, "from": "mx1.example.com", "fromIp": "1.2.3.4", "tls": True, "timestamp": "2026-06-27T09:58:00"},
            {"hop": 2, "from": "mx2.example.com", "fromIp": "5.6.7.8", "tls": False, "timestamp": "2026-06-27T09:59:00"},
        ],
        "transitions": [
            {"from": 1, "to": 2, "delayMs": 1000, "suspicious": True, "reasons": ["tls_downgrade"]},
        ],
    }
    creator = IrisPDFCreator(report=_sample_report(), path=path_data)
    output_path = creator.print_pdf()
    assert os.path.exists(output_path)


def test_print_pdf_with_no_rules_or_recommendations():
    report = _sample_report(rules=[], recommendations=[])
    creator = IrisPDFCreator(report=report)
    path = creator.print_pdf()
    assert os.path.exists(path)


def test_print_pdf_with_legitimate_verdict():
    report = _sample_report(verdict="Legitimate", totalScore=15, rules=[
        {"ruleName": "SPF", "category": "authentication", "score": 5, "verdict": "pass", "details": {}, "recommendation": None},
    ], recommendations=[])
    creator = IrisPDFCreator(report=report)
    path = creator.print_pdf()
    assert os.path.exists(path)
