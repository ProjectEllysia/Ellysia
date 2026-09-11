"""Tests unitarios del generador de PDF de informes Iris (``services/reports.py``)."""

from __future__ import annotations

import os
from unittest import mock

import pytest
from reportlab.lib.styles import getSampleStyleSheet

import src.modules.features.iris.services.reports as reports_mod
import src.modules.system.config_reading as CR
from src.modules.features.iris.services.reports import IrisPDFCreator, IrisReportTheme, PALETTE

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
    creator = IrisPDFCreator(report=_sample_report(), document_id=7)
    path = creator.print_pdf()
    assert os.path.exists(path)
    assert os.path.getsize(path) > 0
    assert path.endswith("42_7_Iris.pdf")


def test_two_documents_of_the_same_analysis_do_not_collide():
    """El modelo permite N documentos por análisis, pero el nombre del
    fichero solo dependía del análisis, así que todos escribían el mismo PDF."""
    first = IrisPDFCreator(report=_sample_report(), document_id=1).print_pdf()
    second = IrisPDFCreator(report=_sample_report(), document_id=2).print_pdf()

    assert first != second
    assert os.path.exists(first) and os.path.exists(second)


def test_deleting_one_document_leaves_the_other_intact():
    """El caso que hacía daño de verdad: ``delete_document_with_file`` borra
    por ``filename``, que era el mismo para los dos documentos."""
    first = IrisPDFCreator(report=_sample_report(), document_id=1).print_pdf()
    second = IrisPDFCreator(report=_sample_report(), document_id=2).print_pdf()

    os.remove(first)

    assert not os.path.exists(first)
    assert os.path.exists(second)
    assert os.path.getsize(second) > 0


def test_without_a_document_id_the_name_is_still_unique():
    """Ningún camino de la aplicación llega así, pero la clase sigue siendo
    usable a pelo y no debe reintroducir la colisión por la puerta de atrás."""
    first = IrisPDFCreator(report=_sample_report()).print_pdf()
    second = IrisPDFCreator(report=_sample_report()).print_pdf()

    assert first != second
    assert os.path.exists(first) and os.path.exists(second)


def test_no_temporary_file_survives_a_successful_render(tmp_path):
    """El PDF se escribe en un temporal y se mueve con ``os.replace()``; si el
    temporal sobreviviera, cada informe dejaría basura en el directorio."""
    path = IrisPDFCreator(report=_sample_report(), document_id=3).print_pdf()

    leftovers = [name for name in os.listdir(os.path.dirname(path)) if name.endswith(".tmp")]
    assert leftovers == []


def test_a_failed_render_leaves_neither_temporary_nor_output(tmp_path, monkeypatch):
    """Un fallo a mitad no debe dejar un PDF truncado en la ruta final: el
    lector que lo descargue recibiría un fichero corrupto sin saberlo."""
    import src.modules.features.iris.services.reports as reports_mod

    creator = IrisPDFCreator(report=_sample_report(), document_id=4)
    expected = creator._output_path()

    monkeypatch.setattr(
        reports_mod.SimpleDocTemplate, "build",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("boom")),
    )

    with pytest.raises(RuntimeError):
        creator.print_pdf()

    assert not os.path.exists(expected)
    leftovers = [name for name in os.listdir(str(tmp_path)) if name.endswith(".tmp")]
    assert leftovers == []


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


# ------------------------------------------------ redacción del raw dump

def _theme() -> IrisReportTheme:
    return IrisReportTheme(getSampleStyleSheet(), PALETTE)


def _rendered_raw_headers_text(report: dict) -> str:
    """Llama a append_raw_headers() directamente y concatena el texto de
    cada Paragraph -- más directo que parsear el PDF resultante."""
    creator = IrisPDFCreator(report=report)
    elements: list = []
    creator.append_raw_headers(elements, _theme())
    return "\n".join(el.text for el in elements if hasattr(el, "text"))


def test_raw_headers_dump_redacts_an_unrelated_email_by_default():
    report = _sample_report(rawHeaders=(
        "From: a@b.com\nTo: c@d.com\nSubject: Test\n"
        "Cc: bystander@example.com\n"
    ))
    rendered = _rendered_raw_headers_text(report)

    assert "bystander@example.com" not in rendered


def test_raw_headers_dump_keeps_the_surfaced_addresses():
    report = _sample_report(rawHeaders="From: a@b.com\nTo: c@d.com\nSubject: Test\n")
    rendered = _rendered_raw_headers_text(report)

    assert "a@b.com" in rendered
    assert "c@d.com" in rendered


def test_raw_headers_dump_is_not_redacted_when_disabled_in_config():
    report = _sample_report(rawHeaders=(
        "From: a@b.com\nTo: c@d.com\nSubject: Test\nCc: bystander@example.com\n"
    ))
    with mock.patch.object(
        reports_mod.CR, "iris_config", lambda: CR.IrisConfig(redact_pii_in_reports=False),
    ):
        rendered = _rendered_raw_headers_text(report)

    assert "bystander@example.com" in rendered


# ------------------------------------------------ contexto ganador de un reenvío

def _rendered_preview_text(report: dict) -> str:
    """Llama a append_email_preview() y concatena el texto de los Paragraph,
    tanto sueltos como dentro de las celdas de la tabla de vista previa."""
    creator = IrisPDFCreator(report=report)
    elements: list = []
    creator.append_email_preview(elements, _theme())
    texts = []
    for element in elements:
        if hasattr(element, "text"):
            texts.append(element.text)
        for row in getattr(element, "_cellvalues", []):
            for cell in row:
                texts.append(cell.text if hasattr(cell, "text") else str(cell))
    return "\n".join(texts)


def test_preview_uses_the_winning_context_headers_over_the_raw():
    """La vista previa describe el mensaje que produjo el veredicto, aunque
    el raw empiece por las cabeceras de otro."""
    report = _sample_report(
        rawHeaders="From: original@corp.example\nSubject: Original\n",
        previewHeaders={"subject": "FW: revisa esto", "from": "alerta@evil.example",
                        "to": None, "replyTo": None, "returnPath": None, "date": None},
    )
    text = _rendered_preview_text(report)
    assert "alerta@evil.example" in text
    assert "FW: revisa esto" in text
    assert "original@corp.example" not in text


def test_preview_note_says_the_wrapper_won_and_summarises_the_original():
    report = _sample_report(
        unwrappedFromForward=True, wrapperFrom="alerta@evil.example",
        winningContext="wrapper",
        winningReason="El envoltorio del reenvío (Phishing) es más grave.",
        secondaryContext={"contextType": "inner", "verdict": "Legitimate", "totalScore": 100.0},
    )
    text = _rendered_preview_text(report)
    assert "envoltorio del reenvío" in text
    assert "El otro mensaje (original) obtuvo Legitimate" in text


def test_preview_note_says_the_original_won_by_default():
    report = _sample_report(unwrappedFromForward=True, wrapperFrom="colega@corp.example")
    text = _rendered_preview_text(report)
    assert "correo original reenviado" in text


# ------------------------------------------------ confianza y cobertura

def _rendered_confidence_text(report: dict) -> str:
    creator = IrisPDFCreator(report=report)
    elements: list = []
    creator.append_confidence(elements, _theme())
    texts = []
    for element in elements:
        for row in getattr(element, "_cellvalues", []):
            texts.extend(cell.text for cell in row if hasattr(cell, "text"))
    return "\n".join(texts)


def test_confidence_card_shows_level_coverage_and_reasons_without_a_percentage():
    report = _sample_report(
        confidence="low",
        coverage={"mode": "headers_only", "uncoveredRules": ["Body Links", "Body Content"]},
        uncertaintyReasons=["Solo se analizaron las cabeceras."],
    )
    text = _rendered_confidence_text(report)
    assert "Confianza del análisis: Baja" in text
    assert "no una probabilidad" in text
    assert "solo cabeceras" in text
    assert "Body Links, Body Content" in text
    assert "Solo se analizaron las cabeceras." in text
    assert "%" not in text


def test_confidence_card_is_omitted_for_reports_without_confidence():
    assert _rendered_confidence_text(_sample_report()) == ""
