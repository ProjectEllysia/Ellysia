"""Confianza, cobertura e incertidumbre del veredicto, de punta a punta.

El score de Iris es una escala de riesgo, no una probabilidad, y un análisis
de solo cabeceras ejecutaba las reglas de cuerpo sobre un mensaje vacío sin
decirlo. Estos tests ejecutan el catálogo real como lo haría el worker y
comprueban qué se persiste y qué devuelve la API.
"""

from __future__ import annotations

import pytest

from src.modules.features.iris.managers.analysis import IrisManager
from src.modules.features.iris.model import IrisAnalysis
from src.modules.features.iris.repositories import IrisAnalysisRepository
from src.modules.features.iris.services.quality import (
    CONFIDENCE_LOW,
    COVERAGE_FULL_MESSAGE,
    COVERAGE_HEADERS_ONLY,
)
from src.modules.features.iris.services.rules import iris_rules
from src.modules.infrastructure import UnitOfWork

pytestmark = pytest.mark.integration

_HEADERS = (
    "From: equipo@example.com\r\n"
    "To: destinatario@example.com\r\n"
    "Subject: Acta de la reunión\r\n"
    "Date: Mon, 1 Jan 2026 10:00:00 +0000\r\n"
    "Message-ID: <abc123@example.com>\r\n"
)
_FULL_MESSAGE = _HEADERS + "Content-Type: text/plain\r\n\r\nAdjunto el acta de ayer.\r\n"


def _analyze(app, user_id: int, raw: str) -> int:
    with app.app_context():
        with UnitOfWork() as uow:
            analysis = IrisAnalysis(raw_headers=raw, user_id=user_id, status="pending")
            IrisAnalysisRepository(uow).save(analysis)
            analysis_id = analysis.id
        IrisManager()._run_analysis(analysis_id, raw)
    return analysis_id


def _body_dependent_rule_names() -> list[str]:
    return [rule_def["name"] for rule_def in iris_rules.get_rules() if rule_def["is_body_dependent"]]


def test_a_clean_headers_only_analysis_is_legitimate_with_low_confidence(
        client, app, root_user, root_headers):
    """Un Legítimo de solo cabeceras no puede presentarse con la misma
    seguridad que uno que inspeccionó el contenido: la API lo dice."""
    analysis_id = _analyze(app, root_user.id, _HEADERS)

    response = client.get(f"/iris/results/{analysis_id}", headers=root_headers)

    assert response.status_code == 200
    report = response.get_json()
    assert report["verdict"] == "Legitimate"
    assert report["confidence"] == CONFIDENCE_LOW
    assert report["coverage"]["mode"] == COVERAGE_HEADERS_ONLY
    assert report["coverage"]["uncoveredRules"] == _body_dependent_rule_names()
    assert any("Solo se analizaron las cabeceras" in reason
               for reason in report["uncertaintyReasons"])


def test_a_full_message_analysis_has_full_coverage(client, app, root_user, root_headers):
    analysis_id = _analyze(app, root_user.id, _FULL_MESSAGE)

    report = client.get(f"/iris/results/{analysis_id}", headers=root_headers).get_json()

    assert report["coverage"] == {"mode": COVERAGE_FULL_MESSAGE, "uncoveredRules": []}
    assert report["confidence"] != CONFIDENCE_LOW
    assert not any("cabeceras" in reason for reason in report["uncertaintyReasons"])


def test_the_listing_carries_the_confidence(client, app, root_user, root_headers):
    """El historial también la muestra, para que el triaje no tenga que abrir
    cada análisis para saber cuáles sostienen su veredicto."""
    analysis_id = _analyze(app, root_user.id, _HEADERS)

    listing = client.get("/iris/results", headers=root_headers).get_json()

    item = next(entry for entry in listing["analyses"] if entry["analysisId"] == analysis_id)
    assert item["confidence"] == CONFIDENCE_LOW


def test_an_analysis_without_confidence_serializes_nulls(client, app, root_user, root_headers):
    """Los análisis anteriores a esta columna siguen leyéndose sin error."""
    with app.app_context():
        with UnitOfWork() as uow:
            analysis = IrisAnalysis(raw_headers=_HEADERS, user_id=root_user.id,
                                    status="finished", verdict="Legitimate", total_score=100.0)
            IrisAnalysisRepository(uow).save(analysis)
            analysis_id = analysis.id

    report = client.get(f"/iris/results/{analysis_id}", headers=root_headers).get_json()

    assert report["confidence"] is None
    assert report["coverage"] is None
    assert report["uncertaintyReasons"] == []
