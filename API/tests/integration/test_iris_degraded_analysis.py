"""B05: una regla rota no puede pasar inadvertida en el informe.

El criterio de cierre del issue pide las tres familias de regla fallida —
autenticación, adjuntos y contenido— con comportamiento conservador. Estos
tests las recorren de punta a punta: rompen una regla real del catálogo,
ejecutan el análisis como lo haría el worker y comprueban qué acaba
persistido y qué se devuelve por API.
"""

from __future__ import annotations

from unittest import mock

import pytest

from src.modules.features.iris.managers.analysis import IrisManager
from src.modules.features.iris.model import IrisAnalysis
from src.modules.features.iris.repositories import IrisAnalysisRepository
from src.modules.features.iris.services.quality import QUALITY_COMPLETE, QUALITY_DEGRADED
from src.modules.features.iris.services.rules import iris_rules
from src.modules.infrastructure import UnitOfWork

pytestmark = pytest.mark.integration


# Un correo sin ninguna señal de phishing: sin romper nada sale Legitimate,
# que es justo el veredicto que la degradación tiene que poder impedir.
_CLEAN_RAW = (
    "From: equipo@example.com\r\n"
    "To: destinatario@example.com\r\n"
    "Subject: Acta de la reunión\r\n"
    "Date: Mon, 1 Jan 2026 10:00:00 +0000\r\n"
    "Message-ID: <abc123@example.com>\r\n"
    "\r\n"
    "Adjunto el acta de ayer.\r\n"
)


def _make_analysis(app, user_id: int) -> int:
    with app.app_context():
        with UnitOfWork() as uow:
            analysis = IrisAnalysis(raw_headers=_CLEAN_RAW, user_id=user_id, status="pending")
            IrisAnalysisRepository(uow).save(analysis)
            return analysis.id


def _reload(app, analysis_id: int) -> IrisAnalysis:
    with app.app_context():
        with UnitOfWork() as uow:
            return IrisAnalysisRepository(uow).get_by_id(analysis_id)


def _run_with_broken_rule(app, analysis_id: int, rule_name: str | None) -> None:
    """Ejecuta el análisis rompiendo una regla concreta del catálogo real.

    Se parchea la función de la regla, no el registro entero: así el resto del
    catálogo se ejecuta de verdad y el test comprueba el comportamiento en un
    análisis completo, no en un laboratorio de una sola regla.
    """
    original_rules = iris_rules.get_rules()
    patched = []
    for rule_def in original_rules:
        if rule_name is not None and rule_def["name"] == rule_name:
            broken = dict(rule_def)
            broken["func"] = mock.Mock(side_effect=RuntimeError("regla rota"))
            patched.append(broken)
        else:
            patched.append(rule_def)

    with app.app_context():
        with mock.patch.object(iris_rules, "get_rules", return_value=patched):
            IrisManager()._run_analysis(analysis_id, _CLEAN_RAW)


def _rule_name_in_family(family: str) -> str:
    for rule_def in iris_rules.get_rules():
        if rule_def.get("family") == family:
            return rule_def["name"]
    raise AssertionError(f"el catálogo no tiene ninguna regla de familia {family!r}")


def test_a_clean_message_is_legitimate_and_complete(app, regular_user):
    """Punto de partida: sin romper nada, este correo sale limpio. Sin esto,
    los tests de abajo no probarían nada — un Suspicious podría venir del
    propio mensaje en vez de la degradación."""
    analysis_id = _make_analysis(app, regular_user.id)

    _run_with_broken_rule(app, analysis_id, None)

    analysis = _reload(app, analysis_id)
    assert analysis.status == "finished"
    assert analysis.verdict == "Legitimate"
    assert analysis.analysis_quality == QUALITY_COMPLETE
    assert analysis.failed_rules is None
    assert analysis.detector_version


def test_a_broken_auth_rule_blocks_the_clean_verdict(app, regular_user):
    """Si la regla que decide si el mensaje está autenticado no se ejecutó,
    presentarlo como limpio es afirmar algo que nadie comprobó."""
    analysis_id = _make_analysis(app, regular_user.id)
    broken = _rule_name_in_family("auth")

    _run_with_broken_rule(app, analysis_id, broken)

    analysis = _reload(app, analysis_id)
    assert analysis.analysis_quality == QUALITY_DEGRADED
    assert analysis.verdict == "Suspicious"
    assert [rule["name"] for rule in analysis.failed_rules] == [broken]
    assert any("no puede ser Legítimo" in reason for reason in analysis.gate_reasons)


def test_a_broken_attachment_rule_blocks_the_clean_verdict(app, regular_user):
    """Mismo razonamiento: nadie miró lo que el mensaje trae dentro."""
    analysis_id = _make_analysis(app, regular_user.id)
    broken = _rule_name_in_family("attachment")

    _run_with_broken_rule(app, analysis_id, broken)

    analysis = _reload(app, analysis_id)
    assert analysis.analysis_quality == QUALITY_DEGRADED
    assert analysis.verdict == "Suspicious"


def test_a_broken_content_rule_degrades_but_keeps_the_verdict(app, regular_user):
    """Las reglas de contenido son muchas y solapadas: perder una degrada la
    confianza, pero no ciega el análisis del mismo modo."""
    analysis_id = _make_analysis(app, regular_user.id)
    broken = _rule_name_in_family("content")

    _run_with_broken_rule(app, analysis_id, broken)

    analysis = _reload(app, analysis_id)
    assert analysis.analysis_quality == QUALITY_DEGRADED
    assert analysis.verdict == "Legitimate"
    assert [rule["name"] for rule in analysis.failed_rules] == [broken]
    # El aviso sí aparece, aunque el veredicto no cambie.
    assert any("Análisis degradado" in reason for reason in analysis.gate_reasons)


def test_the_report_exposes_the_degradation(client, app, regular_user, auth_headers):
    """El frontend y el PDF leen esto: si no viaja por API, no hay forma de
    enseñar la degradación en ningún sitio."""
    analysis_id = _make_analysis(app, regular_user.id)
    broken = _rule_name_in_family("auth")

    _run_with_broken_rule(app, analysis_id, broken)

    response = client.get(f"/iris/results/{analysis_id}",
                          headers=auth_headers(regular_user))

    assert response.status_code == 200
    body = response.get_json()
    assert body["analysisQuality"] == QUALITY_DEGRADED
    assert [rule["name"] for rule in body["failedRules"]] == [broken]
    assert body["detectorVersion"].startswith("iris-rules:")
