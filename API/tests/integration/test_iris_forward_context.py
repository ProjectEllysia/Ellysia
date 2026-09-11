"""El informe de un reenvío describe el mensaje que produjo el veredicto.

Un reenvío "reportar phishing" trae dos mensajes: el envoltorio y el original
adjunto como ``message/rfc822``. El motor evalúa los dos y se queda con el
peor veredicto. Estos tests fijan que, gane el que gane, el veredicto, el
score, las reglas, la vista previa de cabeceras, la cadena Received y los IOCs
hablan del **mismo** mensaje, y que el otro se conserva como secundario.

Se usa un catálogo mínimo en vez del real: una regla que penaliza cualquier
remitente de ``evil.example`` basta para decidir qué contexto gana sin
depender de los pesos del catálogo, que cambian con cada recalibración.
"""

from __future__ import annotations

from unittest import mock

import pytest

from src.modules.features.iris.managers.analysis import IrisManager
from src.modules.features.iris.model import IrisAnalysis, IrisRuleResult
from src.modules.features.iris.repositories import IrisAnalysisRepository, IrisRuleResultRepository
from src.modules.features.iris.services.contexts import CONTEXT_INNER, CONTEXT_WRAPPER
from src.modules.features.iris.services.registry import RuleResult
from src.modules.features.iris.services.rules import iris_rules
from src.modules.infrastructure import UnitOfWork

pytestmark = pytest.mark.integration

_EVIL_SENDER = "Soporte <alerta@evil.example>"
_BENIGN_SENDER = "Compañero <colega@corp.example>"


def _sender_rule(headers: dict) -> RuleResult:
    """Penaliza con fuerza cualquier remitente de ``evil.example``."""
    if "evil.example" in headers.get("from", ""):
        return RuleResult(score=-60.0, verdict="fail", details={"from": headers.get("from")},
                          recommendation="No responder al remitente.")
    return RuleResult(score=0.0, verdict="pass", details={})


_CATALOG = [{
    "func": _sender_rule, "name": "Sender Test", "category": "identity",
    "description": "", "needs_context": False, "family": "",
}]


def _forward(wrapper_from: str, inner_from: str) -> str:
    """Construye un reenvío con el original adjunto como ``message/rfc822``."""
    return (
        f"From: {wrapper_from}\r\n"
        "To: buzon@corp.example\r\n"
        "Subject: FW: revisa esto\r\n"
        "Date: Mon, 1 Jan 2026 10:00:00 +0000\r\n"
        "Received: from wrapper-relay.example (wrapper-relay.example [198.51.100.7])"
        " by mx.corp.example; Mon, 1 Jan 2026 10:00:00 +0000\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: multipart/mixed; boundary=\"OUTER\"\r\n"
        "\r\n"
        "--OUTER\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "\r\n"
        "<html><body><a href=\"https://wrapper-link.example/x\">abrir</a></body></html>\r\n"
        "--OUTER\r\n"
        "Content-Type: message/rfc822\r\n"
        "Content-Disposition: attachment; filename=\"original.eml\"\r\n"
        "\r\n"
        f"From: {inner_from}\r\n"
        "To: victima@corp.example\r\n"
        "Subject: Original adjunto\r\n"
        "Date: Mon, 1 Jan 2026 09:00:00 +0000\r\n"
        "Received: from inner-relay.example (inner-relay.example [203.0.113.9])"
        " by mx.other.example; Mon, 1 Jan 2026 09:00:00 +0000\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "\r\n"
        "<html><body><a href=\"https://inner-link.example/y\">ver</a></body></html>\r\n"
        "--OUTER--\r\n"
    )


def _analyze(app, user_id: int, raw: str) -> int:
    """Crea el análisis y lo ejecuta como lo haría el worker, con el catálogo mínimo."""
    with app.app_context():
        with UnitOfWork() as uow:
            analysis = IrisAnalysis(raw_headers=raw, user_id=user_id, status="pending")
            IrisAnalysisRepository(uow).save(analysis)
            analysis_id = analysis.id
        with mock.patch.object(iris_rules, "get_rules", return_value=list(_CATALOG)):
            IrisManager()._run_analysis(analysis_id, raw)
    return analysis_id


def _report(app, analysis_id: int, user_id: int) -> tuple[dict, dict, dict]:
    """Informe, IOCs y cadena Received del análisis, tal y como los sirve la API."""
    with app.app_context():
        manager = IrisManager()
        return (
            manager.get_analysis_results(analysis_id),
            manager.get_analysis_iocs(analysis_id, user_id),
            manager.get_analysis_path(analysis_id, user_id),
        )


def test_a_malicious_wrapper_over_a_benign_original_reports_the_wrapper(app, regular_user):
    """El atacante manda su phishing como envoltorio y grapa un ``.eml``
    benigno: el veredicto viene del envoltorio, y todo el informe tiene que
    describir el envoltorio, no el original."""
    analysis_id = _analyze(app, regular_user.id, _forward(_EVIL_SENDER, _BENIGN_SENDER))

    report, iocs, path = _report(app, analysis_id, regular_user.id)

    assert report["verdict"] == "Phishing"
    assert report["totalScore"] == 40.0
    assert report["winningContext"] == CONTEXT_WRAPPER
    assert "envoltorio" in report["winningReason"]
    assert [rule["verdict"] for rule in report["rules"]] == ["fail"]
    assert report["topSignals"][0]["ruleName"] == "Sender Test"
    assert report["previewHeaders"]["from"] == _EVIL_SENDER
    assert report["previewHeaders"]["subject"] == "FW: revisa esto"

    assert report["secondaryContext"]["contextType"] == CONTEXT_INNER
    assert report["secondaryContext"]["verdict"] == "Legitimate"
    assert [rule["verdict"] for rule in report["secondaryContext"]["rules"]] == ["pass"]

    assert iocs["contextType"] == CONTEXT_WRAPPER
    assert "wrapper-link.example" in iocs["domains"]
    assert "inner-link.example" not in iocs["domains"]
    assert "evil.example" in iocs["domains"]

    assert path["contextType"] == CONTEXT_WRAPPER
    assert [hop["fromIp"] for hop in path["hops"]] == ["198.51.100.7"]


def test_a_malicious_original_inside_a_benign_wrapper_reports_the_original(app, regular_user):
    """El caso habitual de "reportar phishing": el envoltorio es el empleado
    que reenvía, el original es el phishing. Todo el informe describe el
    original."""
    analysis_id = _analyze(app, regular_user.id, _forward(_BENIGN_SENDER, _EVIL_SENDER))

    report, iocs, path = _report(app, analysis_id, regular_user.id)

    assert report["verdict"] == "Phishing"
    assert report["winningContext"] == CONTEXT_INNER
    assert "original" in report["winningReason"]
    assert report["previewHeaders"]["from"] == _EVIL_SENDER
    assert report["previewHeaders"]["subject"] == "Original adjunto"
    assert report["secondaryContext"]["contextType"] == CONTEXT_WRAPPER
    assert report["secondaryContext"]["verdict"] == "Legitimate"

    assert iocs["contextType"] == CONTEXT_INNER
    assert "inner-link.example" in iocs["domains"]
    assert "wrapper-link.example" not in iocs["domains"]

    assert [hop["fromIp"] for hop in path["hops"]] == ["203.0.113.9"]


def test_both_contexts_keep_their_own_rule_rows(app, regular_user):
    """Las reglas de los dos mensajes se guardan, cada fila con su contexto,
    y ninguna del secundario se cuela en la lista del ganador."""
    analysis_id = _analyze(app, regular_user.id, _forward(_EVIL_SENDER, _BENIGN_SENDER))

    with app.app_context():
        with UnitOfWork() as uow:
            rows = IrisRuleResultRepository(uow).get_by_analysis(analysis_id)
            by_context = {row.context_type: row.verdict for row in rows}

    assert by_context == {CONTEXT_WRAPPER: "fail", CONTEXT_INNER: "pass"}


def test_a_tie_keeps_the_original_as_the_winner(app, regular_user):
    """Con el mismo veredicto en los dos, se muestra el original: es el que
    el usuario quería analizar al reenviar."""
    analysis_id = _analyze(app, regular_user.id, _forward(_EVIL_SENDER, _EVIL_SENDER))

    report, _, _ = _report(app, analysis_id, regular_user.id)

    assert report["winningContext"] == CONTEXT_INNER
    assert "mismo veredicto" in report["winningReason"]


def test_a_plain_message_has_no_secondary_context(app, regular_user):
    """Sin reenvío solo hay un contexto: el interno, sin motivo ni secundario."""
    raw = (
        f"From: {_EVIL_SENDER}\r\nTo: victima@corp.example\r\nSubject: Hola\r\n"
        "Date: Mon, 1 Jan 2026 10:00:00 +0000\r\n\r\nCuerpo.\r\n"
    )
    analysis_id = _analyze(app, regular_user.id, raw)

    report, _, _ = _report(app, analysis_id, regular_user.id)

    assert report["winningContext"] == CONTEXT_INNER
    assert report["winningReason"] is None
    assert report["secondaryContext"] is None
    assert report["previewHeaders"]["from"] == _EVIL_SENDER


def test_an_analysis_without_stored_context_still_reads_all_its_rules(app, regular_user):
    """Un análisis sin contexto ganador guardado conserva sus filas sin
    marcar: el informe las sigue mostrando todas y describe el interno."""
    with app.app_context():
        with UnitOfWork() as uow:
            analysis = IrisAnalysis(
                raw_headers=_forward(_EVIL_SENDER, _BENIGN_SENDER), user_id=regular_user.id,
                status="finished", verdict="Legitimate", total_score=100.0,
            )
            IrisAnalysisRepository(uow).save(analysis)
            analysis_id = analysis.id
            IrisRuleResultRepository(uow).save(IrisRuleResult(
                analysis_id=analysis_id, rule_name="SPF", category="auth",
                score=0.0, verdict="pass", position=0,
            ))

    report, _, _ = _report(app, analysis_id, regular_user.id)

    assert report["winningContext"] is None
    assert [rule["ruleName"] for rule in report["rules"]] == ["SPF"]
    assert report["previewHeaders"]["from"] == _BENIGN_SENDER
