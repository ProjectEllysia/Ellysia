"""Calidad del análisis — qué se inspeccionó de verdad y qué no.

Una regla que revienta se convertía en un ``RuleResult(verdict="error")`` y
ahí se acababa todo: el análisis podía terminar como ``Legitimate`` sin
ninguna advertencia, aunque la regla que faltó fuera la que decide si el
mensaje está autenticado. Estos tests fijan la política conservadora que lo
sustituye, que depende de **qué familia** de regla se perdió.
"""

from __future__ import annotations

import pytest

from src.modules.features.iris.services.quality import (
    QUALITY_COMPLETE,
    QUALITY_DEGRADED,
    assess_quality,
    cap_verdict,
    detector_version,
)
from src.modules.features.iris.services.rules import RuleResult

pytestmark = pytest.mark.unit


def _rule(name: str, family: str = "", category: str = "header_analysis") -> dict:
    return {"name": name, "family": family, "category": category}


def _ok(score: float = 0.0) -> RuleResult:
    return RuleResult(score=score, verdict="pass")


def _errored() -> RuleResult:
    """Lo que el motor pone cuando una regla lanza una excepción."""
    return RuleResult(score=0, verdict="error", details={"error": "boom"})


# ---------------------------------------------------------------------------
# assess_quality
# ---------------------------------------------------------------------------

def test_all_rules_executed_is_complete():
    rules = [_rule("SPF", "auth"), _rule("Body Links", "links")]
    quality = assess_quality(rules, [_ok(), _ok()])

    assert quality.quality == QUALITY_COMPLETE
    assert quality.failed_rules == []
    assert quality.blocks_clean_verdict is False


def test_a_broken_rule_degrades_and_is_recorded():
    rules = [_rule("SPF", "auth"), _rule("Body Links", "links")]
    quality = assess_quality(rules, [_ok(), _errored()])

    assert quality.quality == QUALITY_DEGRADED
    assert quality.failed_rules == [
        {"name": "Body Links", "family": "links", "category": "header_analysis"}
    ]


def test_a_rule_that_merely_found_something_is_not_a_failure():
    """La distinción que da nombre al campo: una regla que puntúa negativo
    hizo su trabajo. Solo cuenta como fallida la que no llegó a ejecutarse."""
    rules = [_rule("SPF", "auth")]
    quality = assess_quality(rules, [RuleResult(score=-12, verdict="fail")])

    assert quality.quality == QUALITY_COMPLETE


# ---------------------------------------------------------------------------
# Política por familia
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("family", ["auth", "attachment"])
def test_losing_auth_or_attachment_blocks_a_clean_verdict(family):
    """Son las dos familias que responden a una pregunta que ninguna otra
    responde: si faltan, el silencio no es un dato — es no haber mirado."""
    rules = [_rule("Regla", family)]
    quality = assess_quality(rules, [_errored()])

    verdict, reasons = cap_verdict("Legitimate", quality)

    assert quality.blocks_clean_verdict is True
    assert verdict == "Suspicious"
    assert any("no puede ser Legítimo" in reason for reason in reasons)


def test_losing_a_content_rule_degrades_without_changing_the_verdict():
    """Las familias de contenido son muchas y cada una individualmente
    pequeña: perder una degrada la confianza, pero las demás siguen mirando
    el mismo mensaje desde ángulos parecidos."""
    rules = [_rule("Alarming Keywords", "content")]
    quality = assess_quality(rules, [_errored()])

    verdict, reasons = cap_verdict("Legitimate", quality)

    assert quality.is_degraded
    assert quality.blocks_clean_verdict is False
    assert verdict == "Legitimate"
    assert reasons  # pero el aviso de degradación sí aparece


def test_cap_never_improves_a_verdict():
    """Mismo contrato que los gates existentes: solo pueden empeorar."""
    rules = [_rule("SPF", "auth")]
    quality = assess_quality(rules, [_errored()])

    assert cap_verdict("Phishing", quality)[0] == "Phishing"
    assert cap_verdict("Suspicious", quality)[0] == "Suspicious"


def test_complete_analysis_adds_no_reasons():
    quality = assess_quality([_rule("SPF", "auth")], [_ok()])

    assert cap_verdict("Legitimate", quality) == ("Legitimate", [])


# ---------------------------------------------------------------------------
# detector_version
# ---------------------------------------------------------------------------

def test_detector_version_is_stable_across_ordering():
    """Reordenar el registro no cambia el catálogo, así que no debe cambiar
    la marca; si lo hiciera, dos informes idénticos parecerían distintos."""
    a = [_rule("SPF"), _rule("DKIM"), _rule("DMARC")]
    b = [_rule("DMARC"), _rule("SPF"), _rule("DKIM")]

    assert detector_version(a) == detector_version(b)


def test_detector_version_changes_when_the_catalogue_changes():
    base = [_rule("SPF"), _rule("DKIM")]

    assert detector_version(base) != detector_version(base + [_rule("ARC Chain")])
    assert detector_version(base) != detector_version([_rule("SPF"), _rule("DKIM v2")])


def test_detector_version_fits_the_column():
    """La columna son 64 caracteres; con 48 reglas debe caber de sobra."""
    rules = [_rule(f"Regla número {i} con nombre largo") for i in range(200)]

    assert len(detector_version(rules)) <= 64


# ------------------------------------------------ cobertura y confianza

import inspect
import re

from src.modules.features.iris.services.contexts import ContextEvaluation
from src.modules.features.iris.services.parsers import parse_raw_message
from src.modules.features.iris.services.quality import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    COVERAGE_FULL_MESSAGE,
    COVERAGE_HEADERS_ONLY,
    AnalysisQuality,
    assess_confidence,
    assess_coverage,
)
from src.modules.features.iris.services.rules import iris_rules

_HEADERS_ONLY = "From: a@corp.example\r\nTo: b@corp.example\r\nSubject: Hola\r\n"
_FULL_MESSAGE = _HEADERS_ONLY + "Content-Type: text/plain\r\n\r\nCuerpo del mensaje.\r\n"


def _evaluation(verdict="Legitimate", score=100.0, mode=COVERAGE_FULL_MESSAGE,
                quality=None, context_type="inner"):
    return ContextEvaluation(
        context_type=context_type, verdict=verdict, total_score=score, gate_reasons=[],
        results=[], quality=quality or AnalysisQuality(quality=QUALITY_COMPLETE),
        coverage={"mode": mode, "uncoveredRules": ["Body Links"] if mode == COVERAGE_HEADERS_ONLY else []},
    )


def test_headers_only_coverage_lists_the_body_dependent_rules():
    rules_defs = [_rule("Body Links") | {"is_body_dependent": True}, _rule("SPF")]
    coverage = assess_coverage(parse_raw_message(_HEADERS_ONLY), rules_defs)
    assert coverage == {"mode": COVERAGE_HEADERS_ONLY, "uncoveredRules": ["Body Links"]}


def test_a_message_with_a_body_has_full_coverage():
    rules_defs = [_rule("Body Links") | {"is_body_dependent": True}]
    coverage = assess_coverage(parse_raw_message(_FULL_MESSAGE), rules_defs)
    assert coverage == {"mode": COVERAGE_FULL_MESSAGE, "uncoveredRules": []}


def test_a_clean_full_analysis_has_high_confidence_and_no_reasons():
    assessment = assess_confidence(_evaluation(), None, 80, 55)
    assert assessment.level == CONFIDENCE_HIGH
    assert assessment.reasons == []


def test_a_legitimate_verdict_on_headers_only_is_low_confidence():
    """Un Legítimo sin contenido que mirar no dice que el mensaje sea seguro."""
    assessment = assess_confidence(_evaluation(mode=COVERAGE_HEADERS_ONLY), None, 80, 55)
    assert assessment.level == CONFIDENCE_LOW
    assert any("Solo se analizaron las cabeceras" in reason for reason in assessment.reasons)


def test_a_phishing_verdict_on_headers_only_is_only_medium():
    """Las cabeceras bastaron para ver phishing: falta contenido, pero el
    veredicto no afirma nada que no se haya comprobado."""
    assessment = assess_confidence(
        _evaluation(verdict="Phishing", score=20.0, mode=COVERAGE_HEADERS_ONLY), None, 80, 55,
    )
    assert assessment.level == CONFIDENCE_MEDIUM


def test_a_blocking_degradation_is_low_and_a_minor_one_is_medium():
    blocking = AnalysisQuality(quality=QUALITY_DEGRADED, failed_rules=[{"name": "SPF"}],
                               blocks_clean_verdict=True)
    minor = AnalysisQuality(quality=QUALITY_DEGRADED, failed_rules=[{"name": "Generic Greeting"}])
    assert assess_confidence(_evaluation(verdict="Suspicious", score=70.0, quality=blocking),
                             None, 80, 55).level == CONFIDENCE_LOW
    assert assess_confidence(_evaluation(verdict="Suspicious", score=70.0, quality=minor),
                             None, 80, 55).level == CONFIDENCE_MEDIUM


def test_a_score_next_to_a_threshold_is_medium():
    assessment = assess_confidence(_evaluation(score=82.0), None, 80, 55)
    assert assessment.level == CONFIDENCE_MEDIUM
    assert any("umbral 80" in reason for reason in assessment.reasons)


def test_a_gated_verdict_is_not_borderline_even_near_a_threshold():
    """Si un gate decidió el veredicto, que el score esté cerca de un umbral
    no lo hace frágil: cambiar el score no lo cambiaría."""
    assessment = assess_confidence(_evaluation(verdict="Phishing", score=82.0), None, 80, 55)
    assert assessment.level == CONFIDENCE_HIGH


def test_a_forward_whose_messages_disagree_is_medium():
    secondary = _evaluation(verdict="Legitimate", context_type="wrapper")
    assessment = assess_confidence(_evaluation(verdict="Phishing", score=20.0), secondary, 80, 55)
    assert assessment.level == CONFIDENCE_MEDIUM
    assert any("no coinciden" in reason for reason in assessment.reasons)


_BODY_ACCESS_RE = re.compile(r"\.(body_text|body_html|links|attachments)\b")


def test_every_rule_that_reads_the_body_declares_it():
    """``is_body_dependent`` alimenta la cobertura: si una regla lee cuerpo,
    enlaces o adjuntos sin declararlo, un análisis de solo cabeceras diría
    que la cubrió cuando no tuvo nada que mirar."""
    for rule_def in iris_rules.get_rules():
        reads_body = bool(_BODY_ACCESS_RE.search(inspect.getsource(rule_def["func"])))
        assert rule_def["is_body_dependent"] == reads_body, rule_def["name"]
