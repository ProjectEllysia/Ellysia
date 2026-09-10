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
