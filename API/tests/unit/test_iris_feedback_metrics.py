"""Métricas del detector a partir de etiquetas, y el corpus versionado.

``services/feedback_metrics.py`` es puro: lo usan igual el endpoint de
métricas y este corpus. Aquí se fija la aritmética y se comprueba que el
catálogo actual clasifica bien las muestras etiquetadas de
``tests/fixtures/iris/``.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from src.modules.features.iris.managers import IrisManager
from src.modules.features.iris.services.feedback_metrics import (
    LABEL_LEGITIMATE,
    LABEL_MALICIOUS,
    LABEL_UNKNOWN,
    LabelledOutcome,
    compute_feedback_metrics,
    outcome_from_rules,
)
from src.modules.features.iris.services.parsers import parse_raw_message
from src.modules.features.iris.services.quality import assess_coverage
from src.modules.features.iris.services.rules import iris_rules

pytestmark = pytest.mark.unit

_CORPUS = Path(__file__).resolve().parents[1] / "fixtures" / "iris"


def _outcome(label, verdict, fired=(), covered=("auth", "links")):
    return LabelledOutcome(label=label, verdict=verdict,
                           fired_families=frozenset(fired), covered_families=frozenset(covered))


def test_metrics_without_labels_have_no_rates():
    """Sin datos, las tasas valen None: "no se sabe" no es "0 %"."""
    metrics = compute_feedback_metrics([], ["auth"], analyses_total=3)
    assert metrics["reviewed"] == 0
    assert metrics["feedbackCoverage"] == 0.0
    assert metrics["overall"]["precision"] is None
    assert metrics["families"][0]["recall"] is None


def test_unknown_labels_count_as_reviewed_but_not_as_measured():
    metrics = compute_feedback_metrics([_outcome(LABEL_UNKNOWN, "Phishing")], ["auth"], analyses_total=1)
    assert metrics["reviewed"] == 1
    assert metrics["unknown"] == 1
    assert metrics["overall"]["disagreementRate"] is None


def test_overall_and_family_rates():
    outcomes = [
        _outcome(LABEL_MALICIOUS, "Phishing", fired=("links",)),          # acierto
        _outcome(LABEL_LEGITIMATE, "Suspicious", fired=("links",)),       # falso positivo
        _outcome(LABEL_MALICIOUS, "Legitimate", covered=("auth",)),       # falso negativo, links sin cubrir
        _outcome(LABEL_LEGITIMATE, "Legitimate"),                         # acierto negativo
    ]
    metrics = compute_feedback_metrics(outcomes, ["links", "auth"], analyses_total=8)

    assert metrics["feedbackCoverage"] == 0.5
    assert metrics["overall"]["precision"] == 0.5
    assert metrics["overall"]["recall"] == 0.5
    assert metrics["overall"]["disagreementRate"] == 0.5
    links = next(entry for entry in metrics["families"] if entry["family"] == "links")
    assert links["fired"] == 2
    assert links["precision"] == 0.5
    assert links["recall"] == 0.5
    assert links["coverage"] == 0.75


def test_outcome_from_rules_derives_fired_and_covered_families():
    family_of = {"SPF": "auth", "Body Links": "links", "Generic Greeting": "content", "Threading": ""}
    outcome = outcome_from_rules(
        LABEL_MALICIOUS, "Phishing",
        [("SPF", -8.0), ("Body Links", 0.0), ("Threading", -3.0)],
        family_of, unevaluated_rules=["Generic Greeting"],
    )
    assert outcome.fired_families == frozenset({"auth"})
    assert outcome.covered_families == frozenset({"auth", "links"})


# ------------------------------------------------------------- corpus versionado

def _evaluate(raw: str):
    """Ejecuta el catálogo sobre *raw* como el motor (sin cola ni base de datos).

    Returns:
        tuple: ``(veredicto, [(regla, score)], reglas sin contenido)``.
    """
    context = parse_raw_message(raw)
    rules_defs = iris_rules.get_rules()
    results = []
    named_results = {}
    for rule_def in rules_defs:
        rule_input = context if rule_def.get("needs_context") else context.headers
        result = rule_def["func"](rule_input)
        result = replace(result, score=min(0.0, float(result.score)))
        results.append(result)
        named_results[rule_def["name"]] = result
    total_score = IrisManager._aggregate_score(rules_defs, results)
    verdict, _ = IrisManager._apply_verdict_gates(IrisManager()._determine_verdict(total_score), named_results)
    rules = [(rule_def["name"], result.score) for rule_def, result in zip(rules_defs, results)]
    return verdict, rules, assess_coverage(context, rules_defs)["uncoveredRules"]


def _corpus():
    manifest = json.loads((_CORPUS / "manifest.json").read_text(encoding="utf-8"))
    return manifest, [
        (sample, (_CORPUS / sample["file"]).read_bytes().decode("utf-8")) for sample in manifest["samples"]
    ]


def test_the_corpus_manifest_is_versioned_and_complete():
    manifest, samples = _corpus()
    assert manifest["version"]
    assert {sample["label"] for sample, _ in samples} == {LABEL_LEGITIMATE, LABEL_MALICIOUS}
    assert sorted(path.name for path in _CORPUS.glob("*.eml")) == sorted(sample["file"] for sample, _ in samples)


def test_the_current_catalog_classifies_the_corpus_without_errors():
    """Con el catálogo actual, el corpus no tiene ni falsos positivos ni
    falsos negativos. Si un cambio de reglas rompe esto, el cambio mueve el
    detector en una dirección que hay que justificar antes de desplegarlo."""
    family_of = {rule_def["name"]: rule_def.get("family") or "" for rule_def in iris_rules.get_rules()}
    _, samples = _corpus()

    outcomes = []
    for sample, raw in samples:
        verdict, rules, uncovered = _evaluate(raw)
        outcomes.append(outcome_from_rules(sample["label"], verdict, rules, family_of, uncovered))

    metrics = compute_feedback_metrics(outcomes, set(family_of.values()) - {""}, analyses_total=len(samples))
    assert metrics["overall"]["falsePositives"] == 0, metrics["overall"]
    assert metrics["overall"]["falseNegatives"] == 0, metrics["overall"]
    assert metrics["overall"]["precision"] == 1.0
    assert metrics["overall"]["recall"] == 1.0
