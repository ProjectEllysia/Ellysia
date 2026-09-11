"""
Métricas del detector a partir del feedback del analista.

El veredicto de Iris es una predicción; la etiqueta del analista es la
verdad que se usa para medirla. Este módulo es puro —sin ORM ni red— para
que lo usen igual el endpoint de métricas, que lee etiquetas de la base de
datos, y el corpus versionado de ``API/resources/iris/corpus/``, que trae las suyas
en un manifiesto.

Convenciones:

- Un veredicto **positivo** es cualquiera que avisa (``Suspicious`` o
  ``Phishing``); ``Legitimate`` es negativo.
- ``malicious`` y ``legitimate`` son las etiquetas que miden; ``unknown``
  cuenta como revisado, pero no entra en precisión, recall ni desacuerdo.
- Una métrica cuyo denominador es cero vale ``None``: "no hay datos" no es lo
  mismo que "0 %".
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, Iterable, List, Optional

LABEL_MALICIOUS = "malicious"
LABEL_LEGITIMATE = "legitimate"
LABEL_UNKNOWN = "unknown"
FEEDBACK_LABELS = (LABEL_MALICIOUS, LABEL_LEGITIMATE, LABEL_UNKNOWN)

_POSITIVE_VERDICTS = frozenset({"Suspicious", "Phishing"})


@dataclass(frozen=True)
class LabelledOutcome:
    """Un análisis etiquetado, reducido a lo que las métricas necesitan.

    Attributes:
        label: Etiqueta vigente del analista (``malicious``, ``legitimate`` o
            ``unknown``).
        verdict: Veredicto que emitió Iris (``Legitimate``, ``Suspicious`` o
            ``Phishing``).
        fired_families: Familias de regla con al menos una regla que restó
            puntos en el contexto ganador.
        covered_families: Familias que se evaluaron por completo: ninguna de
            sus reglas falló al ejecutarse ni se quedó sin contenido que
            inspeccionar.
    """

    label: str
    verdict: str
    fired_families: FrozenSet[str]
    covered_families: FrozenSet[str]


def _ratio(numerator: int, denominator: int) -> Optional[float]:
    """Cociente redondeado a 4 decimales, o ``None`` si no hay denominador."""
    return round(numerator / denominator, 4) if denominator else None


def _confusion(pairs: Iterable[tuple[bool, bool]]) -> Dict[str, int]:
    """Matriz de confusión de pares (predicho positivo, etiquetado malicioso).

    Args:
        pairs: Un par por análisis etiquetado ``malicious`` o ``legitimate``.

    Returns:
        dict: ``truePositives``, ``falsePositives``, ``falseNegatives`` y
            ``trueNegatives``.
    """
    counts = {"truePositives": 0, "falsePositives": 0, "falseNegatives": 0, "trueNegatives": 0}
    for predicted, malicious in pairs:
        if predicted and malicious:
            counts["truePositives"] += 1
        elif predicted:
            counts["falsePositives"] += 1
        elif malicious:
            counts["falseNegatives"] += 1
        else:
            counts["trueNegatives"] += 1
    return counts


def _rates(counts: Dict[str, int]) -> Dict[str, Optional[float]]:
    """Precisión, recall y tasa de desacuerdo de una matriz de confusión.

    Args:
        counts: Salida de ``_confusion``.

    Returns:
        dict: ``precision`` (de lo que se marcó, cuánto era malicioso),
            ``recall`` (de lo malicioso, cuánto se marcó) y
            ``disagreementRate`` (fracción de etiquetados en que la
            predicción y la etiqueta no coinciden). ``None`` sin datos.
    """
    true_positives = counts["truePositives"]
    false_positives = counts["falsePositives"]
    false_negatives = counts["falseNegatives"]
    labelled = sum(counts.values())
    return {
        "precision": _ratio(true_positives, true_positives + false_positives),
        "recall": _ratio(true_positives, true_positives + false_negatives),
        "disagreementRate": _ratio(false_positives + false_negatives, labelled),
    }


def compute_feedback_metrics(outcomes: List[LabelledOutcome], families: Iterable[str],
                             analyses_total: int) -> Dict[str, Any]:
    """Mide el detector contra las etiquetas del analista, en global y por familia.

    En global, la predicción es el veredicto (positivo si avisa). Por familia,
    la predicción es "la familia disparó": así se ve qué familia genera los
    falsos positivos y cuál deja pasar lo malicioso, que es lo que necesita una
    recalibración.

    Args:
        outcomes: Un ``LabelledOutcome`` por análisis con etiqueta vigente.
        families: Familias de regla del catálogo a desglosar (p. ej. ``auth``,
            ``links``).
        analyses_total: Análisis terminados sobre los que se podría haber
            dado feedback; es el denominador de la cobertura de feedback.

    Returns:
        dict: ``analysesTotal``, ``reviewed`` (con cualquier etiqueta),
            ``unknown``, ``feedbackCoverage`` (revisados / terminados),
            ``overall`` (matriz de confusión más ``precision``, ``recall`` y
            ``disagreementRate``) y ``families``: una entrada por familia con
            ``family``, ``fired``, ``precision``, ``recall``,
            ``disagreementRate`` y ``coverage`` (fracción de etiquetados en
            que la familia se evaluó por completo).
    """
    decided = [outcome for outcome in outcomes if outcome.label in (LABEL_MALICIOUS, LABEL_LEGITIMATE)]

    overall_counts = _confusion(
        (outcome.verdict in _POSITIVE_VERDICTS, outcome.label == LABEL_MALICIOUS) for outcome in decided
    )

    family_metrics = []
    for family in sorted(set(families)):
        counts = _confusion(
            (family in outcome.fired_families, outcome.label == LABEL_MALICIOUS) for outcome in decided
        )
        covered = sum(1 for outcome in decided if family in outcome.covered_families)
        family_metrics.append({
            "family": family,
            "fired": counts["truePositives"] + counts["falsePositives"],
            **_rates(counts),
            "coverage": _ratio(covered, len(decided)),
        })

    return {
        "analysesTotal": analyses_total,
        "reviewed": len(outcomes),
        "unknown": len(outcomes) - len(decided),
        "feedbackCoverage": _ratio(len(outcomes), analyses_total),
        "overall": {**overall_counts, **_rates(overall_counts)},
        "families": family_metrics,
    }


def outcome_from_rules(label: str, verdict: str, rules: Iterable[tuple[str, float]],
                       family_of: Dict[str, str], unevaluated_rules: Iterable[str]) -> LabelledOutcome:
    """Construye un ``LabelledOutcome`` a partir de los resultados de regla.

    Args:
        label: Etiqueta vigente del analista.
        verdict: Veredicto que emitió Iris.
        rules: Pares ``(nombre de regla, score)`` del contexto ganador.
        family_of: Familia de cada regla del catálogo (``""`` si no tiene).
        unevaluated_rules: Reglas que no se evaluaron de verdad: las que
            fallaron al ejecutarse y las que no tuvieron contenido que
            inspeccionar.

    Returns:
        LabelledOutcome: Con las familias que dispararon y las que se
            evaluaron por completo (todas las del catálogo menos las que
            contienen alguna regla sin evaluar).
    """
    fired = frozenset(
        family_of.get(name, "") for name, score in rules if score < 0 and family_of.get(name)
    )
    unevaluated_families = {family_of.get(name, "") for name in unevaluated_rules}
    covered = frozenset(
        family for family in set(family_of.values()) if family and family not in unevaluated_families
    )
    return LabelledOutcome(label=label, verdict=verdict, fired_families=fired, covered_families=covered)
