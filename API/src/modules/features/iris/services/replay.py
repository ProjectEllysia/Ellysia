"""
Replay offline: qué habría decidido Iris con otra política de puntuación.

Un cambio de umbrales, de perfil o de pesos puede mover la tasa de falsos
positivos en cualquier dirección, y sin comparar no hay forma de saber en
cuál. El replay ejecuta el mismo conjunto de mensajes con dos o más
``ScoringPolicy`` y devuelve, muestra a muestra, qué veredicto cambió y qué
gates aparecieron o desaparecieron, más las métricas de cada política frente
a las etiquetas del corpus.

El módulo no ejecuta reglas por su cuenta: recibe la función que evalúa un
mensaje bajo una política (en la aplicación, ``IrisManager.evaluate_raw``).
Así el replay y los análisis reales usan exactamente el mismo motor.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional

from .feedback_metrics import compute_feedback_metrics, outcome_from_rules
from .scoring import ScoringPolicy

#: Evalúa un mensaje crudo bajo una política y devuelve ``verdict``,
#: ``totalScore``, ``gateReasons``, ``rules`` (pares nombre/score del contexto
#: ganador) y ``unevaluatedRules``.
Evaluate = Callable[[str, ScoringPolicy], Dict[str, Any]]


@dataclass(frozen=True)
class ReplaySample:
    """Un mensaje del corpus de replay.

    Attributes:
        sample_id: Identificador estable de la muestra.
        raw: Mensaje crudo (cabeceras o ``.eml`` completo).
        label: Etiqueta conocida (``malicious``, ``legitimate`` o
            ``unknown``), o ``None`` si la muestra no está etiquetada: se
            compara igualmente, pero no entra en las métricas.
    """

    sample_id: str
    raw: str
    label: Optional[str] = None


def load_corpus(directory: Path) -> tuple[str, List[ReplaySample]]:
    """Lee un corpus versionado (``manifest.json`` más un fichero por muestra).

    Args:
        directory: Carpeta con ``manifest.json``, cuyas muestras tienen
            ``id``, ``file`` y ``label``.

    Returns:
        tuple: ``(versión del corpus, muestras)`` en el orden del manifiesto.
    """
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    samples = [
        ReplaySample(
            sample_id=entry["id"],
            raw=(directory / entry["file"]).read_bytes().decode("utf-8"),
            label=entry.get("label"),
        )
        for entry in manifest["samples"]
    ]
    return manifest["version"], samples


def replay(samples: List[ReplaySample], policies: Mapping[str, ScoringPolicy], evaluate: Evaluate,
           family_of: Mapping[str, str], detector: str) -> Dict[str, Any]:
    """Evalúa cada muestra con cada política y compara contra la primera.

    La primera política del mapa es la referencia (normalmente la vigente);
    las demás son candidatas. Una muestra "cambia" si alguna candidata le da
    un veredicto distinto del de la referencia.

    Args:
        samples: Mensajes a evaluar.
        policies: Nombre → política, en orden; la primera es la referencia.
        evaluate: Función que evalúa un mensaje bajo una política (ver
            ``Evaluate``).
        family_of: Familia de cada regla del catálogo, para las métricas.
        detector: Marca del catálogo evaluado (``detector_version``).

    Returns:
        dict: ``baseline`` (nombre de la referencia), ``policies`` (por
            nombre: ``scoringVersion``, ``snapshot`` y ``metrics`` frente a
            las etiquetas), ``samples`` (por muestra: ``id``, ``label``,
            ``results`` por política, ``verdictChanged`` y ``gateChanges``
            con los gates ``added``/``removed`` de cada candidata) y
            ``changedCount``.

    Raises:
        ValueError: Si no se pasa ninguna política.
    """
    if not policies:
        raise ValueError("El replay necesita al menos una política.")
    names = list(policies)
    baseline = names[0]
    families = {family for family in family_of.values() if family}

    outcomes: Dict[str, list] = {name: [] for name in names}
    sample_reports = []
    for sample in samples:
        results = {name: evaluate(sample.raw, policies[name]) for name in names}
        baseline_gates = set(results[baseline]["gateReasons"])
        gate_changes = {
            name: {
                "added": sorted(set(results[name]["gateReasons"]) - baseline_gates),
                "removed": sorted(baseline_gates - set(results[name]["gateReasons"])),
            }
            for name in names[1:]
        }
        sample_reports.append({
            "id": sample.sample_id,
            "label": sample.label,
            "results": {
                name: {
                    "verdict": result["verdict"],
                    "totalScore": result["totalScore"],
                    "gateReasons": result["gateReasons"],
                }
                for name, result in results.items()
            },
            "verdictChanged": any(
                results[name]["verdict"] != results[baseline]["verdict"] for name in names[1:]
            ),
            "gateChanges": gate_changes,
        })
        if sample.label:
            for name, result in results.items():
                outcomes[name].append(outcome_from_rules(
                    sample.label, result["verdict"], result["rules"], family_of,
                    result["unevaluatedRules"],
                ))

    return {
        "baseline": baseline,
        "policies": {
            name: {
                "scoringVersion": policies[name].version(detector),
                "snapshot": policies[name].snapshot(detector),
                "metrics": compute_feedback_metrics(outcomes[name], families, analyses_total=len(samples)),
            }
            for name in names
        },
        "samples": sample_reports,
        "changedCount": sum(1 for report in sample_reports if report["verdictChanged"]),
    }
