"""
Calidad de un análisis: qué se pudo inspeccionar de verdad y qué no.

Una regla que revienta no aborta el análisis —eso sería peor: un solo fallo
tiraría un informe entero por 47 reglas que sí funcionaron—, pero tampoco
puede desaparecer sin dejar rastro. Hasta `B05`, una excepción de regla se
convertía en un ``RuleResult(score=0, verdict="error")`` y ahí se acababa
todo: el análisis podía terminar como ``Legitimate`` sin ninguna advertencia,
aunque la regla que faltó fuera la que decide si el mensaje está autenticado.

Este módulo produce las tres cosas que hacen visible esa diferencia:

- ``analysis_quality``: ``complete`` o ``degraded``.
- ``failed_rules``: qué reglas no se pudieron ejecutar (el nombre es el que
  fija el issue; léase "reglas que fallaron **al ejecutarse**", no "reglas
  que detectaron algo malo" — esas son las que puntúan negativo).
- ``detector_version``: qué catálogo de reglas produjo el resultado, para que
  un informe guardado siga siendo interpretable cuando el catálogo cambie.

Y la política conservadora que las acompaña, que depende de **qué familia** de
regla se perdió (ver ``DEGRADING_FAMILIES``).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List

#: Valor de ``verdict`` con el que el motor marca una regla que lanzó una
#: excepción, en lugar de devolver un resultado (ver ``_evaluate_contexts``).
RULE_ERROR_VERDICT = "error"

QUALITY_COMPLETE = "complete"
QUALITY_DEGRADED = "degraded"

#: Familias cuya ausencia impide presentar el mensaje como limpio.
#:
#: No todas las reglas pesan igual cuando faltan. El catálogo tiene ocho
#: familias, y las de contenido, enlaces, identidad, camino de respuesta y
#: cadena Received son muchas y cada una individualmente pequeña: perder una
#: degrada la confianza, pero las demás siguen mirando el mismo mensaje desde
#: ángulos parecidos.
#:
#: ``auth`` y ``attachment`` no funcionan así. Son las dos únicas familias que
#: responden a una pregunta que ninguna otra regla responde —«¿es quien dice
#: ser?» y «¿lo que trae dentro es peligroso?»— y ahí el silencio no es un
#: dato menos: es no haber mirado. Un mensaje cuyo bloque de autenticación no
#: se pudo evaluar no puede presentarse como legítimo por el hecho de que el
#: resto de reglas no encontrara nada.
DEGRADING_FAMILIES = frozenset({"auth", "attachment"})


@dataclass(frozen=True)
class AnalysisQuality:
    """Veredicto sobre el propio análisis, no sobre el correo.

    Attributes:
        quality: ``complete`` si se ejecutaron todas las reglas,
            ``degraded`` si alguna no llegó a ejecutarse.
        failed_rules: Una entrada por regla que no se pudo ejecutar, con su
            nombre, familia y categoría. Serializable a JSONB tal cual.
        blocks_clean_verdict: True si alguna de las reglas perdidas pertenece
            a una familia de ``DEGRADING_FAMILIES``, es decir, si el análisis
            no puede presentarse como limpio.
    """

    quality: str
    failed_rules: List[Dict[str, Any]] = field(default_factory=list)
    blocks_clean_verdict: bool = False

    @property
    def is_degraded(self) -> bool:
        return self.quality == QUALITY_DEGRADED


def assess_quality(rules_defs: List[dict], results: List[Any]) -> AnalysisQuality:
    """Compara el catálogo ejecutado con sus resultados y resume qué faltó.

    ``rules_defs`` y ``results`` se emparejan **por posición**: es el mismo
    contrato que usa ``_persist_analysis_results`` para guardar las filas de
    ``IrisRuleResult``, y por eso el motor lee el registro de reglas una sola
    vez por análisis.
    """
    failed_rules = [
        {
            "name": rule_def["name"],
            "family": rule_def.get("family") or None,
            "category": rule_def.get("category") or None,
        }
        for rule_def, result in zip(rules_defs, results)
        if getattr(result, "verdict", None) == RULE_ERROR_VERDICT
    ]

    if not failed_rules:
        return AnalysisQuality(quality=QUALITY_COMPLETE)

    blocks = any(rule["family"] in DEGRADING_FAMILIES for rule in failed_rules)
    return AnalysisQuality(
        quality=QUALITY_DEGRADED,
        failed_rules=failed_rules,
        blocks_clean_verdict=blocks,
    )


def detector_version(rules_defs: List[dict]) -> str:
    """Identifica el catálogo de reglas que produjo un resultado.

    Un informe guardado hace tres meses se leyó con un catálogo que ya no es
    el actual, y sin esta marca no hay forma de saber cuál. Se compone del
    número de reglas y de un resumen del conjunto **ordenado** de sus nombres:
    ordenado a propósito, para que reordenar el registro no cambie la marca,
    pero añadir, quitar o renombrar una regla sí lo haga.

    Cabe de sobra en los 64 caracteres de la columna (``iris-rules:48:`` más
    12 hexadecimales).
    """
    names = sorted(rule_def["name"] for rule_def in rules_defs)
    digest = hashlib.sha256("\n".join(names).encode("utf-8")).hexdigest()[:12]
    return f"iris-rules:{len(names)}:{digest}"


def cap_verdict(verdict: str, quality: AnalysisQuality) -> tuple[str, List[str]]:
    """Aplica la política conservadora del análisis degradado.

    Devuelve el veredicto ya ajustado y las razones a añadir a
    ``gate_reasons`` — la misma lista que ya explica por qué un veredicto es
    el que es, para que la degradación se lea junto al resto de motivos en
    lugar de en un rincón aparte de la interfaz.

    La única corrección es impedir el ``Legitimate``: un análisis degradado
    puede seguir siendo ``Suspicious`` o ``Phishing`` sin problema —esos
    veredictos ya avisan— pero no puede decir "limpio" sobre un mensaje cuya
    autenticación o cuyos adjuntos nunca llegó a mirar. Nunca **mejora** un
    veredicto, igual que los gates existentes.
    """
    if not quality.is_degraded:
        return verdict, []

    lost = ", ".join(rule["name"] for rule in quality.failed_rules)
    reasons = [f"Análisis degradado: no se pudieron ejecutar estas reglas ({lost})."]

    if quality.blocks_clean_verdict and verdict == "Legitimate":
        reasons.append(
            "El veredicto no puede ser Legítimo: falló alguna regla de "
            "autenticación o de adjuntos, así que el mensaje no llegó a "
            "inspeccionarse por completo. Revisión manual recomendada."
        )
        return "Suspicious", reasons

    return verdict, reasons
