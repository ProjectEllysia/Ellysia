"""
Calidad de un análisis: qué se pudo inspeccionar de verdad y qué no.

Una regla que revienta no aborta el análisis —eso sería peor: un solo fallo
tiraría un informe entero por 47 reglas que sí funcionaron—, pero tampoco
puede desaparecer sin dejar rastro. Antes, una excepción de regla se
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
from enum import StrEnum
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
            "ruleId": rule_def.get("rule_id") or None,
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


COVERAGE_FULL_MESSAGE = "full_message"
COVERAGE_HEADERS_ONLY = "headers_only"

CONFIDENCE_HIGH = "high"
CONFIDENCE_MEDIUM = "medium"
CONFIDENCE_LOW = "low"

#: Puntos de score por debajo de los cuales un veredicto que sale del score se
#: considera pegado al umbral: una sola regla de peso pequeño lo cambiaría.
BORDERLINE_MARGIN = 5.0


def assess_coverage(context: Any, rules_defs: List[dict]) -> Dict[str, Any]:
    """Resume qué partes del mensaje se pudieron inspeccionar.

    Un análisis de solo cabeceras ejecuta igualmente las reglas de cuerpo,
    enlaces y adjuntos, pero sobre un mensaje vacío: no encuentran nada porque
    no hay nada que mirar, no porque el contenido sea limpio. Esta función lo
    hace explícito.

    Args:
        context: ``MessageContext`` evaluado (cabeceras más cuerpo, enlaces y
            adjuntos si el envío traía el ``.eml`` completo).
        rules_defs: Catálogo evaluado; se usa el flag ``is_body_dependent`` de
            cada regla.

    Returns:
        dict: ``mode`` —``full_message`` si el mensaje traía cuerpo o
            adjuntos, ``headers_only`` si no— y ``uncoveredRules``, los nombres
            de las reglas que dependen del cuerpo y no tuvieron nada que
            inspeccionar (lista vacía en ``full_message``).
    """
    has_content = bool(context.body_text or context.body_html or context.attachments)
    if has_content:
        return {"mode": COVERAGE_FULL_MESSAGE, "uncoveredRules": []}
    return {"mode": COVERAGE_HEADERS_ONLY, "uncoveredRules": body_dependent_rule_names(rules_defs)}


class AnalysisMode(StrEnum):
    """Qué parte del correo pide analizar el usuario (``POST /iris/analyze``, campo ``mode``).

    Attributes:
        HEADERS: Solo el bloque de cabeceras.
        MESSAGE: El ``.eml`` completo, con cuerpo, enlaces y adjuntos.
    """
    HEADERS = "headers"
    MESSAGE = "message"


def body_dependent_rule_names(rules_defs: List[dict]) -> List[str]:
    """Reglas que no tienen nada que inspeccionar en un análisis de solo cabeceras.

    Es la misma lista que ``assess_coverage`` guarda en ``uncoveredRules`` de un
    análisis de solo cabeceras, y la que ``GET /iris/capabilities`` publica
    para que la interfaz la enseñe **antes** de enviar, al elegir el modo.

    Args:
        rules_defs: Catálogo de reglas; se usa el flag ``is_body_dependent``.

    Returns:
        List[str]: Nombres de las reglas de cuerpo, enlaces y adjuntos, en el
            orden del catálogo.
    """
    return [rule_def["name"] for rule_def in rules_defs if rule_def.get("is_body_dependent")]


@dataclass(frozen=True)
class ConfidenceAssessment:
    """Cuánto se puede sostener un veredicto, en una escala ordinal.

    **No es una probabilidad.** El score de Iris es una escala de riesgo sin
    calibración estadística detrás, así que un número de confianza («92 %»)
    afirmaría una precisión que nadie ha medido. En su lugar hay tres niveles
    que salen de reglas deterministas y siempre van acompañados de sus motivos.

    Attributes:
        level: ``high`` (nada resta confianza), ``medium`` (hay motivos de
            incertidumbre que no invalidan el veredicto) o ``low`` (el
            veredicto afirma algo que el análisis no llegó a comprobar: un
            ``Legitimate`` sin contenido que inspeccionar, o una regla de
            autenticación o de adjuntos que no se ejecutó).
        reasons: Frases legibles, una por motivo; vacía cuando ``level`` es
            ``high``.
    """

    level: str
    reasons: List[str] = field(default_factory=list)


def assess_confidence(winner: Any, secondary: Any,
                      legitimate_threshold: float, suspicious_threshold: float) -> ConfidenceAssessment:
    """Evalúa la confianza del veredicto ganador y sus motivos de incertidumbre.

    Motivos que se tienen en cuenta:

    - **Solo cabeceras**: las reglas de cuerpo, enlaces y adjuntos no tuvieron
      nada que inspeccionar. Si además el veredicto es ``Legitimate``, la
      confianza es ``low``: el mensaje no está limpio, simplemente no se miró.
    - **Análisis degradado**: alguna regla no se ejecutó. Es ``low`` si era de
      una familia que bloquea el veredicto limpio (``DEGRADING_FAMILIES``).
    - **Score pegado a un umbral**: solo cuando el veredicto sale del score (no
      de un gate) y está a menos de ``BORDERLINE_MARGIN`` puntos de un umbral.
    - **Reenvío en desacuerdo**: el envoltorio y el original tienen
      veredictos distintos.

    Args:
        winner: ``ContextEvaluation`` que decidió el veredicto.
        secondary: ``ContextEvaluation`` del otro mensaje de un reenvío, o
            ``None`` si no lo era.
        legitimate_threshold: Umbral de score de ``Legitimate`` (0–100).
        suspicious_threshold: Umbral de score de ``Suspicious`` (0–100).

    Returns:
        ConfidenceAssessment: Nivel y motivos. ``high`` sin motivos cuando no
            hay nada que reste confianza.
    """
    reasons: List[str] = []
    is_low = False

    coverage = winner.coverage or {}
    if coverage.get("mode") == COVERAGE_HEADERS_ONLY:
        uncovered_count = len(coverage.get("uncoveredRules") or [])
        reasons.append(
            f"Solo se analizaron las cabeceras: {uncovered_count} reglas de cuerpo, "
            "enlaces y adjuntos no tuvieron contenido que inspeccionar."
        )
        if winner.verdict == "Legitimate":
            is_low = True
            reasons.append(
                "Un veredicto Legítimo sin cuerpo ni adjuntos solo dice que las "
                "cabeceras no muestran señales, no que el contenido sea seguro."
            )

    if winner.quality.is_degraded:
        reasons.append(
            f"No se pudieron ejecutar {len(winner.quality.failed_rules)} reglas, así "
            "que una parte del mensaje no se inspeccionó."
        )
        if winner.quality.blocks_clean_verdict:
            is_low = True

    score = float(winner.total_score)
    if score >= legitimate_threshold:
        score_verdict = "Legitimate"
    elif score >= suspicious_threshold:
        score_verdict = "Suspicious"
    else:
        score_verdict = "Phishing"
    if score_verdict == winner.verdict:
        for threshold in (legitimate_threshold, suspicious_threshold):
            if abs(score - threshold) < BORDERLINE_MARGIN:
                reasons.append(
                    f"El score ({score:g}) está a menos de {BORDERLINE_MARGIN:g} puntos "
                    f"del umbral {threshold:g}: una sola señal pequeña cambiaría el veredicto."
                )
                break

    if secondary is not None and secondary.verdict != winner.verdict:
        reasons.append(
            "Los dos mensajes del reenvío no coinciden "
            f"({winner.verdict} frente a {secondary.verdict})."
        )

    if is_low:
        return ConfidenceAssessment(level=CONFIDENCE_LOW, reasons=reasons)
    return ConfidenceAssessment(level=CONFIDENCE_MEDIUM if reasons else CONFIDENCE_HIGH,
                                reasons=reasons)


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
