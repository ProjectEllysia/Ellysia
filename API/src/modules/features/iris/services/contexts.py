"""
Contexto ganador de un análisis: qué mensaje produjo el veredicto.

Un reenvío "reportar phishing" trae dos mensajes: el envoltorio que llegó al
buzón y el original adjunto como ``message/rfc822``. El motor evalúa los dos y
se queda con el peor veredicto (ver ``MessageContext`` en ``parsers.py`` para
por qué analizar solo el interno no es seguro). Este módulo fija qué contexto
ganó, por qué, y cómo recuperar ese mismo contexto al servir el informe, para
que el veredicto, el score, las reglas, la vista previa, los IOCs y el PDF
describan siempre el mismo mensaje.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional

from .parsers import MessageContext, decode_mime_words

#: El mensaje analizado por defecto: el original desenvuelto de un reenvío, o
#: el único mensaje cuando no hay reenvío.
CONTEXT_INNER = "inner"

#: El envoltorio de un reenvío ``message/rfc822``.
CONTEXT_WRAPPER = "wrapper"

#: Cabeceras que resume la vista previa del informe, en el orden en que se
#: muestran, con la clave camelCase que viaja por la API.
_PREVIEW_HEADERS = (
    ("subject", "subject"),
    ("from", "from"),
    ("to", "to"),
    ("reply-to", "replyTo"),
    ("return-path", "returnPath"),
    ("date", "date"),
)


@dataclass(frozen=True)
class ContextEvaluation:
    """Resultado de ejecutar el catálogo de reglas sobre un contexto.

    Attributes:
        context_type: Qué mensaje se evaluó: ``CONTEXT_INNER`` o
            ``CONTEXT_WRAPPER``.
        verdict: Veredicto final de este contexto tras gates y política de
            calidad (``Legitimate``, ``Suspicious`` o ``Phishing``).
        total_score: Score agregado 0–100 de este contexto.
        gate_reasons: Motivos de los gates y de la degradación que fijaron el
            veredicto.
        results: Un ``RuleResult`` por regla, emparejado por posición con el
            catálogo evaluado.
        quality: ``AnalysisQuality`` de este contexto.
        coverage: Cobertura de este contexto (``mode`` y ``uncoveredRules``,
            ver ``services/quality.assess_coverage``). Por defecto un dict
            vacío, que se lee como "sin información de cobertura".
    """

    context_type: str
    verdict: str
    total_score: float
    gate_reasons: List[str]
    results: List[Any]
    quality: Any
    coverage: Dict[str, Any] = field(default_factory=dict)


def choose_winning_evaluation(
    evaluations: List[ContextEvaluation],
    severity: Mapping[str, int],
) -> tuple[ContextEvaluation, Optional[ContextEvaluation], Optional[str]]:
    """Elige la evaluación que decide el veredicto del análisis.

    Gana la de veredicto más grave. En empate gana la primera de la lista —el
    mensaje interno, que es el que el usuario quería analizar al reenviar—,
    porque el envoltorio no aporta nada peor que justifique desplazarlo.

    Args:
        evaluations: Evaluaciones en orden de preferencia en caso de empate;
            la primera es siempre la del contexto interno. Nunca vacía.
        severity: Gravedad de cada veredicto (mayor = peor), la misma tabla
            que usan los gates.

    Returns:
        tuple: ``(ganadora, secundaria, motivo)``. ``secundaria`` y ``motivo``
            son ``None`` cuando solo hubo un contexto (no era un reenvío); en un
            reenvío, ``secundaria`` es la evaluación que perdió y ``motivo`` es
            una frase legible que explica por qué ganó la otra.
    """
    chosen = evaluations[0]
    for evaluation in evaluations[1:]:
        if severity[evaluation.verdict] > severity[chosen.verdict]:
            chosen = evaluation

    others = [evaluation for evaluation in evaluations if evaluation is not chosen]
    if not others:
        return chosen, None, None

    secondary = others[0]
    return chosen, secondary, _winning_reason(chosen, secondary)


def _winning_reason(winner: ContextEvaluation, secondary: ContextEvaluation) -> str:
    """Frase que explica al analista por qué el veredicto sale de ``winner``.

    Args:
        winner: Evaluación que decidió el veredicto.
        secondary: Evaluación del otro mensaje del reenvío.

    Returns:
        str: Explicación en castellano, lista para la UI y el PDF.
    """
    if winner.context_type == CONTEXT_WRAPPER:
        return (
            f"El envoltorio del reenvío ({winner.verdict}) es más grave que el "
            f"correo original adjunto ({secondary.verdict}): el veredicto, las "
            "reglas y la evidencia describen el envoltorio."
        )
    if winner.verdict == secondary.verdict:
        return (
            f"El correo original adjunto y el envoltorio del reenvío tienen el "
            f"mismo veredicto ({winner.verdict}); se muestra el original."
        )
    return (
        f"El correo original adjunto ({winner.verdict}) es más grave que el "
        f"envoltorio del reenvío ({secondary.verdict}): el veredicto, las "
        "reglas y la evidencia describen el original."
    )


def context_of_type(parsed: MessageContext, context_type: Optional[str]) -> MessageContext:
    """Devuelve, de un mensaje ya parseado, el contexto indicado.

    Args:
        parsed: Resultado de ``parse_raw_message`` sobre el raw del análisis.
        context_type: ``CONTEXT_WRAPPER`` para el envoltorio; cualquier otro
            valor —``CONTEXT_INNER`` o ``None`` en análisis que no guardaron
            contexto ganador— devuelve el contexto interno.

    Returns:
        MessageContext: El envoltorio si se pidió y existe; si no, ``parsed``.
    """
    if context_type == CONTEXT_WRAPPER and parsed.wrapper_context is not None:
        return parsed.wrapper_context
    return parsed


def preview_headers(context: MessageContext) -> Dict[str, Optional[str]]:
    """Cabeceras de la vista previa (asunto, remitente, destinatario…) de un contexto.

    El informe y el PDF muestran estas cabeceras junto al veredicto; se sacan
    del contexto ganador para que la vista previa hable del mismo mensaje que
    el veredicto.

    Args:
        context: Contexto del que leer las cabeceras.

    Returns:
        dict: ``subject``, ``from``, ``to``, ``replyTo``, ``returnPath`` y
            ``date``, cada una decodificada (RFC 2047) o ``None`` si falta.
    """
    preview: Dict[str, Optional[str]] = {}
    for header_name, key in _PREVIEW_HEADERS:
        value = context.headers.get(header_name)
        preview[key] = decode_mime_words(value) if value else None
    return preview
