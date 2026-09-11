"""
IrisAIWriter — AI-generated executive narrative for a finished Iris analysis.

Follows the same pattern as ``themis/services/analyzers.py``'s
``NmapAIWriter``/``NiktoAIWriter``/``LybraAIWriter``: model calling is
delegated to an injected scribe ``AIGenerator``, prompts live in
SecOpsConfig.json (``features.iris.prompts.summary``), and the strategy (Ollama/
OpenAI) is resolved per module via ``CR.scribe_config().strategy_for("iris")``.

Unlike Themis — where the AI narrative is generated inline while building
the PDF and never persisted on its own — Iris's web report viewer is a live
JSON view, not just a PDF, so the narrative is generated on demand via its
own endpoint and persisted on ``IrisAnalysis.ai_summary`` (see
``IrisManager.generate_ai_summary``) so it survives independently of any
PDF export.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, Optional

import src.modules.system.config_reading as CR
from src.modules.tools.scribe import AIGenerator, AIInput, build_generator
from src.modules.tools.scribe.exceptions import AIResponseError

_VALID_CONFIDENCE = {"ALTA", "MEDIA", "BAJA"}

#: Confianza del análisis (``IrisAnalysis.confidence``) en la escala del
#: resumen. El resumen no puede saber más que el análisis del que parte, así
#: que cuando el análisis trae confianza, el resumen usa la misma.
_ANALYSIS_CONFIDENCE_LABELS = {"high": "ALTA", "medium": "MEDIA", "low": "BAJA"}


def _extract_json_with_regex(raw: str) -> Optional[dict]:
    """Best-effort JSON recovery from a model response that failed ``json.loads``.

    Same fallback as Themis's analyzers: a top-level ``{...}`` object or a
    fenced ```` ```json ```` block, first one that parses wins.
    """
    for pattern in [r'\{[\s\S]*?\}(?=\s*$)', r'```(?:json)?\s*([\s\S]*?)\s*```']:
        match = re.search(pattern, raw, re.MULTILINE)
        if match:
            try:
                json_str = match.group(1) if match.groups() else match.group()
                return json.loads(json_str)
            except json.JSONDecodeError:
                continue
    return None


def _confidence_note(report: Dict[str, Any]) -> str:
    """Aviso de confianza y cobertura que se añade al final del prompt.

    Va anexado, igual que ``_degradation_note``, para no depender de que la
    plantilla desplegada en ``SecOpsConfig.json`` tenga un marcador nuevo.
    Le da al modelo la misma confianza ordinal y los mismos motivos que ve
    el analista en la UI y en el PDF, y le prohíbe convertirla en un
    porcentaje: el score no está calibrado y un número inventaría precisión.

    Args:
        report: Informe de ``IrisManager.get_analysis_results``; se leen
            ``confidence``, ``coverage`` y ``uncertaintyReasons``.

    Returns:
        str: El aviso, o cadena vacía si el informe no trae confianza
            (análisis anteriores a que se calculara).
    """
    label = _ANALYSIS_CONFIDENCE_LABELS.get(report.get("confidence") or "")
    if label is None:
        return ""
    coverage = report.get("coverage") or {}
    coverage_text = ("solo cabeceras (no se inspeccionó cuerpo ni adjuntos)"
                     if coverage.get("mode") == "headers_only" else "mensaje completo")
    reasons = report.get("uncertaintyReasons") or []
    reasons_text = (" Motivos: " + " ".join(reasons)) if reasons else ""
    return (
        f"\n\nCONFIANZA DEL ANÁLISIS: {label}. Cobertura: {coverage_text}.{reasons_text} "
        "Usa exactamente esta confianza en el campo \"confidence\", no la "
        "expreses como porcentaje y no afirmes más certeza de la que indica."
    )


class IrisAIWriter:
    """Generates an executive narrative (summary, attacker intent,
    recommendations, confidence) from a finished Iris analysis report.

    Attributes:
        _generator: scribe AIGenerator used for model calling.
    """

    def __init__(self, generator: Optional[AIGenerator] = None) -> None:
        self._generator = generator or build_generator("iris")

    def _build_prompts(self) -> dict:
        return CR.iris_config().prompts.get("summary", {})

    @staticmethod
    def model_name() -> str:
        """Qué backend de IA produjo el resumen.

        Es el nombre de la estrategia de scribe configurada para Iris
        (``ollama``/``openai``/``google``), que es la identidad que la
        aplicación controla de verdad: el modelo concreto lo elige cada
        estrategia por su cuenta y puede cambiar bajo los pies sin que aquí se
        note.
        """
        return str(CR.scribe_config().strategy_for("iris"))

    @classmethod
    def prompt_version(cls) -> str:
        """Marca del prompt con el que se generó un resumen.

        Los prompts viven en ``SecOpsConfig.json`` y se pueden editar en
        caliente, así que dos resúmenes guardados pueden venir de instrucciones
        distintas sin que nada lo delate. Se resume el par
        (system, userTemplate) para que cualquier edición cambie la marca —
        mismo criterio que ``detector_version`` con el catálogo de reglas:
        derivado, no escrito a mano, así que no puede quedarse desactualizado.
        """
        prompts = CR.iris_config().prompts.get("summary", {})
        material = f"{prompts.get('system', '')}\n{prompts.get('userTemplate', '')}"
        digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:12]
        return f"iris-summary:{digest}"

    @staticmethod
    def _degradation_note(report: Dict[str, Any]) -> str:
        """Aviso que se añade al prompt cuando el análisis fue degradado.

        Va anexado al final del prompt en vez de como marcador de la plantilla
        porque las plantillas viven en ``SecOpsConfig.json``: un marcador nuevo
        obligaría a editar la configuración desplegada para que este aviso
        apareciera, y un despliegue con la plantilla vieja se quedaría
        silenciosamente sin él — justo el fallo silencioso que se quiere evitar.

        Sin esto, el modelo redacta un resumen ejecutivo seguro sobre un
        análisis que no lo es: no tiene forma de saber que faltan reglas,
        porque lo único que recibe son las que sí se ejecutaron.
        """
        if report.get("analysisQuality") != "degraded":
            return ""
        names = ", ".join(
            rule.get("name", "?") for rule in (report.get("failedRules") or [])
        ) or "desconocidas"
        return (
            "\n\nAVISO IMPORTANTE: este análisis está DEGRADADO. No se pudieron "
            f"ejecutar estas reglas: {names}. La parte del mensaje que les "
            "correspondía no se ha inspeccionado. Dilo explícitamente en el "
            "resumen y no afirmes que el mensaje es seguro basándote en la "
            "ausencia de hallazgos."
        )

    def _build_user_prompt(self, report: Dict[str, Any]) -> str:
        failed_rules = [
            {
                "name": rule.get("ruleName"),
                "ruleId": rule.get("ruleId"),
                "category": rule.get("category"),
                "score": rule.get("score"),
                "recommendation": rule.get("recommendation"),
            }
            for rule in (report.get("rules") or [])
            if (rule.get("score") or 0) < 0
        ]

        template = self._build_prompts().get("userTemplate", "")
        prompt = (
            template
            .replace("{{verdict}}", str(report.get("verdict") or "Suspicious"))
            .replace("{{score}}", str(report.get("totalScore")))
            .replace("{{gate_reasons_json}}", json.dumps(report.get("gateReasons") or [], ensure_ascii=False))
            .replace("{{failed_rules_json}}", json.dumps(failed_rules, indent=2, ensure_ascii=False))
        )
        return prompt + self._degradation_note(report) + _confidence_note(report)

    def generate(self, report: Dict[str, Any]) -> dict:
        """Generate the AI narrative for a finished analysis report dict.

        Args:
            report: The dict produced by ``IrisManager.get_analysis_results``
                (verdict, totalScore, gateReasons, rules, ...).

        Returns:
            ``{"executive_summary", "attacker_intent", "recommendations",
            "confidence"}``. ``confidence`` es la del propio análisis
            (``ALTA``/``MEDIA``/``BAJA``) cuando el informe la trae, aunque el
            modelo responda otra: el resumen no puede saber más que el
            análisis del que parte.

        Raises:
            AIResponseError, AIFallbackExhaustedError, CircuitBreakerOpenError:
                propagated from scribe on backend failure — callers (see
                ``IrisManager.execute_ai_summary_generation``) catch broadly
                and degrade to "no summary available" rather than failing
                the whole analysis.
        """
        prompts = self._build_prompts()
        if not prompts.get("system"):
            raise AIResponseError("Prompt 'features.iris.prompts.summary.system' no configurado", attempt=0)

        ai_input = AIInput(
            system_prompt=prompts["system"],
            user_prompt=self._build_user_prompt(report),
            num_predict=768,
            temperature=0.3,
            top_p=0.85,
            repeat_penalty=1.2,
        )

        result = self._generator.digest(ai_input)
        parsed = self._parse_response(result.text)
        analysis_label = _ANALYSIS_CONFIDENCE_LABELS.get(report.get("confidence") or "")
        if analysis_label is not None:
            parsed["confidence"] = analysis_label
        return parsed

    def _parse_response(self, raw: str, attempt: int = 0) -> dict:
        if not raw:
            raise AIResponseError("Respuesta vacía del modelo", attempt=attempt)

        result = self._try_parse(raw)
        if result is None:
            recovered = _extract_json_with_regex(raw)
            if recovered is None:
                raise AIResponseError(f"No se pudo parsear la respuesta: {raw[:200]}", attempt=attempt)
            result = recovered

        if not isinstance(result.get("recommendations"), list):
            result["recommendations"] = []
        result["recommendations"] = [str(recommendation) for recommendation in result["recommendations"] if recommendation]

        confidence = str(result.get("confidence") or "").upper()
        result["confidence"] = confidence if confidence in _VALID_CONFIDENCE else "BAJA"

        result["executive_summary"] = str(result.get("executive_summary") or "")
        result["attacker_intent"] = str(result.get("attacker_intent") or "")

        return result

    @staticmethod
    def _try_parse(raw: str) -> Optional[dict]:
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return None
