"""
IrisAIWriter — AI-generated executive narrative for a finished Iris analysis.

Follows the same pattern as ``themis/services/analyzers.py``'s
``NmapAIWriter``/``NiktoAIWriter``/``OpenVASAIWriter``: model calling is
delegated to an injected scribe ``AIGenerator``, prompts live in
SecOpsConfig.json (``features.iris.prompts.summary``), and the strategy (Ollama/
OpenAI) is resolved per module via ``get_ai_strategy_for("iris")``.

Unlike Themis — where the AI narrative is generated inline while building
the PDF and never persisted on its own — Iris's web report viewer is a live
JSON view, not just a PDF, so the narrative is generated on demand via its
own endpoint and persisted on ``IrisAnalysis.ai_summary`` (see
``IrisManager.generate_ai_summary``) so it survives independently of any
PDF export.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Optional

import src.modules.system.config_reading as CR
from src.modules.tools.scribe import AIGenerator, AIInput, build_generator
from src.modules.tools.scribe.exceptions import AIResponseError

_VALID_CONFIDENCE = {"ALTA", "MEDIA", "BAJA"}


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


class IrisAIWriter:
    """Generates an executive narrative (summary, attacker intent,
    recommendations, confidence) from a finished Iris analysis report.

    Attributes:
        _generator: scribe AIGenerator used for model calling.
    """

    def __init__(self, generator: Optional[AIGenerator] = None) -> None:
        self._generator = generator or build_generator("iris")

    def _build_prompts(self) -> dict:
        return CR.get_iris_prompts().get("summary", {})

    def _build_user_prompt(self, report: Dict[str, Any]) -> str:
        failed_rules = [
            {
                "name": r.get("ruleName"),
                "category": r.get("category"),
                "score": r.get("score"),
                "recommendation": r.get("recommendation"),
            }
            for r in (report.get("rules") or [])
            if (r.get("score") or 0) < 0
        ]

        template = self._build_prompts().get("userTemplate", "")
        return (
            template
            .replace("{{verdict}}", str(report.get("verdict") or "Suspicious"))
            .replace("{{score}}", str(report.get("totalScore")))
            .replace("{{gate_reasons_json}}", json.dumps(report.get("gateReasons") or [], ensure_ascii=False))
            .replace("{{failed_rules_json}}", json.dumps(failed_rules, indent=2, ensure_ascii=False))
        )

    def generate(self, report: Dict[str, Any]) -> dict:
        """Generate the AI narrative for a finished analysis report dict.

        Args:
            report: The dict produced by ``IrisManager.get_analysis_results``
                (verdict, totalScore, gateReasons, rules, ...).

        Returns:
            ``{"executive_summary", "attacker_intent", "recommendations",
            "confidence"}``.

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
        return self._parse_response(result.text)

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
        result["recommendations"] = [str(r) for r in result["recommendations"] if r]

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
