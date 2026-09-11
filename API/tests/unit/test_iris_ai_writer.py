"""Tests unitarios de IrisAIWriter (IA1).

Cubre:
- Parseo de una respuesta JSON limpia del modelo.
- Recuperación de JSON envuelto en un bloque ```json ... ```.
- Normalización de campos inválidos/ausentes (confidence, recommendations).
- Construcción del user prompt con veredicto/score/reglas falladas.
- Degradación cuando faltan los prompts en la configuración.
"""

from __future__ import annotations

import pytest

import src.modules.system.config_reading as CR
from src.modules.features.iris.services.ai_writer import IrisAIWriter
from src.modules.tools.scribe import AIResult
from src.modules.tools.scribe.exceptions import AIResponseError

pytestmark = pytest.mark.unit

_FAKE_PROMPTS = {
    "summary": {
        "system": "Eres un analista anti-phishing calibrado.",
        "userTemplate": (
            "Veredicto: {{verdict}} Score: {{score}} "
            "Gates: {{gate_reasons_json}} Reglas: {{failed_rules_json}}"
        ),
    }
}


class _FakeGenerator:
    def __init__(self, text: str):
        self._text = text

    def digest(self, ai_input):
        return AIResult(text=self._text)


def _sample_report():
    return {
        "verdict": "Phishing",
        "totalScore": 12,
        "gateReasons": ["lookalike sender domain"],
        "rules": [
            {"ruleName": "Lookalike Sender Domain", "category": "header_analysis",
             "score": -15, "recommendation": "Verifica el dominio real."},
            {"ruleName": "SPF", "category": "authentication", "score": 0, "recommendation": None},
        ],
    }


def test_generate_parses_clean_json_response(monkeypatch):
    monkeypatch.setattr(CR, "iris_config", lambda: CR.IrisConfig(prompts=_FAKE_PROMPTS))
    raw = (
        '{"executive_summary": "Correo de phishing suplantando una marca.", '
        '"attacker_intent": "Robo de credenciales.", '
        '"recommendations": ["No hagas clic", "Reporta el correo"], '
        '"confidence": "ALTA"}'
    )
    writer = IrisAIWriter(generator=_FakeGenerator(raw))
    result = writer.generate(_sample_report())

    assert result["executive_summary"] == "Correo de phishing suplantando una marca."
    assert result["attacker_intent"] == "Robo de credenciales."
    assert result["recommendations"] == ["No hagas clic", "Reporta el correo"]
    assert result["confidence"] == "ALTA"


def test_generate_recovers_json_from_fenced_block(monkeypatch):
    monkeypatch.setattr(CR, "iris_config", lambda: CR.IrisConfig(prompts=_FAKE_PROMPTS))
    raw = (
        "Aquí tienes el análisis:\n"
        "```json\n"
        '{"executive_summary": "Resumen.", "attacker_intent": "Intento.", '
        '"recommendations": [], "confidence": "MEDIA"}\n'
        "```"
    )
    writer = IrisAIWriter(generator=_FakeGenerator(raw))
    result = writer.generate(_sample_report())
    assert result["executive_summary"] == "Resumen."
    assert result["confidence"] == "MEDIA"


def test_generate_defaults_invalid_confidence_to_baja(monkeypatch):
    monkeypatch.setattr(CR, "iris_config", lambda: CR.IrisConfig(prompts=_FAKE_PROMPTS))
    raw = '{"executive_summary": "x", "attacker_intent": "y", "confidence": "URGENTE!"}'
    writer = IrisAIWriter(generator=_FakeGenerator(raw))
    result = writer.generate(_sample_report())
    assert result["confidence"] == "BAJA"
    assert result["recommendations"] == []


def test_generate_raises_on_empty_response(monkeypatch):
    monkeypatch.setattr(CR, "iris_config", lambda: CR.IrisConfig(prompts=_FAKE_PROMPTS))
    writer = IrisAIWriter(generator=_FakeGenerator(""))
    with pytest.raises(AIResponseError):
        writer.generate(_sample_report())


def test_generate_raises_when_system_prompt_missing(monkeypatch):
    monkeypatch.setattr(CR, "iris_config", lambda: CR.IrisConfig(prompts={"summary": {}}))
    writer = IrisAIWriter(generator=_FakeGenerator("{}"))
    with pytest.raises(AIResponseError):
        writer.generate(_sample_report())


def test_user_prompt_includes_verdict_score_and_only_failed_rules(monkeypatch):
    monkeypatch.setattr(CR, "iris_config", lambda: CR.IrisConfig(prompts=_FAKE_PROMPTS))
    writer = IrisAIWriter(generator=_FakeGenerator("{}"))
    prompt = writer._build_user_prompt(_sample_report())

    assert "Phishing" in prompt
    assert "12" in prompt
    assert "lookalike sender domain" in prompt
    assert "Lookalike Sender Domain" in prompt
    # SPF passed (score 0) -- must not appear in the failed-rules list.
    assert '"name": "SPF"' not in prompt


def test_user_prompt_carries_the_analysis_confidence_and_coverage(monkeypatch):
    """El resumen recibe la misma confianza, cobertura y motivos que ve el
    analista, y la instrucción de no convertirlos en porcentaje."""
    monkeypatch.setattr(CR, "iris_config", lambda: CR.IrisConfig(prompts=_FAKE_PROMPTS))
    writer = IrisAIWriter(generator=_FakeGenerator("{}"))
    report = _sample_report() | {
        "confidence": "low",
        "coverage": {"mode": "headers_only", "uncoveredRules": ["Body Links"]},
        "uncertaintyReasons": ["Solo se analizaron las cabeceras."],
    }
    prompt = writer._build_user_prompt(report)

    assert "CONFIANZA DEL ANÁLISIS: BAJA" in prompt
    assert "solo cabeceras" in prompt
    assert "Solo se analizaron las cabeceras." in prompt
    assert "porcentaje" in prompt


def test_user_prompt_has_no_confidence_note_for_old_reports(monkeypatch):
    monkeypatch.setattr(CR, "iris_config", lambda: CR.IrisConfig(prompts=_FAKE_PROMPTS))
    writer = IrisAIWriter(generator=_FakeGenerator("{}"))
    assert "CONFIANZA DEL ANÁLISIS" not in writer._build_user_prompt(_sample_report())


def test_generate_reports_the_analysis_confidence_not_the_model_one(monkeypatch):
    """El modelo no puede saber más que el análisis del que parte: aunque
    responda ALTA, el resumen lleva la confianza del análisis."""
    monkeypatch.setattr(CR, "iris_config", lambda: CR.IrisConfig(prompts=_FAKE_PROMPTS))
    raw = '{"executive_summary": "x", "attacker_intent": "y", "confidence": "ALTA"}'
    writer = IrisAIWriter(generator=_FakeGenerator(raw))
    result = writer.generate(_sample_report() | {"confidence": "medium"})
    assert result["confidence"] == "MEDIA"
