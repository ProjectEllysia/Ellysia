"""
scribe.factory
──────────────
Construcción de ``AIGenerator`` por inyección de dependencias.

``build_generator(module)`` decide qué estrategia usar leyendo
``SecOpsConfig.json`` (bloque ``tools.scribe``) — permitiendo una estrategia distinta por
módulo, p.ej. Ollama para Themis y OpenAI para Aegis — y la construye con las
credenciales del ``.env``. El modelo puede sobreescribirse desde la config.
"""

from __future__ import annotations

import logging
from typing import Optional

import src.modules.system.config_reading as CR

from .exceptions import AIStrategyConfigurationError
from .generator import AIGenerator
from .strategies import ModelStrategy, OllamaStrategy, OpenAIStrategy, GoogleStrategy

logger = logging.getLogger(__name__)


def _build_strategy(name: str) -> ModelStrategy:
    """Instancia la estrategia ``name`` con credenciales de entorno/config."""
    name = (name or "ollama").lower()
    ai_cfg = CR.get_ai_config()
    overrides = ai_cfg.get("strategies", {}).get(name, {})

    if name == "ollama":
        host, model = CR.get_ollama_environment()
        return OllamaStrategy(host=host, model=overrides.get("model") or model)

    if name == "openai":
        env = CR.get_openai_environment()
        return OpenAIStrategy(
            api_key=env["api_key"],
            model=overrides.get("model") or env["model"],
            base_url=env.get("base_url"),
        )

    if name == "google":
        env = CR.get_google_environment()
        return GoogleStrategy(
            api_key=env["api_key"],
            model=overrides.get("model") or env["model"],
        )

    raise AIStrategyConfigurationError(f"estrategia desconocida: '{name}'")


def build_generator(module: Optional[str] = None) -> AIGenerator:
    """
    Construye un ``AIGenerator`` para el módulo dado.

    Args:
        module: Nombre del módulo consumidor ('aegis', 'themis', …). Si la
            config no define una estrategia para él, se usa ``defaultStrategy``.

    Returns:
        Un AIGenerator listo para ``digest``.
    """
    strategy_name = CR.get_ai_strategy_for(module)
    logger.info("[scribe] módulo=%s → estrategia=%s", module, strategy_name)
    return AIGenerator(_build_strategy(strategy_name))
