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

from .generator import AIGenerator
from .strategies import ModelStrategy

logger = logging.getLogger(__name__)


def _build_strategy(name: str) -> ModelStrategy:
    """Instancia la estrategia ``name`` con credenciales de entorno/config.

    Despacha por ``ModelStrategy._registry`` (B4) en vez de una cadena
    ``if/elif`` por nombre — un proveedor nuevo se da de alta junto a su
    propia clase en ``strategies.py``, sin volver a tocar esta factory.
    """
    name = (name or "ollama").lower()
    overrides = CR.scribe_config().options_for(name)
    return ModelStrategy.resolve(name, overrides)


def build_generator(module: Optional[str] = None) -> AIGenerator:
    """
    Construye un ``AIGenerator`` para el módulo dado.

    Args:
        module: Nombre del módulo consumidor ('aegis', 'themis', …). Si la
            config no define una estrategia para él, se usa ``defaultStrategy``.

    Returns:
        Un AIGenerator listo para ``digest``.
    """
    strategy_name = CR.scribe_config().strategy_for(module)
    logger.info("[scribe] módulo=%s → estrategia=%s", module, strategy_name)

    # La resiliencia se pasa desde aquí y no se deja en los defaults de
    # ``AIGenerator``: la factory es el único sitio que construye generadores
    # de producción, así que es donde la configuración tiene que entrar. Los
    # defaults de la firma siguen valiendo para quien instancia el generador
    # a mano en un test.
    resilience = CR.scribe_resilience_config()
    return AIGenerator(
        _build_strategy(strategy_name),
        max_retries=resilience.max_retries,
        retry_base=resilience.retry_base_seconds,
        breaker_threshold=resilience.breaker_threshold,
        breaker_timeout=resilience.breaker_timeout_seconds,
    )
