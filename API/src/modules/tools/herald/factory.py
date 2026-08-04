"""
herald.factory
──────────────
Construcción de ``Mailer`` por inyección de dependencias.

``build_mailer(module)`` decide qué estrategia usar leyendo
``SecOpsConfig.json`` (bloque ``tools.herald``) — permitiendo una estrategia
distinta por módulo — y la construye con las credenciales del ``.env``.
Espejo exacto de ``scribe.factory.build_generator``.
"""

from __future__ import annotations

import logging
from typing import Optional

import src.modules.system.config_reading as CR

from .mailer import Mailer
from .strategies import EmailStrategy

logger = logging.getLogger(__name__)


def _build_strategy(name: str) -> EmailStrategy:
    """Instancia la estrategia ``name`` con credenciales de entorno/config.

    Despacha por ``EmailStrategy._registry`` (B4) en vez de una cadena
    ``if/elif`` por nombre — mismo mecanismo que ``scribe.factory``.
    """
    name = (name or "smtp").lower()
    overrides = CR.herald_config().options_for(name)
    return EmailStrategy.resolve(name, overrides)


def build_mailer(module: Optional[str] = None) -> Mailer:
    """
    Construye un ``Mailer`` para el módulo dado.

    Args:
        module: Nombre del módulo consumidor ('aegis', …). Si la config no
            define una estrategia para él, se usa ``defaultStrategy``.

    Returns:
        Un Mailer listo para ``send``/``send_bulk``.
    """
    strategy_name = CR.herald_config().strategy_for(module)
    logger.info("[herald] módulo=%s → estrategia=%s", module, strategy_name)
    strategy = _build_strategy(strategy_name)
    return Mailer(strategy=strategy)
