"""
herald.factory
──────────────
Construcción de ``Mailer`` por inyección de dependencias.

``build_mailer(module)`` decide qué estrategia usar leyendo
``SecOpsConfig.json`` (bloque ``email``) — permitiendo una estrategia
distinta por módulo — y la construye con las credenciales del ``.env``.
Espejo exacto de ``scribe.factory.build_generator``.
"""

from __future__ import annotations

import logging
from typing import Optional

import src.modules.system.config_reading as CR

from .exceptions import EmailConfigurationError
from .mailer import Mailer
from .strategies import EmailStrategy, SmtpStrategy

logger = logging.getLogger(__name__)


def _build_strategy(name: str) -> EmailStrategy:
    """Instancia la estrategia ``name`` con credenciales de entorno/config."""
    name = (name or "smtp").lower()
    email_cfg = CR.get_email_config()
    overrides = email_cfg.get("strategies", {}).get(name, {})

    if name == "smtp":
        creds = CR.get_smtp_environment()
        return SmtpStrategy(
            host=overrides.get("host", "localhost"),
            port=int(overrides.get("port", 587)),
            from_address=overrides.get("fromAddress") or creds.get("username", ""),
            from_name=overrides.get("fromName"),
            use_tls=bool(overrides.get("useTls", True)),
            username=creds.get("username"),
            password=creds.get("password"),
        )

    raise EmailConfigurationError(f"estrategia desconocida: '{name}'")


def build_mailer(module: Optional[str] = None) -> Mailer:
    """
    Construye un ``Mailer`` para el módulo dado.

    Args:
        module: Nombre del módulo consumidor ('aegis', …). Si la config no
            define una estrategia para él, se usa ``defaultStrategy``.

    Returns:
        Un Mailer listo para ``send``/``send_bulk``.
    """
    strategy_name = CR.get_email_strategy_for(module)
    logger.info("[herald] módulo=%s → estrategia=%s", module, strategy_name)
    return Mailer(_build_strategy(strategy_name))
