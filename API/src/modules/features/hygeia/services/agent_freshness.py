"""
hygeia.services.agent_freshness
─────────────────────────────────
Compara la versión de agente reportada en un heartbeat contra el suelo
configurado (``features.hygeia.minAgentVersion``), para que la SPA pueda
avisar de qué activos llevan un agente desactualizado.

Función pura: sin DB, sin Flask, sin ORM. Es un aviso, no una validación: el
contrato de ingesta no exige ningún formato a ``agentVersion`` más allá de
su longitud, así que aquí no se puede distinguir con certeza una versión
antigua de un dato que llegó corrompido o en un formato que no se reconoce.
Ante la duda, el resultado es "no se sabe" (``None``), nunca un falso
"desactualizado" — el peor desenlace posible no es no avisar, es avisar de
algo que no es cierto.
"""

from __future__ import annotations

import re
from typing import Optional, Tuple

# Solo enteros separados por puntos ("0", "0.4", "0.4.1"...). Deliberadamente
# estricto: nada de sufijos ("1.2.3-rc1"), prefijos ("v1.2.3") ni separadores
# distintos del punto. Un formato que el comparador no reconoce es exactamente
# el caso que tiene que resolverse a "no se sabe", así que ampliar esta regex
# para tragarse casos raros iría en contra del propósito del módulo.
_VERSION_RE = re.compile(r"^\d+(\.\d+)*$")


def _parse_version(version: Optional[str]) -> Optional[Tuple[int, ...]]:
    """
    Convierte una cadena de versión en una tupla de enteros comparable.

    Returns:
        La tupla de segmentos, o ``None`` si ``version`` es nulo o no encaja
        en el formato estricto ``X.Y.Z...``.
    """
    if not version or not _VERSION_RE.match(version):
        return None
    return tuple(int(segment) for segment in version.split("."))


def is_agent_outdated(agent_version: Optional[str], min_version: str) -> Optional[bool]:
    """
    Indica si la versión de agente de un activo está por debajo del suelo configurado.

    Los dos lados se acotan a la misma longitud rellenando con ceros antes de
    comparar (``"1.2"`` frente a ``"1.2.0"`` no es una diferencia real), y la
    comparación es lexicográfica sobre las tuplas resultantes.

    Args:
        agent_version: Última versión reportada por el activo
            (``MonitoredAsset.agent_version``), o ``None`` si nunca ha
            reportado.
        min_version: Suelo configurado (``HygeiaConfig.min_agent_version``).

    Returns:
        ``True`` si la versión del agente es estrictamente anterior al
        suelo, ``False`` si es igual o posterior, y ``None`` cuando no se
        puede afirmar ninguna de las dos cosas: el activo nunca reportó
        versión, su versión no encaja en el formato ``X.Y.Z...``, o el
        propio suelo configurado tampoco encaja (un valor mal escrito en
        ``SecOpsConfig.json`` no debe traducirse en falsos avisos para todo
        el parque).
    """
    parsed_agent = _parse_version(agent_version)
    parsed_min = _parse_version(min_version)
    if parsed_agent is None or parsed_min is None:
        return None

    length = max(len(parsed_agent), len(parsed_min))
    padded_agent = parsed_agent + (0,) * (length - len(parsed_agent))
    padded_min = parsed_min + (0,) * (length - len(parsed_min))
    return padded_agent < padded_min
