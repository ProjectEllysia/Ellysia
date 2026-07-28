"""
Adaptador inventario de software → servicios de Lybra (Fase I).

Simétrico a los adaptadores que Themis ya tiene para Nikto y OpenVAS
(``themis/lybra/adapters.py``), pero vive de este lado porque es Hygeia
quien conoce la forma de su propio inventario: el contrato de ingesta v1.0
(``SoftwareSchema``), no Themis.

La traducción es deliberadamente fina. El motor ya sabe qué hacer con una
``List[Service]`` desde la Fase 0.9, y ``services_from_payload`` ya sabe
construirlas a partir de diccionarios sueltos — que es exactamente la forma
en la que el inventario está guardado (JSONB). Aquí solo se renombran
campos y se marca la procedencia.
"""

from __future__ import annotations

import logging
from typing import List

from src.modules.features.themis.lybra import Service, services_from_payload

logger = logging.getLogger(__name__)


def services_from_inventory(software: list) -> List[Service]:
    """
    Traduce el inventario de software de un activo a ``Service`` de Lybra.

    Tres decisiones, todas del diseño de la Fase 0.9:

    - **Sin puerto ni protocolo.** Un paquete instalado no escucha en ningún
      sitio. El motor lo contempla: emite ``category="installed_package"``
      en vez de ``"open_port"`` cuando el puerto falta, y ``compute_dedup_key``
      se apoya en el producto para distinguir dos paquetes del mismo host.
    - **``origin="inventory"``.** Es lo que hace que un hallazgo por versión
      nazca ``confirmed=true``/``qod=95`` en vez del ``qod=70`` genérico de
      una hipótesis por banner: la versión no se dedujo de la red, se leyó
      del gestor de paquetes del propio host.
    - **Se descarta lo que no tiene versión.** Sin versión el matcher no
      puede resolver un CPE (``_resolve_cpe`` devuelve ``None``), así que un
      paquete sin ella no puede producir ni una sola CVE — solo un hallazgo
      informativo por entrada. Un inventario de Windows trae cientos, y
      ahogarían la lista de hallazgos con ruido sin aportar detección.

    Args:
        software: Lista de aplicaciones tal como las guarda
            ``MonitoredAsset.inventory`` (claves del ``SoftwareSchema``:
            ``name``, ``vendor``, ``version``...).

    Returns:
        Los ``Service`` correspondientes, uno por paquete con versión.
    """
    payload = [
        {
            "port":     None,
            "protocol": "",
            # El nombre del paquete es lo que la tabla CPE_PRODUCT_OVERRIDES
            # del motor intenta casar, así que va como `product`, no como
            # `name` (que en un Service es el nombre del *servicio* de red).
            "product":  (item.get("name") or "").strip(),
            "version":  (item.get("version") or "").strip(),
            "origin":   "inventory",
        }
        for item in (software or [])
        if (item.get("name") or "").strip() and (item.get("version") or "").strip()
    ]
    services = services_from_payload(payload)
    logger.debug(
        "Inventario adaptado: %d paquetes -> %d servicios con versión",
        len(software or []), len(services),
    )
    return services
