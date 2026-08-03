"""
Adaptador inventario de software → servicios de Lybra (Fase I).

Simétrico a los adaptadores que Themis ya tiene para Nikto
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

from src.modules.features.themis.lybra import Service, extract_trailing_version, services_from_payload

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

    Una cuarta decisión, encontrada al analizar un inventario real (Fase
    I-b): **la versión incrustada en el nombre gana a la del campo
    ``version``, cuando ambas existen y no coinciden.** JetBrains es el caso
    verificado — su instalador registra el *build interno*
    (``"252.26199.169"``) como ``version`` de Windows, mientras que la
    versión de marketing contra la que NVD expresa sus rangos
    (``"2025.2.2"``) solo aparece incrustada en el propio ``name``
    (``"IntelliJ IDEA 2025.2.2"``). Comparar el build interno contra esos
    rangos no solo pierde coincidencias reales: las inventa — un build
    number ordena como "más antiguo que cualquier año", así que casa con
    prácticamente cualquier rango del tipo "afecta a versiones anteriores a
    X" (visto en producción: ~50 CVEs falsos para una sola instalación). En
    el resto del inventario observado, ambas fuentes ya coinciden cuando las
    dos existen, así que preferir la incrustada no cambia nada — solo
    corrige el caso donde discrepan.

    Args:
        software: Lista de aplicaciones tal como las guarda
            ``MonitoredAsset.inventory`` (claves del ``SoftwareSchema``:
            ``name``, ``vendor``, ``version``...).

    Returns:
        Los ``Service`` correspondientes, uno por paquete con versión.
    """
    payload = []
    for item in (software or []):
        name = (item.get("name") or "").strip()
        if not name:
            continue
        version = extract_trailing_version(name) or (item.get("version") or "").strip()
        if not version:
            continue
        payload.append({
            "port":     None,
            "protocol": "",
            # El nombre del paquete es lo que la tabla CPE_PRODUCT_OVERRIDES
            # del motor intenta casar, así que va como `product`, no como
            # `name` (que en un Service es el nombre del *servicio* de red).
            "product":  name,
            "version":  version,
            "origin":   "inventory",
        })
    services = services_from_payload(payload)
    logger.debug(
        "Inventario adaptado: %d paquetes -> %d servicios con versión",
        len(software or []), len(services),
    )
    return services
