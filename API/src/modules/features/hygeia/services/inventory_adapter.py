"""
Adaptador inventario de software → servicios de Lybra.

Simétrico a los adaptadores que Themis ya tiene para Nikto
(``themis/lybra/adapters.py``), pero vive de este lado porque es Hygeia
quien conoce la forma de su propio inventario: el contrato de ingesta v1.0
(``SoftwareSchema``), no Themis.

La traducción es deliberadamente fina. El motor ya sabe qué hacer con una
``List[Service]`` (es su modo payload), y ``services_from_payload`` ya sabe
construirlas a partir de diccionarios sueltos — que es exactamente la forma
en la que el inventario está guardado (JSONB). Aquí solo se renombran
campos y se marca la procedencia.
"""

from __future__ import annotations

import logging
import re
from typing import Callable, Dict, List

from src.modules.features.themis.lybra import Service, extract_trailing_version, services_from_payload

logger = logging.getLogger(__name__)


# =============================================================================
# VERSIÓN DE ORIGEN vs. VERSIÓN DEL PAQUETE
# =============================================================================

# La época de Debian: "1:9.6p1-3ubuntu13.5" -> se quita el "1:".
_DEBIAN_EPOCH_RE = re.compile(r"^\d+:")


def _debian_upstream_version(version: str) -> str:
    """Devuelve la versión de origen de una versión de paquete de Debian.

    La gramática de Debian es ``[época:]versión_de_origen[-revisión]``, y el
    separador de la revisión es el ÚLTIMO guion (la versión de origen solo
    puede contener guiones si hay revisión, así que no hay ambigüedad).

    Por qué hace falta, y no es una preferencia estética: ``version_compare``
    parte la cadena en tramos de dígitos y de letras, y las letras ordenan por
    debajo de los números. Con la versión completa::

        "2.39-0ubuntu8.3"  ->  [2, 39, 0, "ubuntu", 8, 3]
        "2.39"             ->  [2, 39]

    la instalada sale *más antigua* que 2.39 por culpa del sufijo de
    empaquetado, así que un rango ``version_start_including="2.39"`` no casa y
    la vulnerabilidad no se reporta. Es un falso negativo, que es el peor tipo
    de fallo que puede tener esto.

    El precio, dicho claramente: se pierde la señal de si la distribución tiene
    el parche aplicado. Debian y Ubuntu estables **corrigen vulnerabilidades
    sin subir la versión de origen** —``9.6p1-3ubuntu13.5`` puede llevar ya el
    parche de una CVE que afecta a ``9.6p1``—, así que esto puede reportar como
    vulnerable algo que ya está corregido.

    Pero ese falso positivo **existe igual con la versión completa**: el NVD no
    sabe expresar "corregido en la revisión 13.5 de Ubuntu", así que sus rangos
    tampoco la excluirían. Recortar no lo empeora; solo deja de perder las
    coincidencias del primer caso. Resolverlo de verdad exige otra fuente de
    datos —los avisos de la propia distribución: DSA, USN, OVAL—, que es otro
    trabajo.

    Args:
        version: La versión tal como la reporta dpkg, p. ej.
            ``"1:9.6p1-3ubuntu13.5"``.

    Returns:
        La versión de origen (``"9.6p1"``), o la cadena original si recortarla
        la dejaría vacía.
    """
    upstream = _DEBIAN_EPOCH_RE.sub("", version, count=1)
    head, separator, _revision = upstream.rpartition("-")
    if separator and head:
        upstream = head
    return upstream or version


# Solo dpkg. RPM no lo necesita: el agente ya manda %{VERSION}, que es la
# versión de origen, y deja fuera %{RELEASE}, que es el empaquetado.
#
# Snap queda fuera a propósito aunque sus versiones se le parezcan
# ("firefox 122.0-2"). Ahí la cadena la declara quien publica el snap y no
# sigue ninguna gramática, así que recortar por el último guion podría
# llevarse una etiqueta de versión preliminar de verdad. Debian no tiene ese
# riesgo: sus preliminares usan "~", no "-".
_UPSTREAM_VERSION_BY_SOURCE: Dict[str, Callable[[str], str]] = {
    "dpkg": _debian_upstream_version,
}


def _package_version(item: dict) -> str:
    """Devuelve la versión de un paquete en la forma que el motor sabe comparar.

    La normalización vive aquí y no en el agente a propósito: así
    ``MonitoredAsset.inventory`` conserva la versión exacta del paquete —que es
    lo que hay que enseñar en el informe en PDF, y lo que dice si un parche de
    la distribución está aplicado— y solo el motor ve la recortada.
    """
    version = (item.get("version") or "").strip()
    if not version:
        return ""
    source = (item.get("source") or "").strip().lower()
    normalize = _UPSTREAM_VERSION_BY_SOURCE.get(source)
    return normalize(version) if normalize else version


def services_from_inventory(software: list) -> List[Service]:
    """
    Traduce el inventario de software de un activo a ``Service`` de Lybra.

    Tres decisiones, todas heredadas del modo payload de Lybra:

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

    Y una quinta, aparecida al implementar el inventario de Linux: **de los
    paquetes de dpkg se usa la versión de origen, no la del paquete**
    (``"9.6p1"``, no ``"1:9.6p1-3ubuntu13.5"``). El sufijo de empaquetado hace
    que ``version_compare`` ordene la versión instalada por debajo de la misma
    versión sin sufijo, y eso pierde coincidencias reales. Ver
    :func:`_debian_upstream_version`, que explica también lo que cuesta.

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
        version = extract_trailing_version(name) or _package_version(item)
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
