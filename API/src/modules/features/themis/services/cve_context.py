"""Enriquecer hallazgos con lo que la KB local sabe de sus CVEs.

Descripción, CWEs y —lo más accionable de todo— la versión en la que el
problema está corregido. Nada de esto se inventa: sale del registro NVD
replicado localmente, y `fixed_version` sólo se rellena cuando la propia NVD
declara una cota superior en la regla de aplicabilidad que casó con el producto
del hallazgo.

Vivía dentro del constructor del PDF (``FindingsPrintingStrategy``), así que
era exclusivo del informe: la interfaz no podía decir «actualiza a 2.4.58 o
superior» ni aunque quisiera, porque ese dato nunca llegaba a la API. Aquí
queda a mano de los dos. No está en ``lybra/``, que es la capa pura, porque
consulta la base de datos.
"""

from __future__ import annotations

from typing import Optional

from src.modules.infrastructure.session import build_repository

from ..lybra import parse_cpe23
from ..repositories import KbRepository


def enrich_with_cve_context(findings: list) -> None:
    """Añadir ``description``, ``cwe_ids`` y ``fixed_version`` a cada hallazgo.

    Modifica los dicts en el sitio.

    Hace **una** consulta en bloque para todos los CVEs del escaneo, nunca una
    por hallazgo: un host con 150 hallazgos es lo normal, y ahí la diferencia
    entre una consulta y ciento cincuenta es la diferencia entre una vista que
    abre y una que no.
    """
    cve_ids = sorted({cve for finding in findings for cve in (finding.get("cve_ids") or [])})
    if not cve_ids:
        return

    entries = {
        cve_entry.cve_id: cve_entry
        for cve_entry in build_repository(KbRepository).get_cves_with_matches(cve_ids)
    }

    for finding in findings:
        ids = finding.get("cve_ids") or []
        if not ids:
            continue
        entry = entries.get(ids[0])
        if entry is None:
            continue
        finding["description"] = entry.description
        finding["cwe_ids"] = entry.cwe_ids or []
        finding["fixed_version"] = find_fixed_version(entry, finding.get("cpe"))


def find_fixed_version(entry, cpe: Optional[str]) -> Optional[str]:
    """La cota "corregido en" de la NVD para el producto de este hallazgo.

    Devuelve ``None`` en vez de adivinar cuando ninguna regla de aplicabilidad
    del CVE declara un límite superior para ese producto: una versión de
    destino inventada es peor que ninguna, porque se actúa sobre ella.
    """
    if not cpe:
        return None
    parsed = parse_cpe23(cpe)
    if not parsed:
        return None
    for cpe_match in entry.cpe_matches:
        if cpe_match.vendor == parsed["vendor"] and cpe_match.product == parsed["product"]:
            if cpe_match.version_end_excluding:
                return cpe_match.version_end_excluding
            if cpe_match.version_end_including:
                return cpe_match.version_end_including
    return None
