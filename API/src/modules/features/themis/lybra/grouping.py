"""Agrupar hallazgos por la unidad sobre la que de verdad se actúa.

Un escaneo contra un host con dos productos desactualizados puede producir 150
hallazgos, y presentarlos como 150 filas seguidas confunde la cantidad de
*evidencia* con la cantidad de *trabajo*: son dos acciones —subir dos productos
de versión— más un puñado de cosas de configuración que no pertenecen a ningún
producto y se arreglan de otra manera.

Esta agrupación existía desde antes, pero vivía dentro del constructor del
prompt de IA del informe PDF (``LybraAIWriter._build_service_rollup``). El
efecto era que el modelo de lenguaje recibía los hallazgos bien organizados y
el usuario los recibía en una lista plana, que es exactamente al revés. Aquí
queda en la capa pura, sin ORM ni red, para que la consuman los dos: el prompt
del informe y la respuesta de la API.

Cada consumidor traduce :class:`ServiceGroup` a su propia forma —el prompt usa
claves en castellano que su texto de sistema documenta, la API usa camelCase—
y por eso esta capa no devuelve ninguna de las dos: devuelve el dato.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .correlation import PRIORITY_LADDER
from .kb import parse_cpe23

# Valores que un CPE usa para decir "cualquier versión" o "ninguna". No son una
# versión que se pueda mostrar ni con la que se pueda comparar.
_EMPTY_CPE_VERSIONS = ("*", "-", "")


@dataclass
class ServiceGroup:
    """Los hallazgos de una unidad remediable, con su resumen ya hecho.

    Attributes:
        label: Nombre de la unidad — el producto con su versión, o la
            categoría sobre un servicio cuando no hay producto que nombrar.
        is_product: Si la unidad es un producto identificado. Es lo que separa
            «actualiza Apache 2.4.52» de «faltan tres cabeceras en http:80»:
            dos clases de trabajo distintas, que merecen presentarse aparte.
        port / service: El servicio afectado.
        findings: Los hallazgos del grupo, en el orden en que llegaron.
        cve_ids / kev_cve_ids: CVEs distintos del grupo, y cuáles de ellos
            están en la lista CISA KEV (explotación activa confirmada).
        max_cvss / max_epss: Los máximos del grupo, que son los que mandan al
            priorizarlo.
        fixed_version: La cota de versión más alta del grupo. Es la única que
            tiene sentido recomendar: cierra también todas las inferiores, así
            que actualizar hasta ahí resuelve el grupo entero de una vez.
        confirmed_count: Cuántos hallazgos se confirmaron activamente, frente a
            los deducidos de un número de versión.
        by_priority: Recuento por nivel de prioridad.
    """

    label: str
    is_product: bool
    port: Optional[int]
    service: Optional[str]
    findings: List[dict] = field(default_factory=list)
    cve_ids: List[str] = field(default_factory=list)
    kev_cve_ids: List[str] = field(default_factory=list)
    max_cvss: Optional[float] = None
    max_epss: Optional[float] = None
    fixed_version: Optional[str] = None
    confirmed_count: int = 0
    by_priority: Dict[str, int] = field(default_factory=dict)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def total_cves(self) -> int:
        return len(self.cve_ids)

    @property
    def worst_priority(self) -> str:
        """La prioridad que representa al grupo: la peor que contiene.

        Un grupo se atiende por su peor hallazgo, no por su media: doce avisos
        informativos junto a un CRITICAL siguen siendo un CRITICAL que hay que
        mirar hoy.

        Vivía en ``LybraEngineManager._worst_priority``, es decir en la capa
        que toca ORM, cuando el dato sale entero de ``by_priority`` y no
        necesita nada de infraestructura. Estaba bien mientras el único
        consumidor era la API; con el informe PDF agrupando también, dejarlo
        allí obligaba al generador del informe a importar un manager para
        calcular una propiedad de un dato que ya tiene en la mano.
        """
        present = [level for level in reversed(PRIORITY_LADDER) if self.by_priority.get(level)]
        return present[0] if present else "INFO"


def group_label(finding: dict) -> Tuple[str, bool]:
    """La unidad remediable a la que pertenece un hallazgo, y si es un producto.

    Con CPE resuelto la unidad es el producto y su versión ("http server
    2.4.7"): actualizarlo cierra todos sus CVEs de golpe.

    Sin CPE —cabeceras ausentes, puertos abiertos, fingerprints— la unidad es
    la categoría sobre ese servicio, no el hallazgo suelto: las tres cabeceras
    que faltan en http:80 se arreglan de una sola pasada por la configuración
    del servidor, así que agruparlas por título produciría tres "productos" de
    un elemento y desdibujaría el inventario.

    Returns:
        La etiqueta y si corresponde a un producto identificado.
    """
    parsed = parse_cpe23(finding["cpe"]) if finding.get("cpe") else None
    if parsed and parsed.get("product"):
        product = parsed["product"].replace("_", " ")
        version = parsed.get("version") or ""
        if version in _EMPTY_CPE_VERSIONS:
            return product, True
        return f"{product} {version}".strip(), True

    category = finding.get("category") or "hallazgo"
    service = finding.get("service") or "servicio"
    return f"{category} ({service})", False


def version_key(version: str) -> tuple:
    """Ordena versiones tipo '2.4.52' numéricamente, no lexicográficamente.

    Sin esto '2.4.9' saldría por encima de '2.4.52'. Los segmentos no numéricos
    (p. ej. '1p1') caen a 0: basta para elegir la cota más alta.
    """
    return tuple(int(part) if part.isdigit() else 0 for part in str(version).split("."))


def build_service_rollup(findings: list, max_groups: Optional[int] = None) -> List[ServiceGroup]:
    """Agrupar hallazgos por servicio afectado, ordenados de más grave a menos.

    Args:
        findings: Hallazgos ya serializados a dict (``cpe``, ``port``,
            ``service``, ``category``, ``cve_ids``, ``cvss_score``,
            ``epss_score``, ``in_kev``, ``confirmed``, ``priority`` y, si el
            llamante lo resolvió antes, ``fixed_version``).
        max_groups: Tope de grupos devueltos. Como el orden es por severidad,
            recortar descarta siempre los menos graves primero. ``None`` (por
            defecto) no recorta: el tope existe para el prompt de IA, donde el
            tamaño del payload importa, y no para la interfaz, donde esconder
            grupos sin decirlo sería mentir por omisión.

    Returns:
        Los grupos, de mayor a menor CVSS máximo.
    """
    groups: Dict[tuple, ServiceGroup] = {}
    kev_by_group: Dict[tuple, set] = {}
    cves_by_group: Dict[tuple, set] = {}

    for finding in findings:
        label, is_product = group_label(finding)
        key = (finding.get("port"), finding.get("service"), label)
        group = groups.get(key)
        if group is None:
            group = ServiceGroup(
                label=label,
                is_product=is_product,
                port=finding.get("port"),
                service=finding.get("service"),
            )
            groups[key] = group
            kev_by_group[key] = set()
            cves_by_group[key] = set()

        group.findings.append(finding)
        finding_cves = finding.get("cve_ids") or []
        cves_by_group[key].update(finding_cves)
        if finding.get("in_kev"):
            kev_by_group[key].update(finding_cves)
        if finding.get("confirmed"):
            group.confirmed_count += 1

        priority = finding.get("priority", "INFO")
        group.by_priority[priority] = group.by_priority.get(priority, 0) + 1

        cvss = finding.get("cvss_score")
        if cvss is not None and (group.max_cvss is None or cvss > group.max_cvss):
            group.max_cvss = cvss
        epss = finding.get("epss_score")
        if epss is not None and (group.max_epss is None or epss > group.max_epss):
            group.max_epss = epss

        # La cota más alta cierra también todas las inferiores del grupo, así
        # que es la única versión destino que tiene sentido recomendar.
        fixed = finding.get("fixed_version")
        if fixed and (group.fixed_version is None
                      or version_key(fixed) > version_key(group.fixed_version)):
            group.fixed_version = fixed

    for key, group in groups.items():
        group.cve_ids = sorted(cves_by_group[key])
        group.kev_cve_ids = sorted(kev_by_group[key])

    rollup = sorted(groups.values(), key=lambda group: -(group.max_cvss or 0))
    return rollup[:max_groups] if max_groups is not None else rollup
