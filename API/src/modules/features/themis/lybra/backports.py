"""Preguntarle al proveedor si esa vulnerabilidad ya está corregida.

Un *backport* es una distribución arreglando un fallo sin subir el número de
versión visible: Debian parchea ``apache2``, el banner sigue diciendo
``2.4.49``, y el motor emite una CVE que ya no existe. Es la causa número uno
de falsos positivos de toda la detección por versión — se ha medido en
**0,42**: cuatro de cada diez CVEs reportados contra un Debian o un Ubuntu ya
estaban corregidos.

Hasta ahora la mitigación era un paliativo declarado (``qod=70``,
``confirmed=false``) que le dice al lector que *puede* ser falso pero no cuál lo
es, que es justo lo que quería saber. Y la verdad no hay que ir a buscarla
dentro del host: Debian, Ubuntu y Red Hat publican exactamente qué paquete
quedó corregido y en qué versión.

Este módulo es la aplicación de esa verdad sobre los hallazgos ya producidos.
Es puro —recibe una función de consulta y devuelve veredictos— para que el
paquete siga libre de ORM.

**Nunca se adivina.** Si no consta de qué distribución es el paquete
(:mod:`~.distro`), o si el proveedor no se ha pronunciado sobre esa CVE, el
hallazgo se queda exactamente como estaba. Bajar un hallazgo por una
suposición sería cambiar falsos positivos por falsos negativos, que en un
escáner es el peor negocio posible.
"""

from __future__ import annotations

from typing import Callable, List, Optional

from .distro import DistroRelease, infer_distro_release
from .kb import version_compare

#: Lo que responde una consulta al espejo de avisos: el estado que el proveedor
#: declara y, si lo corrigió, en qué versión.
PackageStatus = tuple  # (status: str, fixed_in: Optional[str])

#: El check con el que se firma un hallazgo que el proveedor desmintió o
#: confirmó. Se estampa para que un hallazgo sepa decir por qué cambió de
#: estado, y para que el desmentido caduque solo si este check cambia de
#: versión (ver ``apply_lifecycle``).
BACKPORT_CHECK_ID = "lybra:oval-backport@1"


def apply_backport_verdicts(
    findings: List[dict],
    status_lookup: Callable[[str, Optional[str], str, str], Optional[PackageStatus]],
) -> List[dict]:
    """Contrastar cada hallazgo por versión con lo que dice su distribución.

    Tres desenlaces, y sólo dos cambian algo:

    - **El proveedor ya lo corrigió** en una versión menor o igual que la
      instalada → el hallazgo pasa a ``state="fixed"`` y ``confirmed=False``.
      No es que se haya remediado ahora: es que nunca estuvo, y el motor lo
      había deducido de un número de versión que miente.
    - **El proveedor dice que sigue vulnerable** → asciende a
      ``confirmed=True`` con ``qod=90``. Dos fuentes independientes —la versión
      y el propio empaquetador— coinciden, que es una evidencia mucho más
      fuerte que la deducción sola.
    - **No consta** —ni la distribución ni el pronunciamiento— → no se toca.

    Args:
        findings: Los hallazgos del escaneo. Sólo se miran los de categoría
            ``outdated_software`` con CVE: son los únicos que nacen de una
            comparación de versiones y, por tanto, los únicos que un backport
            puede desmentir.
        status_lookup: ``(vendor, release, package, cve_id)`` → ``(status,
            fixed_in)`` o ``None``. Inyectada porque consulta la base de datos
            y este paquete no la toca.

    Returns:
        La misma lista, con los hallazgos que cambiaron ya modificados.
    """
    for finding in findings:
        if finding.get("category") != "outdated_software":
            continue
        cve_ids = finding.get("cve_ids") or []
        if not cve_ids:
            continue

        release = _release_for(finding)
        if release is None:
            continue          # sin distribución no hay a quién preguntar

        package = _package_name(finding)
        if not package:
            continue

        status = status_lookup(release.vendor, release.release, package, cve_ids[0])
        if status is None:
            continue          # el proveedor no se ha pronunciado

        _apply(finding, status, finding.get("_installed_version") or "")
    return findings


def _apply(finding: dict, status: PackageStatus, installed: str) -> None:
    """Traducir el pronunciamiento del proveedor a un cambio en el hallazgo."""
    state, fixed_in = status

    if state == "fixed" and fixed_in:
        # La versión instalada tiene que estar **a la altura** del arreglo: que
        # Debian lo haya corregido en 2.4.49-1~deb11u2 no dice nada bueno de un
        # host que sigue en 2.4.49-1~deb11u1. Sin esta comparación, la
        # verificación desmentiría hallazgos legítimos, que es peor que no
        # tenerla.
        if installed and version_compare(installed, fixed_in) < 0:
            return
        finding["state"] = "fixed"
        finding["confirmed"] = False
        finding["check_id"] = BACKPORT_CHECK_ID
        return

    if state == "vulnerable":
        finding["confirmed"] = True
        finding["qod"] = 90
        finding["check_id"] = BACKPORT_CHECK_ID


def _release_for(finding: dict) -> Optional[DistroRelease]:
    """De qué distribución es el paquete de este hallazgo, si consta."""
    return infer_distro_release(
        finding.get("_installed_version") or "",
        finding.get("title") or "",
    )


def _package_name(finding: dict) -> Optional[str]:
    """El nombre con el que la distribución llama a este paquete.

    Se usa el que trae el hallazgo, en minúsculas. No es perfecto —Debian llama
    ``apache2`` a lo que NVD llama ``http_server``— y ese desajuste es
    justamente el límite conocido de esta primera vuelta: cuando los nombres no
    coinciden, la consulta no encuentra nada y el hallazgo se queda como
    estaba, que es el comportamiento seguro.

    Pendiente: una tabla de equivalencias paquete-distro ↔ producto-NVD
    resolvería este desajuste de nombres de forma sistemática en vez de
    depender de que coincidan por casualidad.
    """
    package = finding.get("_package_name") or finding.get("service") or ""
    return package.strip().lower() or None
