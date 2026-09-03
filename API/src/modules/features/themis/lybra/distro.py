"""De qué distribución es este paquete, y sólo cuando se puede saber.

La verificación de *backports* (Fase O) necesita saber contra qué proveedor
preguntar: si Debian ya parcheó ``apache2`` en su ``2.4.49-1~deb11u1``, esa
respuesta no vale para un Apache compilado a mano ni para uno de Alpine.

El roadmap dejó esta pieza sin resolver y enumeró tres salidas: aplicar sólo
cuando el inventario del agente dé la distribución, inferirla del banner cuando
lo diga, o aplicar el descenso cuando **todas** las distribuciones candidatas
coincidan en que está parcheado.

**La tercera se descarta**, y conviene decir por qué: un paquete compilado
desde el código fuente no pertenece a ninguna distribución, así que "todas
coinciden en que está parcheado" sería cierto y la conclusión falsa —
justamente en el caso donde la vulnerabilidad sí existe. Optimizar la tasa de
falsos positivos a costa de falsos negativos es el peor cambio posible para un
escáner en el que hay que confiar.

Quedan las dos primeras, y aquí se implementan ambas por el mismo camino: **no
se adivina nunca**. Si ninguna señal dice de qué distribución es, la
verificación no se aplica y el hallazgo se queda como estaba, con su ``qod=70``
y su ``confirmed=false``. Callar es la respuesta correcta cuando no se sabe.

La señal más fuerte no es el banner sino la **revisión del propio paquete**:
``1:2.4.49-1ubuntu1`` sólo lo escribe Ubuntu, ``2.4.49-1~deb11u1`` sólo Debian
(y dice hasta la versión), ``2.4.49-r0`` sólo Alpine, ``2.4.49-1.el8`` sólo la
familia de Red Hat. Eso ya lo extrae :func:`~.kb.split_distro_version` desde
#267 — aquí sólo se lee.
"""

from __future__ import annotations

import re
from typing import NamedTuple, Optional

from .kb import split_distro_version


class DistroRelease(NamedTuple):
    """La distribución de un paquete, y su versión cuando consta.

    Attributes:
        vendor: ``"debian"``, ``"ubuntu"``, ``"alpine"`` o ``"rhel"``.
        release: La versión de la distribución (``"11"``, ``"8"``), o ``None``
            si la señal no llegaba a tanto. Un ``None`` no es un fallo: hay
            avisos que aplican a todas las versiones del proveedor, y forzar
            una inventada sería peor que no tenerla.
    """

    vendor: str
    release: Optional[str]


# Una revisión de Debian nombra su versión cuando es una actualización de
# seguridad: "-1~deb11u1", "+deb12u2". El número que sigue a "deb" es la
# release, y es la señal más precisa que hay sin entrar en el host.
_DEBIAN_REVISION = re.compile(r"deb(\d+)u\d+", re.IGNORECASE)

# Ubuntu escribe su nombre en la revisión, pero no su versión: "1ubuntu1",
# "0ubuntu0.22.04.1" sí la lleva, y por eso se intenta leer.
_UBUNTU_REVISION = re.compile(r"ubuntu(?:\d+\.)?(\d+\.\d+)?", re.IGNORECASE)

# La familia de Red Hat marca la release en el propio sufijo: ".el8", ".el9".
_RHEL_REVISION = re.compile(r"\.el(\d+)", re.IGNORECASE)

# Alpine no tiene más marca que su forma de revisión: "r0", "r14".
_ALPINE_REVISION = re.compile(r"^r\d+$", re.IGNORECASE)

# Lo que un banner dice de sí mismo. Apache escribe "(Ubuntu)", "(Debian)" o
# "(Red Hat Enterprise Linux)" en su Server, y es una afirmación del propio
# servicio, no una deducción nuestra.
_BANNER_VENDORS = (
    ("ubuntu", "ubuntu"),
    ("debian", "debian"),
    ("red hat", "rhel"),
    ("redhat", "rhel"),
    ("centos", "rhel"),
    ("rocky", "rhel"),
    ("almalinux", "rhel"),
    ("alpine", "alpine"),
)


def infer_distro_release(version: str = "", banner: str = "") -> Optional[DistroRelease]:
    """De qué distribución viene un paquete, o ``None`` si no consta.

    Se miran dos señales, la más fiable primero:

    1. **La revisión del propio paquete.** Sólo la escribe quien empaqueta, así
       que no admite ambigüedad: un ``1~deb11u1`` es Debian 11 y no puede ser
       otra cosa. Está disponible siempre que el hallazgo venga del inventario
       de un agente, que es donde los *backports* más duelen.
    2. **El banner del servicio**, cuando el propio servicio lo declara
       (``Apache/2.4.49 (Ubuntu)``). No dice la versión de la distribución,
       pero decir el proveedor ya acota la pregunta.

    Args:
        version: La versión del paquete, tal cual se descubrió.
        banner: El producto o banner del servicio.

    Returns:
        La distribución, o ``None`` cuando ninguna señal la nombra — que es el
        caso de un binario compilado a mano, y el caso en el que **no hay que
        aplicar** ninguna verificación de backport.
    """
    from_version = _from_package_revision(version or "")
    if from_version is not None:
        return from_version
    return _from_banner(banner or "")


def _from_package_revision(version: str) -> Optional[DistroRelease]:
    """La distribución según cómo empaquetó su revisión."""
    _epoch, _upstream, revision = split_distro_version(version)
    if not revision:
        return None

    debian = _DEBIAN_REVISION.search(revision)
    if debian:
        return DistroRelease("debian", debian.group(1))

    rhel = _RHEL_REVISION.search(revision)
    if rhel:
        return DistroRelease("rhel", rhel.group(1))

    if "ubuntu" in revision.lower():
        ubuntu = _UBUNTU_REVISION.search(revision)
        release = ubuntu.group(1) if ubuntu and ubuntu.group(1) else None
        return DistroRelease("ubuntu", release)

    if _ALPINE_REVISION.match(revision):
        return DistroRelease("alpine", None)

    return None


def _from_banner(banner: str) -> Optional[DistroRelease]:
    """La distribución según lo que el propio servicio dice de sí mismo."""
    lowered = banner.lower()
    for needle, vendor in _BANNER_VENDORS:
        if needle in lowered:
            return DistroRelease(vendor, None)
    return None
