"""El catálogo de favicons — identificar producto cuando el servidor no dice nada.

El hash del favicon es una de las técnicas más eficaces que existen para
reconocer un producto web que se niega a identificarse. Un panel de Jenkins, un
login de GitLab, un vCenter o un Fortinet tienen el **mismo** icono en todas
sus instalaciones: sobrevive a ``server_tokens off``, no cambia entre versiones
menores, y nadie se acuerda de personalizarlo. Shodan la expone como
``http.favicon.hash`` precisamente porque funciona.

``HttpDissector.probe`` pide ``/favicon.ico`` una vez por servicio HTTP,
``fingerprint_http`` calcula su SHA-256 y ``HttpFingerprint`` lo expone como
campo; este módulo es quien de verdad lo consulta, resolviéndolo contra el
catálogo de abajo.

Dos decisiones de diseño, ambas explícitas:

**El algoritmo es el de la convención pública, no SHA-256.** Shodan —y todas
las herramientas que consumen sus datos— hashean el favicon **codificado en
base64** con MurmurHash3 de 32 bits, no los bytes crudos con SHA-256. Adoptar
esa convención es la diferencia entre poder reutilizar catálogos públicos
existentes y tener que construir el nuestro desde cero, que a su vez es la
diferencia entre veinte entradas y varios miles. Se guardan los dos: el
SHA-256 como identidad exacta del fichero, el MurmurHash3 como clave de
catálogo.

MurmurHash3 va implementado aquí, en treinta líneas, en vez de traer la
dependencia ``mmh3`` (una extensión en C) por una sola función. Mismo criterio
que llevó a construir SNMP sin ``pysnmp`` y el parseo BER a mano.

**Un favicon identifica producto, casi nunca versión.** Así que esto alimenta
el *nombre* —y con él las firmas de tecnología y la cascada de versión—, nunca
un CPE completo por sí solo. El catálogo no tiene ni un campo de versión, para
que no se pueda hacer aunque se quiera.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional


# El feed vive junto a los demás de Lybra. Dos directorios arriba:
# fingerprinting/favicon.py -> lybra/feeds/.
_BUNDLED_FAVICON_HASHES = Path(__file__).parent.parent / "feeds" / "favicon_hashes.json"

_C1 = 0xCC9E2D51
_C2 = 0x1B873593
_MASK = 0xFFFFFFFF


def _rotl32(value: int, bits: int) -> int:
    """Rota ``value`` a la izquierda dentro de 32 bits."""
    return ((value << bits) | (value >> (32 - bits))) & _MASK


def murmurhash3_x86_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 de 32 bits, variante x86, con resultado con signo.

    Transcripción directa de la implementación de referencia de Austin Appleby.
    El resultado se devuelve **con signo** porque así es como lo publica la
    librería ``mmh3`` de Python, y por tanto como aparecen los hashes en todos
    los catálogos públicos: un valor de catálogo copiado de fuera tiene que
    poder compararse tal cual, sin que nadie recuerde convertirlo.

    Args:
        data: Los bytes a hashear.
        seed: La semilla; 0 es la que usa la convención pública.

    Returns:
        El hash, como entero de 32 bits con signo.
    """
    length = len(data)
    h1 = seed & _MASK
    rounded_end = length & ~0x3

    for start in range(0, rounded_end, 4):
        k1 = int.from_bytes(data[start:start + 4], "little")
        k1 = (k1 * _C1) & _MASK
        k1 = _rotl32(k1, 15)
        k1 = (k1 * _C2) & _MASK
        h1 ^= k1
        h1 = _rotl32(h1, 13)
        h1 = (h1 * 5 + 0xE6546B64) & _MASK

    tail = data[rounded_end:]
    if tail:
        k1 = int.from_bytes(tail + b"\x00" * (4 - len(tail)), "little")
        k1 = (k1 * _C1) & _MASK
        k1 = _rotl32(k1, 15)
        k1 = (k1 * _C2) & _MASK
        h1 ^= k1

    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & _MASK
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & _MASK
    h1 ^= h1 >> 16

    return h1 - 0x100000000 if h1 & 0x80000000 else h1


def favicon_hash(favicon: bytes) -> int:
    """Calcula el hash de catálogo de un favicon, en la convención pública.

    El favicon se codifica primero en base64 **con saltos de línea cada 76
    caracteres y un salto final** —lo que produce ``base64.encodebytes``, que es
    lo mismo que el ``codecs.encode(data, "base64")`` del código de referencia—
    y el hash se calcula sobre ese texto, no sobre los bytes crudos. Ese detalle
    no es un capricho: es lo que hace que el número coincida con el de cualquier
    catálogo público, y sin coincidencia el catálogo no vale para nada.

    Args:
        favicon: Los bytes crudos del favicon.

    Returns:
        El hash de 32 bits con signo.
    """
    return murmurhash3_x86_32(base64.encodebytes(favicon))


@dataclass(frozen=True)
class FaviconEntry:
    """Una entrada del catálogo: un hash y el producto al que pertenece.

    Attributes:
        hash_value: El hash de catálogo (:func:`favicon_hash`), con signo.
        product: El nombre del producto, tal y como debe aparecer en el
            hallazgo. Nunca lleva versión: un favicon no la identifica.
        vendor: El fabricante, cuando aporta algo. Opcional.
        source: De dónde salió la entrada, para que cada hash sea auditable.
            Un número sin procedencia no se puede verificar ni corregir.
    """
    hash_value: int
    product: str
    vendor: Optional[str] = None
    source: Optional[str] = None


def load_favicon_hashes(path: Optional[str] = None) -> List[FaviconEntry]:
    """Carga el catálogo de favicons.

    Args:
        path: Ruta a un fichero de catálogo. Por defecto, el empaquetado.

    Returns:
        Las entradas del catálogo.
    """
    feed_path = Path(path) if path else _BUNDLED_FAVICON_HASHES
    data = json.loads(feed_path.read_text(encoding="utf-8"))
    return [
        FaviconEntry(
            hash_value=int(entry["hash"]),
            product=entry["product"],
            vendor=entry.get("vendor"),
            source=entry.get("source"),
        )
        for entry in data.get("favicons", [])
    ]


def validate_favicon_hashes(entries: List[FaviconEntry]) -> List[str]:
    """Comprueba que el catálogo esté bien formado, y describe lo que no lo esté.

    Mismo criterio que los demás feeds de Lybra: su modo de fallo es el
    silencio. Una entrada sin producto no identifica nada; dos entradas con el
    mismo hash y productos distintos hacen que una de las dos no se consulte
    jamás, y cuál de las dos depende del orden del fichero.

    La procedencia es obligatoria a propósito. Un hash es un número de diez
    dígitos que nadie puede revisar de memoria: sin decir de dónde salió, no hay
    forma de comprobarlo ni de corregirlo cuando el producto cambie de icono.

    Args:
        entries: Las entradas cargadas.

    Returns:
        Una lista de problemas legibles, vacía si el catálogo está bien formado.
    """
    problems: List[str] = []
    by_hash: Dict[int, str] = {}
    for entry in entries:
        if not entry.product:
            problems.append(f"La entrada con hash {entry.hash_value} no nombra producto")
        if not entry.source:
            problems.append(f"{entry.product or entry.hash_value}: sin procedencia declarada")
        previous = by_hash.get(entry.hash_value)
        if previous is not None and previous != entry.product:
            problems.append(
                f"Hash {entry.hash_value} repetido para productos distintos: "
                f"{previous} y {entry.product}"
            )
        by_hash[entry.hash_value] = entry.product
    return problems


class FaviconCatalog:
    """El catálogo cargado, listo para consultar por hash.

    Args:
        entries: Las entradas; por defecto, las del feed empaquetado.
    """

    def __init__(self, entries: Optional[List[FaviconEntry]] = None) -> None:
        self._by_hash: Dict[int, FaviconEntry] = {
            entry.hash_value: entry
            for entry in (entries if entries is not None else load_favicon_hashes())
        }

    def __len__(self) -> int:
        return len(self._by_hash)

    @property
    def is_empty(self) -> bool:
        """Si el catálogo no tiene ni una entrada.

        Lo consulta ``HttpDissector.probe`` para **no pedir el favicon** cuando
        no hay nada con lo que compararlo. Es la respuesta al reproche que
        originó este módulo: pagar una sonda por un dato muerto no se justifica,
        y con esto la sonda sólo se paga cuando puede pagarse a sí misma.
        """
        return not self._by_hash

    def identify(self, favicon: Optional[bytes]) -> Optional[FaviconEntry]:
        """Identifica un producto por su favicon.

        Args:
            favicon: Los bytes crudos del favicon, o ``None``.

        Returns:
            La entrada del catálogo, o ``None`` si no hay favicon o su hash no
            está catalogado. Un favicon desconocido no produce identificación:
            nunca se deduce un producto de un icono que no se reconoce.
        """
        if not favicon:
            return None
        return self._by_hash.get(favicon_hash(favicon))
