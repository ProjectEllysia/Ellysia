"""Los objetivos reales que el operador declara, y la lista blanca que abren.

Este dato lo leen dos sitios que **no pueden discrepar**: el sello de red de la
suite (``tests/conftest.py``), que decide a qué direcciones se deja salir, y el
banco de paridad real (``test_lybra_real_parity_bench.py``), que decide a cuáles
escanear. Si cada uno releyera la variable por su cuenta, una diferencia tonta
—un ``strip`` de más, un separador distinto— dejaría al banco intentando llegar
a un sitio que el sello bloquea, o peor, al sello abriendo una dirección que el
banco ni usa.

Vive en un módulo propio, y no en el conftest, porque el conftest no se puede
importar por nombre sin ambigüedad: hay más de uno en el árbol de tests
(``tests/postgres/conftest.py``), y cuál gana depende del orden de recolección.
El conftest lo carga por ruta.

Not a test module itself (no ``test_`` prefix) — pytest does not collect it.
"""

from __future__ import annotations

import ipaddress
import os
import socket
from typing import Set, Tuple

#: La variable que declara el lado real de la paridad laboratorio/real.
ENVIRONMENT_VARIABLE = "LYBRA_REAL_TARGETS"


def declared_real_targets() -> Tuple[str, ...]:
    """Los objetivos reales declarados por quien ejecuta la suite.

    Una lista separada por comas de hosts o IPs sobre los que quien ejecuta
    afirma tener autorización de escaneo. Vacía por defecto, que es lo que hace
    que el banco de paridad real se salte solo y que la suite no salga a la red
    en ninguna máquina que no lo haya pedido.

    No se lee de ningún fichero del repositorio a propósito: las direcciones de
    un laboratorio real no tienen por qué publicarse, y una autorización de
    escaneo es de quien la tiene, no del repositorio.
    """
    raw = os.environ.get(ENVIRONMENT_VARIABLE, "")
    return tuple(target.strip() for target in raw.split(",") if target.strip())


def allowed_outbound_addresses() -> Set[str]:
    """Direcciones IP concretas a las que el sello de red deja salir.

    Se resuelven **una vez**, antes de instalar el sello. No es "abrir la red
    durante la sesión": es una lista blanca de las direcciones que el operador
    declaró, y el resto de la suite —incluidos los tests que dependen de que un
    socket a 10.0.0.5 falle al instante— sigue exactamente igual de sellada.

    Un objetivo que no resuelve no abre ningún agujero ni hunde a los demás: se
    ignora aquí, y el banco lo reportará como inalcanzable cuando le toque, que
    es donde se ve.
    """
    allowed: Set[str] = set()
    for target in declared_real_targets():
        try:
            allowed.add(ipaddress.ip_address(target).compressed)
            continue
        except ValueError:
            pass
        try:
            allowed.update(info[4][0] for info in socket.getaddrinfo(target, None))
        except OSError:
            pass
    return allowed
