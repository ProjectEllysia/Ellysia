"""La sonda de Telnet — porque que exista ya es el hallazgo.

El roadmap descartó el *dissector* de Telnet con buen criterio: su negociación
de opciones (IAC) no deja un texto identificable de forma fiable sin inventar
patrones, así que no hay un producto/versión que leer. Pero el *check* es otra
cosa. Telnet manda credenciales en claro por diseño; que un servicio esté ahí,
hablando el protocolo, ya es un hallazgo de configuración de red —el que la
Fase N prometía— sin necesidad de identificar nada.

Lo que este módulo comprueba es exactamente eso y nada más: que al otro lado
hay algo que **habla Telnet**. Un servidor Telnet abre la conversación
negociando opciones, y esa negociación empieza siempre por el byte ``IAC``
(``0xFF``, RFC 854). Ese byte es la firma: un puerto 23 que lo envía es Telnet;
uno que acepta la conexión y calla, o que manda otra cosa, no se cuenta —
podría ser cualquier servicio mudo en un puerto reutilizado.
"""

from __future__ import annotations

import logging
import socket
from typing import Callable, Optional

logger = logging.getLogger(__name__)

# IAC — "Interpret As Command", el byte que abre toda negociación de opciones
# de Telnet (RFC 854). Su sola presencia al principio de la respuesta es la
# firma del protocolo.
TELNET_IAC = 0xFF


class TelnetProbe:  # pylint: disable=too-few-public-methods
    """Comprueba si un puerto habla Telnet leyendo su negociación de apertura.

    Args:
        timeout: El plazo de conexión y lectura, en segundos.
        connect: Callable ``(address, timeout) -> socket`` inyectable, para que
            un test use un socket falso.
    """

    def __init__(self, timeout: float = 5.0, connect: Optional[Callable] = None) -> None:
        self._timeout = timeout
        self._connect = connect or socket.create_connection

    def speaks_telnet(self, host: str, port: int = 23) -> bool:
        """Devuelve ``True`` sólo si el servicio abre negociando opciones Telnet.

        Args:
            host: El objetivo.
            port: El puerto.

        Returns:
            ``True`` cuando la respuesta empieza por ``IAC``. Un servicio mudo o
            que manda otra cosa devuelve ``False``: no se infiere Telnet de un
            puerto abierto, se confirma por lo que responde.
        """
        try:
            sock = self._connect((host, port), self._timeout)
        except OSError as err:
            logger.debug("Telnet: conexión fallida a %s:%s: %s", host, port, err)
            return False
        try:
            sock.settimeout(self._timeout)
            data = sock.recv(3)
            return bool(data) and data[0] == TELNET_IAC
        except OSError as err:
            logger.debug("Telnet: sin respuesta de %s:%s: %s", host, port, err)
            return False
        finally:
            try:
                sock.close()
            except OSError:
                pass
