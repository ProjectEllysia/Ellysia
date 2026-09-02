"""La cascada de identificación — para servicios que no están donde deberían.

Todos los predicados de aplicabilidad del motor deciden con la misma fórmula:
*el nombre del servicio está en esta lista, o el puerto está en este conjunto*.
Y cuando el descubrimiento es propio (Fase T, sin Nmap), el nombre del servicio
sale de ``WELL_KNOWN_PORTS``, que es **otra tabla de puertos**. Es decir: en el
camino de autodescubrimiento, la decisión era puramente el número de puerto.

La consecuencia es un punto ciego grande y muy común en redes reales: un MySQL
en el 33060, un SSH en el 2222, un Redis en el 6380, un PostgreSQL en el 5433,
un panel web en el 8081, una base de datos movida a propósito "para no salir en
los escaneos". Ninguno recibía dissector; todos producían un ``open_port`` con
``qod=30`` y ahí se acababa. Sin producto no hay CPE, sin CPE no hay CVE.

Ésa era la diferencia de fondo con Nmap y con OpenVAS: los dos identifican un
servicio **por lo que responde**, no por dónde escucha.

Y había una ironía: el motor ya sabía hacerlo. Siete de sus dissectors leen un
banner que el servicio ofrece sin que nadie se lo pida. Lo que faltaba no era
capacidad de leer, era permiso para intentarlo.

Esta cascada es una versión honesta y acotada de lo que hace ``nmap -sV``: no
un fichero de miles de sondas, sino "prueba lo que ya sabes leer". Tiene tres
escalones y **ninguno se ejecuta si un dissector ya reclamó el servicio**, así
que la ruta rápida de los servicios en su puerto de siempre no paga nada:

1. Una conexión, y se lee lo que el servicio ofrezca por su cuenta con un
   plazo corto. Ese banner se ofrece a cada dissector que sepa leer uno
   (:meth:`Dissector.identify_from_banner`); el primero que lo reconozca gana.
2. Si el servicio no dice nada, se prueban en orden unas pocas sondas activas
   baratas — las de los dissectors que declaran :attr:`Dissector.tries_blind`,
   hoy Redis (``INFO``) y HTTP (``GET /``) — con un **presupuesto explícito**.
3. Si sigue mudo, no hay identificación. Un puerto que acepta la conexión y no
   contesta a nada sigue siendo un ``open_port`` informativo, como antes.

La lista de intentos es **dato derivado del registro**, no una lista paralela:
un dissector nuevo entra en la cascada por declarar sus dos capacidades, sin
que este módulo cambie. Ése es justamente el error que #272 documentó — un mapa
escrito a mano que se quedó con dos entradas mientras el módulo definía once.
"""

from __future__ import annotations

import logging
import socket
from typing import Callable, List, Optional, Sequence

from ..engine import Service
from .dispatch import Dissector, DissectorResult

logger = logging.getLogger(__name__)


def read_volunteered_banner(
    host: str,
    port: int,
    timeout: float,
    connect: Optional[Callable] = None,
) -> Optional[bytes]:
    """Conecta y lee lo que el servicio diga sin que se le pregunte nada.

    Una sola lectura y un plazo corto: no se negocia, no se manda nada, no se
    espera a un segundo paquete. Un servicio que no saluda deja el plazo
    correr, y por eso el plazo es corto — es el coste que se paga por cada
    puerto desconocido, multiplicado por cuantos haya.

    Args:
        host: El objetivo.
        port: El puerto.
        timeout: El plazo de conexión y de lectura, en segundos.
        connect: Callable ``(address, timeout) -> socket`` inyectable, mismo
            patrón que el resto de sondas del paquete.

    Returns:
        Los bytes recibidos, o ``None`` si la conexión falla o el servicio no
        dice nada.
    """
    opener = connect or socket.create_connection
    try:
        sock = opener((host, port), timeout)
    except OSError as err:
        logger.debug("Cascada: conexión fallida a %s:%s: %s", host, port, err)
        return None
    try:
        sock.settimeout(timeout)
        banner = sock.recv(1024)
        return banner or None
    except OSError as err:
        logger.debug("Cascada: sin saludo de %s:%s: %s", host, port, err)
        return None
    finally:
        try:
            sock.close()
        except OSError:
            pass


def banner_readers(dissectors: Sequence[Dissector]) -> List[Dissector]:
    """Los dissectors que saben identificar desde un banner ofrecido.

    Se deriva preguntándole a cada uno si sobrescribe
    :meth:`Dissector.identify_from_banner`, no de una lista aparte: una lista
    aparte es exactamente lo que se queda desincronizada.

    Args:
        dissectors: Los dissectors del registro.

    Returns:
        Los que sí leen banners, en orden de registro.
    """
    return [
        dissector for dissector in dissectors
        if type(dissector).identify_from_banner is not Dissector.identify_from_banner
    ]


def blind_probers(dissectors: Sequence[Dissector]) -> List[Dissector]:
    """Los dissectors que se pueden intentar contra un servicio mudo."""
    return [dissector for dissector in dissectors if dissector.tries_blind]


def identify_unknown_service(  # pylint: disable=too-many-arguments
    target: str,
    service: Service,
    dissectors: Sequence[Dissector],
    rate_limiter,
    *,
    banner_timeout: float = 2.0,
    max_blind_probes: int = 2,
    connect: Optional[Callable] = None,
) -> Optional[DissectorResult]:
    """Intenta identificar un servicio que ningún dissector ha reclamado.

    Ver el docstring del módulo para los tres escalones y por qué existen.

    Args:
        target: El host objetivo.
        service: El servicio descubierto, sin nombre reconocible.
        dissectors: Los dissectors del registro.
        rate_limiter: El limitador de ritmo por host; cada intento pide turno.
        banner_timeout: El plazo de la lectura del saludo, en segundos.
        max_blind_probes: Cuántas sondas activas se permiten como máximo por
            servicio desconocido. El presupuesto que impide que esto se
            convierta en un escaneo de servicios completo.
        connect: Callable de conexión inyectable para la lectura del saludo.

    Returns:
        La identificación, o ``None`` si el servicio no dijo nada reconocible.
    """
    rate_limiter.acquire(target)
    banner = read_volunteered_banner(target, service.port, banner_timeout, connect)

    if banner:
        for dissector in banner_readers(dissectors):
            try:
                identified = dissector.identify_from_banner(banner)
            except Exception:  # noqa: BLE001 - un parser no puede tumbar la cascada
                logger.debug("Cascada: %s falló leyendo el banner de %s:%s",
                             dissector.label, target, service.port, exc_info=True)
                continue
            if identified is not None:
                logger.debug("Cascada: %s:%s identificado como %s por su saludo",
                             target, service.port, identified.label)
                return identified

    if max_blind_probes <= 0:
        return None

    for dissector in blind_probers(dissectors)[:max_blind_probes]:
        try:
            probed = dissector.probe(target, service, rate_limiter)
        except Exception:  # noqa: BLE001 - misma garantía de aislamiento
            logger.debug("Cascada: sonda a ciegas %s falló contra %s:%s",
                         dissector.label, target, service.port, exc_info=True)
            continue
        if probed is not None and probed.product:
            logger.debug("Cascada: %s:%s identificado como %s por sonda a ciegas",
                         target, service.port, probed.label)
            return probed

    return None
