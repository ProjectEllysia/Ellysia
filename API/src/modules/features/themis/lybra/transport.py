"""
Lybra's own port discovery — the transport layer.

This is the always-available foundation of the roadmap's transport plan: an
unprivileged TCP ``connect`` scan built on asyncio. It lets an Lybra scan find
open ports for itself, so a scan no longer has to be handed the ports from a
prior Nmap run.

Several faster or lower-level techniques are deliberately *not* built here — a
stateless SYN fast-path, and AIMD (loss-based) rate control. They would need
raw-socket privileges (``CAP_NET_RAW``), cannot be exercised in this test
environment, and the roadmap itself treats them as later optimizations to
reach for only once measured throughput demands them. The connect scan below
is the base that is always present; a raw path would only ever be a faster
route to the same result, with Nmap still available as the oracle to check
against.

**UDP is a separate, smaller story** (Fase N/Ronda 1, roadmap §6.3): a
"connect scan" is meaningless over a datagram socket, so the only signal
available without raw sockets is a curated payload/expected-reply pair per
port — and *that* needs no ``CAP_NET_RAW`` at all, an unprivileged
``sendto``/``recvfrom`` (or a connected UDP socket, which is what this module
uses) suffices. :data:`UDP_PROBES` starts with a single row (SNMP,
port 161 — the highest-value non-HTTP dissector still missing per the
roadmap) and grows one row per protocol a check or dissector actually
consumes, not ahead of need.

The event loop is created and torn down entirely inside :func:`scan_ports_sync`
— the "asyncio island". It lives within a single synchronous worker call and
never touches the Flask process or an ORM session. The connection opener is
injectable, so the scanner can be tested without opening real sockets.

**Un barrido vacío y un barrido bloqueado no son lo mismo** (L48-c). Un
objetivo que deja de contestar a mitad de camino —él mismo, o un cortafuegos
por delante— produce un plazo agotado en cada puerto, y sumarlos daba una
lista vacía indistinguible de un host genuinamente limpio. Por eso el barrido
clasifica cada intento (:class:`PortOutcome`), lo reporta entero
(:class:`PortSweep`) y ``scan_ports_sync`` devuelve ``None`` cuando nada
contestó de ninguna forma.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import time
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Dict, Iterable, List, Optional, Tuple

from .engine import Service

logger = logging.getLogger(__name__)


# Maps a well-known TCP port to its conventional service name. Used to label a
# freshly discovered port before we have a banner for it; fingerprinting (Fase F)
# refines the label when it is enabled.
WELL_KNOWN_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
    161: "snmp", 389: "ldap", 443: "https", 445: "microsoft-ds", 465: "smtps",
    636: "ldaps",
    587: "submission", 631: "ipp", 993: "imaps", 995: "pop3s", 1433: "ms-sql-s",
    1521: "oracle", 2049: "nfs", 2375: "docker", 2376: "docker-tls",
    2379: "etcd", 3306: "mysql", 3389: "ms-wbt-server",
    3268: "globalcatldap", 3269: "globalcatldapssl",
    5432: "postgresql", 5601: "kibana", 5900: "vnc", 5985: "wsman",
    6379: "redis", 6443: "kubernetes", 8080: "http-proxy", 8443: "https-alt",
    8500: "consul", 8888: "http-alt", 9200: "elasticsearch", 27017: "mongodb",
}

# The ports swept when the caller does not specify a list: the common,
# high-signal services, plus a handful of extras. This is intentionally not a
# full 1-65535 range — sweeping everything belongs to the raw fast-path, which
# this module does not implement.
DEFAULT_PORTS: tuple = tuple(sorted(WELL_KNOWN_PORTS)) + (
    20, 69, 123, 137, 138, 512, 513, 514, 873, 1080, 1723, 2181, 3000,
    4444, 5000, 5060, 6667, 7001, 8000, 8008, 8081, 8088, 8181, 9000,
    9090, 9300, 11211,
)


# Número mínimo de puertos que hace falta barrer para que "todos expiraron"
# signifique algo. Con una lista de tres puertos, que los tres agoten el plazo
# es perfectamente posible en una red lenta; con sesenta y cuatro, no lo es.
# Por debajo de este umbral, un barrido mudo se reporta como vacío y no como
# fallo — preferimos callar antes que inventar un fallo que no está.
BLOCKED_SWEEP_MIN_PORTS = 8


class PortOutcome(Enum):
    """En qué terminó el intento de conexión a un puerto.

    El escáner tenía un solo bit —abierto o no— y esa era exactamente la
    información que le faltaba al motor. Un puerto *rechazado* (RST) y un
    puerto que *no contesta* se cuentan igual de cerrados en el resultado
    final, pero significan cosas opuestas sobre el objetivo: el primero
    demuestra que el host está vivo y contestando, el segundo no demuestra
    nada. Distinguirlos es lo que permite reconocer un barrido bloqueado (ver
    :class:`PortSweep`).
    """

    OPEN = "open"
    REFUSED = "refused"
    TIMED_OUT = "timed_out"
    UNREACHABLE = "unreachable"


@dataclass(frozen=True)
class PortSweep:
    """El resultado completo de un barrido, no sólo los puertos abiertos.

    ``scan_ports_sync`` devolvía una lista, y una lista vacía es una respuesta
    legítima: "aquí no hay nada expuesto". El problema es que también es lo que
    devuelve un barrido que el objetivo bloqueó a mitad de camino, y las dos
    cosas llegan al motor indistinguibles. La consecuencia no es sólo un
    informe incompleto: el ciclo de vida compara con el escaneo anterior y pasa
    a ``fixed`` todo lo que estaba abierto y ya no aparece, así que un barrido
    bloqueado le dice al usuario que sus vulnerabilidades fueron remediadas.

    Este objeto lleva el detalle que permite hacer la distinción; quien la usa
    es :attr:`is_blocked`.

    Attributes:
        open_ports: Los puertos que aceptaron la conexión.
        refused_ports: Los que la rechazaron activamente (RST) — prueba de que
            el host está vivo.
        timed_out_ports: Los que agotaron el plazo sin contestar nada.
        unreachable_ports: Los que fallaron por un error de red distinto de
            los dos anteriores (host inalcanzable, red caída).
        was_cancelled: Si el barrido se abandonó por cancelación, en cuyo caso
            los puertos no probados no aparecen en ninguna lista y el barrido
            nunca se considera bloqueado.
    """

    open_ports: Tuple[int, ...]
    refused_ports: Tuple[int, ...]
    timed_out_ports: Tuple[int, ...]
    unreachable_ports: Tuple[int, ...]
    was_cancelled: bool = False

    @property
    def is_blocked(self) -> bool:
        """Si el barrido parece bloqueado en vez de limpio.

        La firma de un bloqueo transitorio —el objetivo, o un dispositivo
        intermedio, deja de contestar tras una ráfaga de conexiones— es que
        **nada** contestó de ninguna forma: ni un puerto abierto, ni un solo
        RST, sólo plazos agotados. Contra un host con latencia normal eso no
        es un resultado plausible, y es justo la señal que el escáner tenía
        delante y tiraba.

        Un barrido cancelado nunca cuenta como bloqueado: se dejó a medias a
        propósito.
        """
        if self.was_cancelled:
            return False
        if self.open_ports or self.refused_ports:
            return False
        return len(self.timed_out_ports) >= BLOCKED_SWEEP_MIN_PORTS


class AsyncConnectScanner:
    """A concurrent, unprivileged TCP connect scanner.

    Attempts a real TCP connection to each port and treats a successful connect
    (or a connection *refused*, which still proves the host is up) as evidence
    the port is open. Concurrency is bounded so a scan cannot open an unlimited
    number of sockets at once.

    Args:
        concurrency: The maximum number of connection attempts in flight at once.
        timeout: The per-port connect timeout, in seconds.
        opener: An ``async (host, port) -> (reader, writer)`` callable. Defaults
            to ``asyncio.open_connection``; a test injects a fake here to avoid
            real sockets.
    """

    def __init__(
        self,
        concurrency: int = 200,
        timeout: float = 2.0,
        opener: Optional[Callable] = None
    ) -> None:
        self._concurrency = concurrency
        self._timeout = timeout
        self._opener = opener or asyncio.open_connection

    async def sweep(
        self,
        host: str,
        ports: Iterable[int],
        cancel_check: Optional[Callable[[], bool]] = None
    ) -> PortSweep:
        """Barrer los puertos de un host y clasificar cómo terminó cada intento.

        Args:
            host: El objetivo (IP o nombre).
            ports: Los puertos a probar.
            cancel_check: Callable opcional, consultado antes de cada sonda; si
                devuelve ``True`` se omiten las restantes.

        Returns:
            El :class:`PortSweep` con cada puerto en la lista de su desenlace.
        """
        semaphore = asyncio.Semaphore(self._concurrency)
        outcomes: Dict[int, PortOutcome] = {}
        was_cancelled = False

        async def probe(port: int) -> None:
            nonlocal was_cancelled
            if cancel_check and cancel_check():
                was_cancelled = True
                return
            async with semaphore:
                outcomes[port] = await self._probe_outcome(host, port)

        await asyncio.gather(*(probe(port) for port in ports))

        def ports_with(outcome: PortOutcome) -> Tuple[int, ...]:
            return tuple(sorted(port for port, result in outcomes.items() if result is outcome))

        return PortSweep(
            open_ports=ports_with(PortOutcome.OPEN),
            refused_ports=ports_with(PortOutcome.REFUSED),
            timed_out_ports=ports_with(PortOutcome.TIMED_OUT),
            unreachable_ports=ports_with(PortOutcome.UNREACHABLE),
            was_cancelled=was_cancelled,
        )

    async def scan(
        self,
        host: str,
        ports: Iterable[int],
        cancel_check: Optional[Callable[[], bool]] = None
    ) -> List[int]:
        """Scan a host's ports and return which ones are open.

        The thin view over :meth:`sweep` for callers that only want the open
        ports and have no use for how the rest failed.

        Args:
            host: The target host (IP or hostname).
            ports: The ports to probe.
            cancel_check: An optional callable polled before each probe; if it
                returns ``True`` the remaining probes are skipped.

        Returns:
            The open ports, sorted ascending.
        """
        sweep = await self.sweep(host, ports, cancel_check=cancel_check)
        return list(sweep.open_ports)

    async def _probe_outcome(self, host: str, port: int) -> PortOutcome:
        """Intentar una conexión y decir en qué terminó, cerrándola limpiamente.

        Los tres desenlaces se distinguen porque significan cosas distintas
        sobre el objetivo, no sobre el puerto: ver :class:`PortOutcome`.
        """
        try:
            _, writer = await asyncio.wait_for(self._opener(host, port), self._timeout)
        except asyncio.TimeoutError:
            return PortOutcome.TIMED_OUT
        except ConnectionRefusedError:
            return PortOutcome.REFUSED
        except OSError:
            return PortOutcome.UNREACHABLE
        except Exception as err:  # noqa: BLE001 - unexpected opener error: treat as closed
            logger.debug("connect probe error for %s:%s: %s", host, port, err)
            return PortOutcome.UNREACHABLE
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:  # noqa: BLE001 - close is best-effort
                pass
        return PortOutcome.OPEN

    async def _is_open(self, host: str, port: int) -> bool:
        """Return whether a single port accepts a connection.

        Kept as the boolean view over :meth:`_probe_outcome` — any connection
        error or timeout means "not open".
        """
        return await self._probe_outcome(host, port) is PortOutcome.OPEN


def sweep_ports_sync(
    host: str,
    ports: Optional[Iterable[int]] = None,
    concurrency: int = 200,
    timeout: float = 2.0,
    opener: Optional[Callable] = None,
    cancel_check: Optional[Callable[[], bool]] = None,
) -> PortSweep:
    """Ejecutar un barrido completo síncronamente, en un bucle de eventos propio.

    La frontera de la "isla asyncio", en su forma detallada: devuelve el
    :class:`PortSweep` entero en vez de sólo los puertos abiertos.

    Args:
        host: El objetivo.
        ports: Los puertos a probar; por defecto :data:`DEFAULT_PORTS`.
        concurrency: Máximo de intentos de conexión simultáneos.
        timeout: Plazo por puerto, en segundos.
        opener: Abridor de conexión inyectable (ver :class:`AsyncConnectScanner`).
        cancel_check: Callable de cancelación opcional.

    Returns:
        El :class:`PortSweep` del barrido.
    """
    port_list = list(ports) if ports is not None else list(DEFAULT_PORTS)
    scanner = AsyncConnectScanner(concurrency=concurrency, timeout=timeout, opener=opener)
    return asyncio.run(scanner.sweep(host, port_list, cancel_check=cancel_check))


def scan_ports_sync(
    host: str,
    ports: Optional[Iterable[int]] = None,
    concurrency: int = 200,
    timeout: float = 2.0,
    opener: Optional[Callable] = None,
    cancel_check: Optional[Callable[[], bool]] = None,
    retries: int = 1,
    retry_delay: float = 2.0,
    sleeper: Callable[[float], None] = time.sleep,
) -> Optional[List[int]]:
    """Run a connect scan synchronously, on a fresh event loop of its own.

    This is the boundary of the "asyncio island": it wraps the async scanner in
    ``asyncio.run``, so it is safe to call from an ordinary synchronous worker.

    Devuelve ``None`` —no ``[]``— cuando el barrido parece bloqueado en vez de
    limpio (ver :attr:`PortSweep.is_blocked`). Esa distinción es la razón de
    ser de esta firma: el llamante ya tenía puesta la defensa de tratar
    ``None`` como fallo, pero nunca podía dispararla porque la única respuesta
    posible era una lista. Una lista vacía significa ahora, y sólo ahora,
    "el objetivo contestó y no tiene nada abierto".

    Antes de concluir que hay bloqueo se reintenta el barrido entero: un
    objetivo que deja de contestar a mitad de camino suele recuperarse en
    segundos, y un reintento espaciado cuesta mucho menos que un escaneo
    perdido.

    Args:
        host: The target host.
        ports: The ports to probe; defaults to :data:`DEFAULT_PORTS`.
        concurrency: The maximum number of connection attempts in flight at once.
        timeout: The per-port connect timeout, in seconds.
        opener: An injectable connection opener (see :class:`AsyncConnectScanner`).
        cancel_check: An optional cancellation callable.
        retries: Reintentos adicionales tras un barrido que parece bloqueado.
        retry_delay: Espera entre reintentos, en segundos.
        sleeper: Espera inyectable, para que un test no tenga que dormirla.

    Returns:
        Los puertos abiertos, ascendentes, o ``None`` si el barrido parece
        bloqueado incluso tras los reintentos.
    """
    sweep = sweep_ports_sync(host, ports, concurrency, timeout, opener, cancel_check)
    attempts_left = max(0, retries)
    while sweep.is_blocked and attempts_left > 0:
        logger.warning(
            "Barrido de %s sin una sola respuesta (%s puertos expirados): reintentando",
            host, len(sweep.timed_out_ports),
        )
        if retry_delay > 0:
            sleeper(retry_delay)
        sweep = sweep_ports_sync(host, ports, concurrency, timeout, opener, cancel_check)
        attempts_left -= 1

    if sweep.is_blocked:
        logger.error(
            "Descubrimiento de %s bloqueado: los %s puertos expiraron y ninguno "
            "rechazó la conexión; no es un objetivo limpio",
            host, len(sweep.timed_out_ports),
        )
        return None
    return list(sweep.open_ports)


def services_from_discovered_ports(
    open_ports: Iterable[int],
    protocol: str = "tcp"
) -> List[Service]:
    """Build engine :class:`Service` values from a list of discovered ports.

    A connect (or UDP probe) scan only learns *that* a port answered, not what
    is behind it, so these services carry no product or version —
    fingerprinting (Fase F/N) fills those in when it runs. Each service is
    labelled with its well-known name so that, for example, HTTP checks still
    select the right ports.

    Args:
        open_ports: The discovered open port numbers.
        protocol: The transport they were discovered over — ``"tcp"`` (the
            default, and the only value before Fase N/Ronda 1) or ``"udp"``
            for :func:`scan_udp_ports_sync`'s results.

    Returns:
        One :class:`Service` per port.
    """
    return [
        Service(
            port=port,
            protocol=protocol,
            name=WELL_KNOWN_PORTS.get(port, ""),
            product="",
            version="", 
            cpe=None
        )
        for port in open_ports
    ]


# =========================================================================
# SNMP GetRequest — el único payload de UDP_PROBES por ahora. Vive aquí y no
# en fingerprinting/snmp.py porque este módulo lo necesita para poblar la
# tabla de sondas: si el codificador viviera en snmp.py y transport.py lo
# importara de ahí, snmp.py necesitaría a su vez importar udp_send_recv de
# aquí para construir su sonda — un ciclo. transport.py no depende de nada
# de fingerprinting/, así que el payload vive en la capa base y snmp.py lo
# importa de vuelta (la dirección natural: fingerprinting ya depende de
# checks.py, que a su vez depende de engine.py, la misma base que transport).
# =========================================================================

def _ber_tlv(tag: int, value: bytes) -> bytes:
    """Envuelve ``value`` en un TLV BER de forma corta (longitud < 128).

    Ningún campo que :func:`build_snmp_get_request` construye se acerca a 128
    bytes, así que la forma larga de longitud no hace falta al escribir —
    solo al *leer* la respuesta (``fingerprinting/snmp.py::parse_snmp_sysdescr``),
    donde ``sysDescr`` la supera con frecuencia.
    """
    return bytes([tag, len(value)]) + value


# OID 1.3.6.1.2.1.1.1.0 (sysDescr.0) como TLV BER completo (tag 0x06,
# longitud 8, arcos). El primer byte del contenido es 40*1 + 3 = 0x2B (arcos
# "1.3" empaquetados); cada arco siguiente cabe en un byte porque ninguno
# supera 127.
_SNMP_SYSDESCR_OID_TLV = bytes.fromhex("06082b06010201010100")
_SNMP_NULL_TLV = bytes.fromhex("0500")


def build_snmp_get_request(community: str = "public") -> bytes:
    """Construye un GetRequest SNMP v2c completo para ``sysDescr.0``.

    Con la comunidad por defecto (``"public"``) el mensaje son exactamente 40
    bytes — fijado como caso de test dorado porque es el único artefacto de
    este módulo verificable a ojo contra RFC 3416 / una captura de Wireshark.

    No construye SNMPv1, v3, GETNEXT/GETBULK ni multi-varbind — ver el
    docstring de ``fingerprinting/snmp.py`` para la lista completa de lo que
    este módulo no soporta.

    Args:
        community: La cadena de comunidad a probar.

    Returns:
        El mensaje SNMP completo, listo para enviar por UDP al puerto 161.
    """
    varbind = _ber_tlv(0x30, _SNMP_SYSDESCR_OID_TLV + _SNMP_NULL_TLV)
    varbind_list = _ber_tlv(0x30, varbind)
    pdu_body = (
        _ber_tlv(0x02, b"\x01")   # request-id = 1 (constante: una sola petición por socket)
        + _ber_tlv(0x02, b"\x00")  # error-status = 0
        + _ber_tlv(0x02, b"\x00")  # error-index = 0
        + varbind_list
    )
    pdu = _ber_tlv(0xA0, pdu_body)  # [0] GetRequest-PDU
    message_body = (
        _ber_tlv(0x02, b"\x01")                       # version = 1 (v2c)
        + _ber_tlv(0x04, community.encode("utf-8"))   # community string
        + pdu
    )
    return _ber_tlv(0x30, message_body)


# Tabla payload→puerto para el descubrimiento UDP. Una fila por protocolo que
# de verdad tiene un dissector o un check consumiéndolo — DNS (53) y NTP (123)
# se evaluaron y se descartaron a propósito (roadmap §6.3): nada los consume
# todavía, así que solo producirían un open_port informativo a cambio de
# construir y validar dos consultas más. Añadir una fila es una línea.
UDP_PROBES: Dict[int, bytes] = {161: build_snmp_get_request()}


def udp_send_recv(host: str, port: int, payload: bytes, timeout: float) -> Optional[bytes]:
    """Envía ``payload`` por UDP a ``host:port`` y devuelve la respuesta cruda.

    Usa un socket ``connect()``-ado en vez de ``sendto``/``recvfrom`` sueltos:
    en un socket UDP conectado, un ICMP port-unreachable del destino se
    superficia como ``ConnectionRefusedError`` en la siguiente llamada, así
    que un puerto cerrado falla en microsegundos en vez de agotar el timeout
    completo esperando un paquete que nunca llega.

    Args:
        host: El host destino.
        port: El puerto UDP destino.
        payload: Los bytes a enviar.
        timeout: Timeout de la operación, en segundos.

    Returns:
        Los bytes de respuesta, o ``None`` ante cualquier fallo de red
        (timeout, puerto cerrado, host inalcanzable).
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.connect((host, port))
            sock.send(payload)
            return sock.recv(4096)
    except OSError as err:
        logger.debug("UDP probe failed for %s:%s: %s", host, port, err)
        return None


def scan_udp_ports_sync(
    host: str,
    ports: Optional[Iterable[int]] = None,
    timeout: float = 2.0,
    retries: int = 1,
    sender: Optional[Callable] = None,
) -> List[int]:
    """Descubre puertos UDP abiertos mediante sondas payload/respuesta curadas.

    A diferencia del connect scan de TCP, el silencio en UDP no significa
    "cerrado" — significa "no lo sabemos", así que aquí solo se reportan
    puertos que de verdad contestaron algo. Sin concurrencia ni asyncio a
    propósito: con una tabla de un puerto, un escáner paralelo sería
    andamiaje; se añade si la tabla crece lo bastante como para que
    importe.

    Args:
        host: El host destino.
        ports: Los puertos a probar; por defecto, todos los de
            :data:`UDP_PROBES`. Un puerto sin fila en la tabla se ignora
            silenciosamente — no hay payload que enviarle.
        timeout: Timeout por intento, en segundos.
        retries: Reintentos adicionales tras un primer silencio. Un
            datagrama perdido (no un puerto cerrado) haría que el mismo
            puerto oscilara entre abierto y cerrado entre escaneos, y el
            ciclo de vida de la Fase 5 lo leería como ``fixed``/``regressed``
            falsos — de ahí que el valor por defecto no sea 0.
        sender: Callable inyectable ``(host, port, payload, timeout) ->
            Optional[bytes]``, espejo del ``opener`` del escáner TCP. Por
            defecto, :func:`udp_send_recv`.

    Returns:
        Los puertos que contestaron, sorted ascendente. Nunca ``None``: un
        fallo de sonda para un puerto simplemente no lo añade a la lista.
    """
    send = sender or udp_send_recv
    port_list = list(ports) if ports is not None else list(UDP_PROBES)
    open_ports: List[int] = []
    for port in port_list:
        payload = UDP_PROBES.get(port)
        if payload is None:
            continue
        reply = None
        for _ in range(retries + 1):
            reply = send(host, port, payload, timeout)
            if reply is not None:
                break
        if reply is not None:
            open_ports.append(port)
    return sorted(open_ports)
