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
"""

from __future__ import annotations

import asyncio
import logging
import socket
from typing import Callable, Dict, Iterable, List, Optional

from .engine import Service

logger = logging.getLogger(__name__)


# Maps a well-known TCP port to its conventional service name. Used to label a
# freshly discovered port before we have a banner for it; fingerprinting (Fase F)
# refines the label when it is enabled.
WELL_KNOWN_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
    161: "snmp", 389: "ldap", 443: "https", 445: "microsoft-ds", 465: "smtps",
    587: "submission", 631: "ipp", 993: "imaps", 995: "pop3s", 1433: "ms-sql-s",
    1521: "oracle", 2049: "nfs", 2375: "docker", 3306: "mysql", 3389: "ms-wbt-server",
    5432: "postgresql", 5900: "vnc", 5985: "wsman", 6379: "redis", 8080: "http-proxy",
    8443: "https-alt", 8888: "http-alt", 9200: "elasticsearch", 27017: "mongodb",
}

# The ports swept when the caller does not specify a list: the common,
# high-signal services, plus a handful of extras. This is intentionally not a
# full 1-65535 range — sweeping everything belongs to the raw fast-path, which
# this module does not implement.
DEFAULT_PORTS: tuple = tuple(sorted(WELL_KNOWN_PORTS)) + (
    20, 69, 123, 137, 138, 512, 513, 514, 873, 1080, 1723, 2181, 3000, 3268,
    4444, 5000, 5060, 5601, 6667, 7001, 8000, 8008, 8081, 8088, 8181, 9000,
    9090, 9300, 11211,
)


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

    async def scan(
        self,
        host: str,
        ports: Iterable[int],
        cancel_check: Optional[Callable[[], bool]] = None
    ) -> List[int]:
        """Scan a host's ports and return which ones are open.

        Args:
            host: The target host (IP or hostname).
            ports: The ports to probe.
            cancel_check: An optional callable polled before each probe; if it
                returns ``True`` the remaining probes are skipped.

        Returns:
            The open ports, sorted ascending.
        """
        semaphore = asyncio.Semaphore(self._concurrency)
        open_ports: List[int] = []

        async def probe(port: int) -> None:
            if cancel_check and cancel_check():
                return
            async with semaphore:
                if await self._is_open(host, port):
                    open_ports.append(port)

        await asyncio.gather(*(probe(port) for port in ports))
        return sorted(open_ports)

    async def _is_open(self, host: str, port: int) -> bool:
        """Return whether a single port accepts a connection, closing it cleanly.

        Any connection error or timeout is taken to mean "closed"; the socket is
        always closed afterwards on a best-effort basis.
        """
        try:
            _, writer = await asyncio.wait_for(self._opener(host, port), self._timeout)
        except (OSError, asyncio.TimeoutError):
            return False
        except Exception as err:  # noqa: BLE001 - unexpected opener error: treat as closed
            logger.debug("connect probe error for %s:%s: %s", host, port, err)
            return False
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:  # noqa: BLE001 - close is best-effort
                pass
        return True


def scan_ports_sync(
    host: str,
    ports: Optional[Iterable[int]] = None,
    concurrency: int = 200,
    timeout: float = 2.0,
    opener: Optional[Callable] = None,
    cancel_check: Optional[Callable[[], bool]] = None
) -> List[int]:
    """Run a connect scan synchronously, on a fresh event loop of its own.

    This is the boundary of the "asyncio island": it wraps the async scanner in
    ``asyncio.run``, so it is safe to call from an ordinary synchronous worker.

    Args:
        host: The target host.
        ports: The ports to probe; defaults to :data:`DEFAULT_PORTS`.
        concurrency: The maximum number of connection attempts in flight at once.
        timeout: The per-port connect timeout, in seconds.
        opener: An injectable connection opener (see :class:`AsyncConnectScanner`).
        cancel_check: An optional cancellation callable.

    Returns:
        The open ports, sorted ascending.
    """
    port_list = list(ports) if ports is not None else list(DEFAULT_PORTS)
    scanner = AsyncConnectScanner(concurrency=concurrency, timeout=timeout, opener=opener)
    return asyncio.run(scanner.scan(host, port_list, cancel_check=cancel_check))


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
