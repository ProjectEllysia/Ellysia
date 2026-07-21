"""Lybra's own port discovery — the transport layer.

This is the always-available foundation of the roadmap's transport plan: an
unprivileged TCP ``connect`` scan built on asyncio. It lets an Lybra scan find
open ports for itself, so a scan no longer has to be handed the ports from a
prior Nmap run.

Several faster or lower-level techniques are deliberately *not* built here — a
stateless SYN fast-path, UDP probes, AIMD (loss-based) rate control and a native
probe library. They would all need raw-socket privileges (``CAP_NET_RAW``),
cannot be exercised in this test environment, and the roadmap itself treats them
as later optimizations to reach for only once measured throughput demands them.
The connect scan below is the base that is always present; a raw path would only
ever be a faster route to the same result, with Nmap still available as the
oracle to check against.

The event loop is created and torn down entirely inside :func:`scan_ports_sync`
— the "asyncio island". It lives within a single synchronous worker call and
never touches the Flask process or an ORM session. The connection opener is
injectable, so the scanner can be tested without opening real sockets.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Callable, Iterable, List, Optional

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

        await asyncio.gather(*(probe(p) for p in ports))
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


def services_from_discovered_ports(open_ports: Iterable[int]) -> List[Service]:
    """Build engine :class:`Service` values from a list of discovered ports.

    A connect scan only learns *that* a port answered, not what is behind it, so
    these services carry no product or version — fingerprinting (Fase F) fills
    those in when it runs. Each service is labelled with its well-known name so
    that, for example, HTTP checks still select the right ports.

    Args:
        open_ports: The discovered open port numbers.

    Returns:
        One :class:`Service` per port.
    """
    return [
        Service(port=port, protocol="tcp", name=WELL_KNOWN_PORTS.get(port, ""),
                product="", version="", cpe=None)
        for port in open_ports
    ]


def port_concordance(own_ports: Iterable[int], nmap_ports: Iterable[int]) -> float:
    """Measure how well our discovered ports agree with Nmap's.

    Computes the Jaccard index (size of the intersection over size of the union)
    between the two port sets. This is the number the roadmap's Definition of
    Done thresholds at 0.95 before the connect scan may become the default over
    Nmap for discovery. Two empty sets count as full agreement — there is nothing
    to disagree about.

    Args:
        own_ports: The ports Lybra's connect scan found.
        nmap_ports: The ports Nmap found (the oracle).

    Returns:
        A value in ``[0.0, 1.0]``, where 1.0 is perfect agreement.
    """
    own, nmap = set(own_ports), set(nmap_ports)
    union = own | nmap
    if not union:
        return 1.0
    return len(own & nmap) / len(union)
