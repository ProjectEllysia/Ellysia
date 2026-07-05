"""Ellysia's own port discovery (Fase T, the L0 layer).

The **always-available base** of the roadmap's transport plan: an unprivileged
``connect`` scan built on asyncio. It lets an Ellysia scan discover open ports
by itself, dropping the dependency on a prior Nmap scan's ``OpenPort`` rows.

Deliberately NOT built here (would need ``CAP_NET_RAW`` / raw sockets, cannot be
tested in this environment, and the roadmap itself marks them as later
optimizations gated on measured throughput need): the stateless SYN fast-path,
UDP probes, AIMD loss-based rate control, and the native probe repo. The
connect scan below is what the roadmap calls the base that is *always* present;
raw is only ever a faster path over the same result, and Nmap stays the oracle.

The event loop is created and destroyed inside :func:`scan_ports_sync` — the
"asyncio island" (roadmap §2.2): it lives entirely within the sync RQ worker
call, never touching the Flask process or the ORM session. ``open_connection``
is injectable so the scanner is tested without real sockets.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Callable, Iterable, List, Optional

from .engine import Service

logger = logging.getLogger(__name__)


# Well-known TCP ports -> service name, used to label a discovered port when we
# have no banner yet (fingerprinting, Fase F, refines this when enabled).
WELL_KNOWN_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
    161: "snmp", 389: "ldap", 443: "https", 445: "microsoft-ds", 465: "smtps",
    587: "submission", 631: "ipp", 993: "imaps", 995: "pop3s", 1433: "ms-sql-s",
    1521: "oracle", 2049: "nfs", 2375: "docker", 3306: "mysql", 3389: "ms-wbt-server",
    5432: "postgresql", 5900: "vnc", 5985: "wsman", 6379: "redis", 8080: "http-proxy",
    8443: "https-alt", 8888: "http-alt", 9200: "elasticsearch", 27017: "mongodb",
}

# Curated default sweep when the caller gives no explicit port list. The common,
# high-signal services — not a full 1-65535 range (that belongs to the raw
# fast-path we are not building here).
DEFAULT_PORTS: tuple = tuple(sorted(WELL_KNOWN_PORTS)) + (
    20, 69, 123, 137, 138, 512, 513, 514, 873, 1080, 1723, 2181, 3000, 3268,
    4444, 5000, 5060, 5601, 6667, 7001, 8000, 8008, 8081, 8088, 8181, 9000,
    9090, 9300, 11211,
)


class AsyncConnectScanner:
    """Concurrent TCP connect scanner. Unprivileged; bounded concurrency.

    Args:
        concurrency: Max simultaneous connection attempts.
        timeout: Per-port connect timeout (seconds).
        opener: ``async (host, port) -> (reader, writer)`` — defaults to
            ``asyncio.open_connection``; injected in tests.
    """

    def __init__(self, concurrency: int = 200, timeout: float = 2.0,
                 opener: Optional[Callable] = None) -> None:
        self._concurrency = concurrency
        self._timeout = timeout
        self._opener = opener or asyncio.open_connection

    async def scan(self, host: str, ports: Iterable[int],
                   cancel_check: Optional[Callable[[], bool]] = None) -> List[int]:
        """Return the sorted list of open ports among ``ports``."""
        # ponytail: one task per port bounded by a semaphore is fine for the
        # curated default set (~90 ports). For full 1-65535 ranges, chunk the
        # ports so we don't materialize 65k coroutines — belongs with the raw
        # fast-path, which isn't built here.
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
        try:
            reader, writer = await asyncio.wait_for(self._opener(host, port), self._timeout)
        except (OSError, asyncio.TimeoutError):
            return False
        except Exception as err:  # noqa: BLE001 - unexpected opener error: treat as closed
            logger.debug("connect probe error for %s:%s: %s", host, port, err)
            return False
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:  # noqa: BLE001 - close is best-effort
            pass
        return True


def scan_ports_sync(host: str, ports: Optional[Iterable[int]] = None,
                    concurrency: int = 200, timeout: float = 2.0,
                    opener: Optional[Callable] = None,
                    cancel_check: Optional[Callable[[], bool]] = None) -> List[int]:
    """Synchronous entry point: run a connect scan on its own event loop.

    This is the asyncio-island boundary — safe to call from the sync RQ worker.
    ``ports`` defaults to :data:`DEFAULT_PORTS`.
    """
    port_list = list(ports) if ports is not None else list(DEFAULT_PORTS)
    scanner = AsyncConnectScanner(concurrency=concurrency, timeout=timeout, opener=opener)
    return asyncio.run(scanner.scan(host, port_list, cancel_check=cancel_check))


def services_from_discovered_ports(open_ports: Iterable[int]) -> List[Service]:
    """Build engine :class:`Service` values from discovered port numbers.

    No product/version yet (connect scan sees only that the port answered);
    fingerprinting (Fase F) fills those when enabled. The service name is the
    well-known guess, so HTTP checks still select the right ports.
    """
    return [
        Service(port=port, protocol="tcp", name=WELL_KNOWN_PORTS.get(port, ""),
                product="", version="", cpe=None)
        for port in open_ports
    ]


def port_concordance(own_ports: Iterable[int], nmap_ports: Iterable[int]) -> float:
    """Jaccard agreement between our discovered ports and Nmap's (the oracle).

    The number the roadmap's Fase T Definition of Done thresholds at 0.95 before
    the connect scan can become the default over Nmap for discovery. Both empty
    counts as full agreement (nothing to disagree on).
    """
    own, nmap = set(own_ports), set(nmap_ports)
    union = own | nmap
    if not union:
        return 1.0
    return len(own & nmap) / len(union)
