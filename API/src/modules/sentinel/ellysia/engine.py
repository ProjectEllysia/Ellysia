"""Ellysia's own vulnerability engine.

This is the L2 "detection runtime" seam described in the vuln-engine roadmap.
In Fase 0 it does no detection yet: given the services discovered for a host it
emits one informational "open port" :class:`Finding` per service, so the whole
persistence/correlation plumbing works end to end. Version matching (Fase 1) and
active checks (Fase R) plug into :meth:`EllysiaEngine.analyze` later without the
manager or the persistence layer changing.

The engine is deliberately ORM-free: it takes plain :class:`Service` values and
returns plain dicts ready to build ``Finding`` rows. ``services_from_open_ports``
is the only place that touches the (duck-typed) ``OpenPort`` rows, so the mapping
from Nmap's data model into the engine's lives here, in the ellysia package,
rather than leaking into the manager.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Optional


# Quality of Detection for a bare "the port is open" observation: low, because it
# asserts nothing about vulnerability. Detection checks raise this in later phases.
QOD_OPEN_PORT = 30


@dataclass(frozen=True)
class Service:
    """A single discovered service, the engine's unit of input.

    Attributes:
        port: TCP/UDP port number, or None if it could not be parsed.
        protocol: Transport protocol ("tcp" / "udp").
        name: Service name as identified (e.g. "http", "ssh"). May be empty.
        product: Product name (e.g. "Apache httpd"). May be empty.
        version: Product version (e.g. "2.4.49"). May be empty.
        cpe: CPE string if known, else None.
    """
    port: Optional[int]
    protocol: str
    name: str = ""
    product: str = ""
    version: str = ""
    cpe: Optional[str] = None

    @property
    def label(self) -> str:
        """Best human-readable name for the service ("Apache httpd 2.4.49")."""
        product_version = " ".join(p for p in (self.product, self.version) if p)
        return product_version or self.name or "servicio desconocido"


class EllysiaEngine:
    """Turns discovered services into normalized findings.

    Fase 0: one informational finding per service. The public surface
    (:meth:`analyze`) stays stable as real detection is added underneath.
    """

    FEED_VERSION = "ellysia-0"

    def analyze(self, services: Iterable[Service]) -> List[dict]:
        """Return Finding-data dicts for the given services.

        Args:
            services: The services discovered for the host.

        Returns:
            A list of dicts with ``Finding`` column values (no scan_id; the
            repository sets it when persisting).
        """
        return [self._informational_finding(service) for service in services]

    def _informational_finding(self, service: Service) -> dict:
        """Build the "open port" informational finding for one service."""
        where = f"{service.port}/{service.protocol}" if service.port else service.protocol
        return {
            "title":        f"Puerto {where} abierto — {service.label}",
            "category":     "open_port",
            "port":         service.port,
            "service":      service.name or None,
            "cpe":          service.cpe or None,
            "source":       "ellysia",
            "check_id":     "ellysia:open-port@1",
            "feed_version": self.FEED_VERSION,
            "qod":          QOD_OPEN_PORT,
            "confirmed":    False,
            "state":        "open",
        }


def services_from_open_ports(open_ports: Iterable) -> List[Service]:
    """Map Nmap ``OpenPort`` rows into engine :class:`Service` values.

    Duck-typed on purpose (reads ``op.port.protocol``, ``op.product`` ...) so the
    engine package does not depend on the ORM model. ``op.port.protocol`` is the
    Nmap "80/tcp" form; anything malformed degrades to ``port=None`` rather than
    raising, so one odd row never sinks a whole scan.
    """
    services: List[Service] = []
    for op in open_ports:
        port, protocol = _split_protocol(getattr(getattr(op, "port", None), "protocol", ""))
        services.append(Service(
            port=port,
            protocol=protocol,
            name=(op.given_use or "").strip(),
            product=(op.product or "").strip(),
            version=(op.version or "").strip(),
            cpe=(op.cpe or None),
        ))
    return services


def _split_protocol(protocol: str) -> tuple[Optional[int], str]:
    """Parse Nmap's "80/tcp" into (80, "tcp"); tolerate malformed input."""
    if not protocol:
        return None, "tcp"
    port_str, _, proto = protocol.partition("/")
    try:
        return int(port_str), (proto or "tcp")
    except ValueError:
        return None, (proto or "tcp")
