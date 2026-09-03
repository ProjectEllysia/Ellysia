"""Where a Lybra scan gets its services from — los dos modos del roadmap §0.9.

Extracted out of ``lybra/engine.py`` because the manager kept re-asking the same
question — "are we analysing an external payload, or doing our own discovery?" —
at every step of the pipeline: resolving the target, resolving the services,
deciding whether fingerprinting/active checks may touch the network. Each
:class:`ServiceSource` implementation answers all of that for its mode in one
place instead of a condition re-checked at each of those call sites.

``run_scan`` builds a :class:`ServiceSource` (via :meth:`ServiceSource.build_for_args`)
purely to resolve and validate the scan's target before the scan record exists;
the TaskQueue itself keeps serializing the same primitive arguments it always did
(``services`` / ``discover_ports``), and the worker rebuilds the same object with
the same factory once it is running as ``_run_lybra``.

Hubo un tercer modo, retirado en L52: analizar los servicios que un escaneo
Nmap previo ya había descubierto. Existía porque el motor no tenía transporte
propio; desde que la Fase T se lo dio, era la puerta de atrás de una capacidad
que Lybra ya tiene por sí mismo, y ataba el motor a otro escáner.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from abc import ABC, abstractmethod
from typing import Callable, List, Optional

import src.modules.system.config_reading as CR
from ...repositories import ScanRepository
from ...exceptions import TargetNotAuthorizedError
from ...lybra import PortSweep, Service, services_from_discovered_ports
from ..authorized_target import AuthorizedTargetManager
from ..scan import ScanManager

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class DiscoveryProbes:
    """The three network-probing capabilities ``SelfDiscovery`` needs from
    the calling manager, passed as plain callables instead of the whole
    manager object (E1).

    Before, ``resolve_services`` took the full ``LybraEngineManager`` just to
    reach three of its methods — which forced this module to import that
    manager's *class* purely for the type hint, creating a real import cycle
    with ``lybra/engine.py`` (worked around before with two deferred imports
    there). Handing over three bound methods instead removes the need for
    this module to know the manager's type at all.
    """
    is_host_reachable: Callable[..., bool]
    discover_ports: Callable[[str, Optional[list]], Optional["PortSweep"]]
    discover_udp_ports: Callable[[str], list]


@dataclass(frozen=True)
class ResolvedServices:
    """What a source hands back to the engine: services plus the host/target
    identity they resolved to.

    Attributes:
        is_partial: Si el descubrimiento no llegó a mirar todo el objetivo. Los
            servicios que trae son ciertos; de lo que quedó sin probar no se
            sabe nada, así que el motor marca el escaneo como incompleto y no
            deja que el ciclo de vida cierre hallazgos por ausencia.
    """
    services: List[Service]
    host_id: Optional[int]
    target: Optional[str]
    is_partial: bool = False


class ServiceSource(ABC):
    """One of the two ways a Lybra scan obtains the services it analyses.

    A thin base plus one policy flag (Python's idiomatic stand-in for what
    would be an abstract method in a language that needs them for a fixed,
    reused decision) and one real polymorphic method, :meth:`resolve_services`.
    """

    label: str = "desconocido"


    probes_target_network: bool = True
    """
    Whether Fase F (fingerprinting) and Fase R (active checks) may run
    against the target for this mode. False only for the external-payload
    mode: that data is already a verified fact (Fase 0.9), so re-inferring
    it over the network would be redundant at best, and this mode exists
    precisely for hosts it might not even be able to reach.
    """

    @classmethod
    def build_for_args(
        cls,
        services: Optional[List[Service]],
        ports_to_discover: Optional[list],
    ) -> "ServiceSource":
        """Build the source matching whichever of the two run_scan args was given."""
        if services is not None:
            return ExternalPayload(services)
        return SelfDiscovery(ports_to_discover)

    @abstractmethod
    def valid_scan_target(self, user_id: int, target: Optional[str]) -> str:
        """Resolve and validate this mode's target, before the scan record exists."""
        ...

    @abstractmethod
    def resolve_services(
        self,
        scan_repo: ScanRepository,
        probes: DiscoveryProbes,
        target: Optional[str]
    ) -> Optional[ResolvedServices]:
        """Obtain this mode's services inside the caller's transaction.

        ``probes`` bundles the network-probing capabilities only the
        self-discovery mode uses (E1) — the payload mode ignores it.

        Returns ``None`` for an unrecoverable failure (host unreachable, probe
        blew up) — the caller marks the scan FAILED and stops. This is
        distinct from a resolution that succeeds with zero services, which is
        genuine evidence, not a failure (see ``SelfDiscovery.resolve``).

        Y distinto también de una resolución **parcial**
        (``ResolvedServices.is_partial``), que sí trae servicios ciertos pero
        no vio todo el objetivo: ésa no es un fallo, es un resultado con una
        advertencia pegada.
        """
        ...

    @staticmethod
    def _resolve_host(scan_repo: ScanRepository, target: Optional[str]) -> Optional[int]:
        """Shared host-identity lookup: reuse a Host already known by IP or hostname
        instead of creating a duplicate row for the same device."""
        if not target:
            return None
        host = scan_repo.get_host_by_ip(target) or scan_repo.get_or_create_host(
            hostname=target, ip_address=target,
        )
        return host.id if host else None


class ExternalPayload(ServiceSource):
    """Analyse a services list the caller already resolved (Fase 0.9).

    No network discovery, fingerprinting or active checks run in this mode —
    it exists precisely for services data that came from *not* touching the
    target's network (a Hygeia inventory adapter is the motivating case).
    """

    label = "payload externo"
    probes_target_network = False

    def __init__(self, services: List[Service]) -> None:
        self.services = services

    def valid_scan_target(self, user_id: int, target: Optional[str]) -> str:
        if not target:
            raise ValueError("run_scan requires a target when services is set")
        return target

    def resolve_services(
        self,
        scan_repo: ScanRepository,
        probes: DiscoveryProbes,
        target: Optional[str]
    ) -> ResolvedServices:
        return ResolvedServices(
            services=list(self.services),
            host_id=self._resolve_host(scan_repo, target),
            target=target,
        )


class SelfDiscovery(ServiceSource):
    """Discover the target's open ports with Lybra's own connect scan (Fase T)."""

    label = "descubrimiento propio"

    def __init__(self, ports_to_discover: Optional[list]) -> None:
        self.ports_to_discover = ports_to_discover

    def valid_scan_target(self, user_id: int, target: Optional[str]) -> str:
        if target is None:
            raise ValueError("run_scan requires services or target")
        # Self-discovery touches the target directly, unlike analysing a
        # services payload the caller already resolved (roadmap §6).
        #
        # Rechazo de IP privada aquí (no solo en el endpoint HTTP, ver
        # validate_targets en start_lybra_scan): el flujo programado
        # (scheduling._run_lybra_scan) llama a run_scan() directo, sin pasar
        # por el endpoint. El registro de objetivos autorizados es un gate
        # legal, no de red: no sustituye este rechazo (ver
        # AuthorizedTargetManager).
        ScanManager.reject_private_ip(target)
        if not AuthorizedTargetManager.is_authorized(user_id, target):
            raise TargetNotAuthorizedError(target)
        return target

    def resolve_services(
        self,
        scan_repo: ScanRepository,
        probes: DiscoveryProbes,
        target: Optional[str]
    ) -> Optional[ResolvedServices]:
        discovered_ports: list = []
        udp_ports: list = []
        is_partial = False
        if target:
            if CR.host_reachability_check().enabled and not probes.is_host_reachable(
                target,
                port=CR.host_reachability_check().port,
                timeout=CR.host_reachability_check().timeout,
            ):
                logger.warning(f"Host '{target}' inalcanzable.")
                return None

            sweep = probes.discover_ports(target, self.ports_to_discover)
            if sweep is None:
                logger.error("Descubrimiento de puertos fallido para %s", target)
                return None
            discovered_ports = list(sweep.open_ports)
            is_partial = sweep.was_truncated
            # UDP (Fase N/Ronda 1, roadmap §6.3): sonda curada aparte, nunca a
            # partir de la lista TCP del usuario — self.ports_to_discover es una
            # lista de puertos TCP. Best-effort por diseño de
            # _discover_udp_ports: nunca aborta el descubrimiento TCP.
            udp_ports = probes.discover_udp_ports(target)

        services = services_from_discovered_ports(discovered_ports)
        services += services_from_discovered_ports(udp_ports, protocol="udp")

        return ResolvedServices(
            services=services,
            host_id=self._resolve_host(scan_repo, target),
            target=target,
            is_partial=is_partial,
        )
