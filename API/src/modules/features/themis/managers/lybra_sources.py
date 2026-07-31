"""Where a Lybra scan gets its services from — the three modes of roadmap §0.9.

Extracted out of ``lybra_engine.py`` because the manager kept re-asking the same
question — "are we over a prior Nmap scan, an external payload, or doing our own
discovery?" — at every step of the pipeline: resolving the target, resolving the
services, deciding whether fingerprinting/active checks may touch the network,
deciding whether deep corroborators need explicit authorization, deciding whether
a fresh Nmap corroborator would be redundant. Each :class:`ServiceSource`
implementation answers all of that for its mode in one place instead of a
condition re-checked at each of those call sites.

``run_scan`` builds a :class:`ServiceSource` (via :meth:`ServiceSource.for_args`)
purely to resolve and validate the scan's target before the scan record exists;
the TaskQueue itself keeps serializing the same primitive arguments it always did
(``source_scan_id`` / ``services`` / ``discover_ports``), and the worker rebuilds
the same object with the same factory once it is running as ``_run_lybra``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import List, Optional

import src.modules.system.config_reading as CR
from src.modules.infrastructure import UnitOfWork
from ..repositories import ScanRepository
from ..exceptions import ScanNotFoundError, TargetNotAuthorizedError
from ..lybra import Service, services_from_open_ports, services_from_discovered_ports
from .authorized_target import AuthorizedTargetManager
from .scan import ScanManager

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ResolvedServices:
    """What a source hands back to the engine: services plus the host/target
    identity they resolved to (a source may correct ``target``, e.g. the Nmap
    source falling back to the source scan's own target)."""
    services: List[Service]
    host_id: Optional[int]
    target: Optional[str]


class ServiceSource:
    """One of the three ways a Lybra scan obtains the services it analyses.

    A thin base plus three policy flags (Python's idiomatic stand-in for what
    would be abstract methods in a language that needs them for a fixed,
    reused decision) and one real polymorphic method, :meth:`resolve`.
    """

    label: str = "desconocido"

    # Whether Fase F (fingerprinting) and Fase R (active checks) may run
    # against the target for this mode. False only for the external-payload
    # mode: that data is already a verified fact (Fase 0.9), so re-inferring
    # it over the network would be redundant at best, and this mode exists
    # precisely for hosts it might not even be able to reach.
    probes_target_network: bool = True

    # Whether the deep corroborators (Fase 6) require an explicit
    # authorized-targets register entry before launching. False for the two
    # modes that already validated the target some other way (Nmap: the prior
    # scan; self-discovery: run_scan's own gate at launch) — True only for the
    # payload mode, whose target nothing else ever validates.
    deep_requires_authorization: bool = False

    # Whether the deep corroborators should include a fresh Nmap run. False
    # only when the scan is already built over a prior Nmap scan's ports — a
    # second one would be redundant.
    launches_nmap_corroborator: bool = True

    @classmethod
    def for_args(
        cls,
        source_scan_id: Optional[int],
        services: Optional[List[Service]],
        discover_ports: Optional[list],
    ) -> "ServiceSource":
        """Build the source matching whichever of the three run_scan args was given."""
        if source_scan_id is not None:
            return NmapSourceScan(source_scan_id)
        if services is not None:
            return ExternalPayload(services)
        return SelfDiscovery(discover_ports)

    def scan_target(self, user_id: int, target: Optional[str]) -> str:
        """Resolve and validate this mode's target, before the scan record exists."""
        raise NotImplementedError

    def resolve(self, scan_repo: ScanRepository, manager, target: Optional[str]) -> Optional[ResolvedServices]:
        """Obtain this mode's services inside the caller's transaction.

        ``manager`` is the calling ``LybraEngineManager``— only the
        self-discovery mode uses it, to reach ``is_host_reachable`` and
        ``_discover_ports``, which stay manager methods since they own the
        network/DB access that already lives there.

        Returns ``None`` for an unrecoverable failure (host unreachable, probe
        blew up) — the caller marks the scan FAILED and stops. This is
        distinct from a resolution that succeeds with zero services, which is
        genuine evidence, not a failure (see ``SelfDiscovery.resolve``).
        """
        raise NotImplementedError

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


class NmapSourceScan(ServiceSource):
    """Analyse the services a prior Nmap scan already discovered."""

    deep_requires_authorization = False
    launches_nmap_corroborator = False   # redundant: Nmap-sourced ports already exist

    def __init__(self, source_scan_id: int) -> None:
        self.source_scan_id = source_scan_id
        self.label = f"fuente Nmap {source_scan_id}"

    def scan_target(self, user_id: int, target: Optional[str]) -> str:
        with UnitOfWork() as uow:
            source = ScanRepository(uow).get_by_id(self.source_scan_id)
            if not source:
                raise ScanNotFoundError(self.source_scan_id)
            return source.target

    def resolve(self, scan_repo: ScanRepository, manager, target: Optional[str]) -> ResolvedServices:
        open_ports = scan_repo.get_open_ports_for_scan(self.source_scan_id)
        source = scan_repo.get_by_id(self.source_scan_id)
        return ResolvedServices(
            services=services_from_open_ports(open_ports),
            host_id=source.host_id if source else None,
            target=source.target if source else target,
        )


class ExternalPayload(ServiceSource):
    """Analyse a services list the caller already resolved (Fase 0.9).

    No network discovery, fingerprinting or active checks run in this mode —
    it exists precisely for services data that came from *not* touching the
    target's network (a Hygeia inventory adapter is the motivating case).
    """

    label = "payload externo"
    probes_target_network = False
    deep_requires_authorization = True   # nothing else ever validated this target

    def __init__(self, services: List[Service]) -> None:
        self.services = services

    def scan_target(self, user_id: int, target: Optional[str]) -> str:
        if not target:
            raise ValueError("run_scan requires a target when services is set")
        return target

    def resolve(self, scan_repo: ScanRepository, manager, target: Optional[str]) -> ResolvedServices:
        return ResolvedServices(
            services=list(self.services),
            host_id=self._resolve_host(scan_repo, target),
            target=target,
        )


class SelfDiscovery(ServiceSource):
    """Discover the target's open ports with Lybra's own connect scan (Fase T)."""

    label = "descubrimiento propio"
    deep_requires_authorization = False   # run_scan already required this at launch

    def __init__(self, discover_ports: Optional[list]) -> None:
        self.discover_ports = discover_ports

    def scan_target(self, user_id: int, target: Optional[str]) -> str:
        if target is None:
            raise ValueError("run_scan requires source_scan_id, services, or target")
        # Self-discovery touches the target directly, unlike analysing a prior
        # Nmap scan's already-collected services (roadmap §6).
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

    def resolve(self, scan_repo: ScanRepository, manager, target: Optional[str]) -> Optional[ResolvedServices]:
        discovered_ports: list = []
        udp_ports: list = []
        if target:
            if CR.host_reachability_check().enabled and not manager.is_host_reachable(
                target,
                port=CR.host_reachability_check().port,
                timeout=CR.host_reachability_check().timeout,
            ):
                logger.warning(f"Host '{target}' inalcanzable.")
                return None

            discovered = manager._discover_ports(target, self.discover_ports)  # pylint: disable=protected-access
            if discovered is None:
                logger.error("Descubrimiento de puertos fallido para %s", target)
                return None
            discovered_ports = discovered
            # UDP (Fase N/Ronda 1, roadmap §6.3): sonda curada aparte, nunca a
            # partir de la lista TCP del usuario — self.discover_ports es una
            # lista de puertos TCP. Best-effort por diseño de
            # _discover_udp_ports: nunca aborta el descubrimiento TCP.
            udp_ports = manager._discover_udp_ports(target)  # pylint: disable=protected-access

        services = services_from_discovered_ports(discovered_ports)
        services += services_from_discovered_ports(udp_ports, protocol="udp")

        return ResolvedServices(
            services=services,
            host_id=self._resolve_host(scan_repo, target),
            target=target,
        )
