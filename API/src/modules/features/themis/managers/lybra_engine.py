"""LybraEngineManager — extraido de themis/managers.py (Fase 3 del refactor de estructura)."""

import ipaddress
import logging
from dataclasses import replace
from typing import List, Optional
import src.modules.system.config_reading as CR
from src.modules.system.taskqueue import ITaskQueue, job_context
from src.modules.infrastructure import UnitOfWork
from src.modules.infrastructure.session import build_repository
from src.modules.shared import utcnow_naive, isoformat_utc
from ..repositories import (
    ScanRepository,
    KbRepository,
    AuthorizedTargetRepository,
)
from ..model import (
    Finding,
    LybraScan,
    Scan,
    ScanStatus,
    ScanType,
    AuthorizedTarget,
)
from ..lybra import (
    LybraEngine,
    Service,
    services_from_open_ports,
    services_from_discovered_ports,
    compute_dedup_key,
    merge_findings,
    apply_lifecycle,
    classify_exposure,
    score_finding,
    QOD_OPEN_PORT,
)
from ..services import _Task, LybraPrintingStrategy
from ..exceptions import (
    ScanNotFoundError,
    FindingNotFoundError,
    TargetNotAuthorizedError,
    AuthorizedTargetNotFoundError,
    DuplicateAuthorizedTargetError,
    IPValidationError,
)

from .scan import ScanManager
from .thirdparty_scans_managers import NmapScanManager, NiktoScanManager, OpenVASScanManager



logger = logging.getLogger(__name__)


class AuthorizedTargetManager:
    """CRUD y comprobación de pertenencia para el registro de objetivos autorizados.

    Registro de objetivos autorizados (roadmap §6). Antes de que Lybra ejecute
    cualquier operación que toque la red del objetivo (autodescubrimiento propio,
    fingerprinting propio, comprobaciones activas del runtime), el objetivo debe
    estar en este registro por usuario. Es un gate legal, no de red o de
    privilegios: complementa, no sustituye, el rechazo de IPs privadas que ya
    hace ``ScanManager.validate_ip``.
    """

    @staticmethod
    def _normalize(target: str) -> str:
        """Valida ``target`` como IP o CIDR y devuelve su forma canónica."""
        try:
            return str(ipaddress.ip_network(target.strip(), strict=False))
        except ValueError as exc:
            raise IPValidationError(
                message=f"'{target}' no es una IP ni un CIDR válido",
                ip_spec=target,
            ) from exc

    def add(self, user_id: int, target: str, label: str | None = None) -> AuthorizedTarget:
        """Añade un objetivo al registro del usuario. Rechaza duplicados."""
        normalized = self._normalize(target)
        with UnitOfWork() as uow:
            repo = AuthorizedTargetRepository(uow)
            if repo.get_by_target_and_user(normalized, user_id):
                raise DuplicateAuthorizedTargetError(normalized)
            entry = AuthorizedTarget(user_id=user_id, target=normalized, label=label or None)
            repo.save(entry)
        logger.info(f"Objetivo autorizado '{normalized}' añadido por usuario {user_id}")
        return entry

    def list(self, user_id: int) -> list[AuthorizedTarget]:
        """Lista el registro completo del usuario."""
        return build_repository(AuthorizedTargetRepository).get_by_user(user_id)

    def remove(self, target_id: int, user_id: int) -> str:
        """Elimina una entrada del registro, verificando propiedad.

        Returns:
            El target (IP/CIDR) de la entrada eliminada.
        """
        with UnitOfWork() as uow:
            repo = AuthorizedTargetRepository(uow)
            entry = repo.get_by_id_and_user(target_id, user_id)
            if entry is None:
                raise AuthorizedTargetNotFoundError(target_id)
            target = entry.target
            repo.delete(entry)
        logger.info(f"Objetivo autorizado {target_id} eliminado por usuario {user_id}")
        return target

    @staticmethod
    def is_authorized(user_id: int, target: str) -> bool:
        """True si ``target`` (una IP) cae dentro de alguna entrada autorizada del usuario."""
        try:
            ip = ipaddress.ip_address(target.strip())
        except ValueError:
            return False
        entries = build_repository(AuthorizedTargetRepository).get_by_user(user_id)
        return any(ip in ipaddress.ip_network(entry.target, strict=False) for entry in entries)


@ScanManager.register(ScanType.LYBRA)
class LybraEngineManager(ScanManager):
    """
    Manager for Lybra's own vulnerability engine.

    Unlike the other scanners it launches no external subprocess: in the current
    phase (Fase 0) it takes the services discovered by a previous Nmap scan
    (``source_scan_id``) and produces normalized :class:`Finding` rows through the
    :class:`LybraEngine`. Because that work is a fast, in-memory pass (no
    network), it does not go through the base ``_execute_scan`` (built for
    long-running subprocess tasks); the body lives in ``_run_lybra`` and the
    worker entry point ``execute_lybra_scan`` just wraps it in ``job_context``.

    Example:
    >>> manager = LybraEngineManager()
    >>> scan_id = manager.run_scan(source_scan_id=42, user_id=1)
    """

    SCAN_TYPE = ScanType.LYBRA
    _MODEL = LybraScan
    _strategy_class = LybraPrintingStrategy

    # Categories that are point-in-time events, not persistent vulnerability
    # state - excluded from lifecycle tracking (see Phase 2.5 in _run_lybra).
    _EVENT_CATEGORIES = {"fingerprint", "surface_change"}

    def __init__(self, task_queue: ITaskQueue | None = None) -> None:
        super().__init__(task_queue)

    def run_scan(self,
        user_id: int,
        source_scan_id: Optional[int] = None,  # pylint: disable=arguments-differ
        target: Optional[str] = None,
        services: Optional[List[Service]] = None,
        discover_ports: Optional[list] = None,
        deep: bool = False,
        timeout: int = 120,
        programed_scan_id: Optional[int] = None,
    ) -> int:
        """
        Start an Lybra engine scan in one of three modes.

        - **Over a prior Nmap scan** (``source_scan_id``): analyse the services
          that scan already discovered. Ownership/type validated by the caller.
        - **External payload** (``services`` + ``target``, Fase 0.9): analyse a
          services list the caller already resolved — a Hygeia inventory
          adapter is the motivating case, but any in-process producer of a
          ``List[Service]`` qualifies. No network discovery, fingerprinting or
          active checks run in this mode by default (see ``_run_lybra``); it
          exists precisely for services data that came from *not* touching the
          target's network. ``target`` is still required — it is the host
          identity findings get attached to.
        - **Self-discovery** (``target``, optional ``discover_ports``): Lybra
          discovers the open ports itself with its own connect scan (Fase T),
          no Nmap needed. The caller validates the target (reject private, etc.).

        Args:
            deep: Fase 6 "análisis profundo" — also launch Nmap/Nikto/OpenVAS as
                independent corroborator scans (fire-and-forget; their Finding
                rows merge in at read time, see ``format_scan``). In the
                external-payload mode, this additionally requires ``target`` to
                be in the authorized-targets register, since deep corroborators
                touch the network and payload targets are otherwise never
                validated (see ``_run_lybra``).
            programed_scan_id: Set when launched by the scheduler (Themis
                scheduled scans), same convention as the other scan managers.

        Returns:
            Primary key of the created LybraScan record.
        """
        if source_scan_id is not None:
            with UnitOfWork() as uow:
                source = ScanRepository(uow).get_by_id(source_scan_id)
                if not source:
                    raise ScanNotFoundError(source_scan_id)
                scan_target = source.target
        elif services is not None:
            if not target:
                raise ValueError("run_scan requires a target when services is set")
            scan_target = target
        elif target is not None:
            scan_target = target
            if not AuthorizedTargetManager.is_authorized(user_id, scan_target):
                raise TargetNotAuthorizedError(scan_target)
        else:
            raise ValueError("run_scan requires source_scan_id, services, or target")

        scan = self._create_scan_record(
            target=scan_target,
            user_id=user_id,
            source_scan_id=source_scan_id, # type: ignore
            programed_scan_id=programed_scan_id,
        )
        scan_id = scan.id

        self._tq.submit(
            func=LybraEngineManager.execute_lybra_scan, # type: ignore
            args=(scan_id, source_scan_id, discover_ports, deep, services),
            name=f"LybraScan-{scan_id}",
            category=self.TASK_CATEGORY, # type: ignore
            external_id=self.external_id_for(scan_id),
            timeout=timeout + self._scan_timeout_margin,
        )

        if source_scan_id:
            mode = f"fuente Nmap {source_scan_id}"
        elif services is not None:
            mode = "payload externo"
        else:
            mode = "descubrimiento propio"
        mode += " + análisis profundo" if deep else ""
        logger.info(f"Escaneo Lybra {scan_id} iniciado ({mode})")
        return scan_id  # type: ignore

    @staticmethod
    def execute_lybra_scan(
        scan_id: int, 
        source_scan_id: Optional[int] = None,
        discover_ports: Optional[list] = None, 
        deep: bool = False,
        services: Optional[List[Service]] = None
    ) -> None:
        """Entry point submitted to the TaskQueue. Runs the engine in the worker."""
        with job_context():
            manager = LybraEngineManager()
            manager._run_lybra( # type: ignore
                scan_id,
                source_scan_id,
                discover_ports,
                deep,
                services,
            )

    def _run_lybra(
        self, 
        scan_id: int,
        source_scan_id: Optional[int] = None,
        discover_ports: Optional[list] = None,
        deep: bool = False,
        services_payload: Optional[List[Service]] = None,
    ) -> None:
        """Resolve services (from Nmap, own discovery, or a payload), detect, persist.

        This is the testable body of the scan (the ``execute_* seam → _run_*``
        pattern). Runs synchronously; safe to call directly in tests without a
        worker.
        """

        uses_existing_source: bool = source_scan_id is not None
        uses_payload: bool = services_payload is not None
        try:
            self.update_scan_status(scan_id, ScanStatus.RUNNING)

            with UnitOfWork() as uow:
                scan_repo = ScanRepository(uow)
                kb_repo = KbRepository(uow)

                lybra_scan = scan_repo.get_by_id(scan_id)
                source_target = lybra_scan.target if lybra_scan else None
                user_id = lybra_scan.user_id if lybra_scan else None
                
                is_target_authorized = bool(
                    user_id and source_target
                    and AuthorizedTargetManager.is_authorized(user_id, source_target)
                )
                
                fingerprint_findings: list = []
                surface_findings: list = []
                
                if uses_existing_source:
                    open_ports = scan_repo.get_open_ports_for_scan(source_scan_id)
                    source = scan_repo.get_by_id(source_scan_id)
                    source_host_id = source.host_id if source else None
                    source_target = source.target if source else source_target
                    services = services_from_open_ports(open_ports)
                elif uses_payload:
                    host = None
                    if source_target:
                        host = scan_repo.get_host_by_ip(source_target) or scan_repo.get_or_create_host(
                            hostname=source_target, ip_address=source_target,
                        )
                    source_host_id = host.id if host else None
                    services = list(services_payload)
                else:
                    discovered_ports: list = []
                    if not uses_existing_source and source_target:
                        check_reachability = CR.is_host_reachability_check_enabled()
                        is_host_reacheable = self.is_host_reachable(
                            source_target,
                            port=CR.get_host_reachability_check_port(),
                            timeout=CR.get_host_reachability_check_timeout(),
                        )

                        if check_reachability and not is_host_reacheable:
                            logger.warning(
                                f"Host '{source_target}' inalcanzable. Marcando escaneo Lybra {scan_id} como FAILED"
                            )
                            self.update_scan_status(scan_id, ScanStatus.FAILED)
                            return

                        discovered = self._discover_ports(source_target, discover_ports)
                        if discovered is None:
                            logger.error(f"Descubrimiento de puertos fallido para el escaneo Lybra {scan_id}")
                            self.update_scan_status(scan_id, ScanStatus.FAILED)
                            return

                        discovered_ports = discovered

                    source_target = source_target
                    host = None
                    if source_target:
                        host = scan_repo.get_host_by_ip(source_target) or scan_repo.get_or_create_host(
                            hostname=source_target, ip_address=source_target,
                        )
                    source_host_id = host.id if host else None
                    services = services_from_discovered_ports(discovered_ports)

                if (
                    not uses_payload and 
                    source_target and 
                    is_target_authorized and 
                    CR.is_lybra_fingerprinting_enabled()
                ):
                    services, fingerprint_findings = self._fingerprint_services(
                        source_target, 
                        services
                    )

                previous_map = self._previous_findings_map(scan_repo, user_id, source_target, scan_id)

                if source_host_id:
                    surface_findings = self._detect_surface_changes(scan_repo, source_host_id, services)

                engine = LybraEngine(
                    cve_lookup=kb_repo.cves_for_cpe,
                    kev_lookup=lambda cve_id: kb_repo.get_kev(cve_id) is not None,
                    epss_lookup=lambda cve_id: getattr(kb_repo.get_epss(cve_id), "score", None),
                )
                findings_data = engine.analyze(services)
                findings_data.extend(fingerprint_findings)
                findings_data.extend(surface_findings)

            if not uses_payload and source_target and is_target_authorized and CR.is_lybra_active_checks_enabled():
                findings_data.extend(self._run_active_checks(source_target, services))

            deep_scan_ids: list = []
            if deep and source_target:
                if uses_payload and not is_target_authorized:
                    logger.info(
                        f"Análisis profundo omitido para el escaneo Lybra {scan_id}: objetivo no autorizado"
                    )
                else:
                    deep_scan_ids = self._launch_deep_corroborators(
                        user_id, source_target, source_scan_id, services
                    )

            for finding in findings_data:
                finding["host_id"] = source_host_id
                finding["dedup_key"] = compute_dedup_key(finding)
            findings_data = merge_findings(findings_data)

            trackable = [f for f in findings_data if f.get("category") not in self._EVENT_CATEGORIES]
            events = [f for f in findings_data if f.get("category") in self._EVENT_CATEGORIES]
            for event in events:
                event["state"] = "open"
            trackable_previous = {
                key: prev for key, prev in previous_map.items()
                if prev["snapshot"].get("category") not in self._EVENT_CATEGORIES
            }
            findings_data = apply_lifecycle(trackable, trackable_previous) + events

            with UnitOfWork() as uow:
                scan_repo = ScanRepository(uow)
                scan = scan_repo.get_by_id(scan_id)
                scan.host_id = source_host_id
                scan.deep_scan_ids = deep_scan_ids or None  # type: ignore
                self._persist_scan_results(uow, scan, findings_data)
                scan.status = ScanStatus.FINISHED.value  # type: ignore
                scan.finished_at = utcnow_naive()  # type: ignore

            logger.info(f"Escaneo Lybra {scan_id} completado: {len(findings_data)} hallazgos")

        except Exception as e:
            logger.error(f"Error en escaneo Lybra {scan_id}: {e}", exc_info=True)
            self.update_scan_status(scan_id, ScanStatus.FAILED)

    def _discover_ports(self, target: str, discover_ports) -> Optional[list]:
        """Discover open ports with Lybra's own connect scan (Fase T).

        Returns ``None`` (not ``[]``) when discovery itself failed unexpectedly,
        as opposed to running cleanly and finding zero open ports. The caller
        must not conflate the two: treating a failed probe as "everything is
        closed" would falsely mark previously-open findings as fixed once
        lifecycle correlation runs.
        """
        from ..lybra import scan_ports_sync
        try:
            return scan_ports_sync(target, discover_ports)
        except Exception:
            logger.exception("Lybra port discovery failed for %s", target)
            return None

    def _run_active_checks(self, target: str, services) -> list:
        """Run the declarative check runtime against the target's HTTP, TLS and
        network (Fase N) services.

        Best-effort: a runtime failure (unreachable host, etc.) yields no active
        findings rather than failing the whole scan. Safe mode only.
        """
        from ..lybra import load_checks, CheckRuntime, HttpProbe, HostRateLimiter, TlsProbe, NetworkProbe
        try:
            runtime = CheckRuntime(
                load_checks(),
                HttpProbe().fetch,
                mode="safe",
                rate_limiter=HostRateLimiter(),
                tls_fetch=TlsProbe().fetch,
                network_open=NetworkProbe().open,
            )
            return runtime.run(target, services)
        except Exception:
            logger.exception("Lybra active checks failed for %s", target)
            return []

    def _fingerprint_services(self, target: str, services: list) -> tuple:
        """Run Lybra's own HTTP/SSH/FTP dissectors; fill identification gaps and
        record agreement with Nmap.

        Fase F, two jobs at once:

        - When a service already has a product/version (Nmap-sourced), our own
          reading is never used to override it — it only feeds an informational
          "agrees/disagrees with Nmap" finding, the concordance evidence the
          roadmap's Definition of Done needs before Nmap `-sV` can be demoted
          to a fallback for a service family.
        - When a service has *no* product/version (self-discovered, Fase T, no
          Nmap involved), our own reading fills that gap so the version matcher
          (``LybraEngine._resolve_cpe``) has something to work with instead of
          silently finding nothing. It goes in exactly as low-confidence as an
          Nmap-sourced reading would (``qod=70`` in the matcher, same as
          today) — nothing here inflates confidence, it only supplies input.

        Best-effort per service; a probe failure just skips that service.

        Returns:
            A ``(services, findings)`` tuple: the service list with any newly
            identified product/version filled in, and the informational
            fingerprint findings.
        """
        from ..lybra import (
            HttpProbe, SshProbe, FtpProbe, HostRateLimiter, is_http_service, is_ftp_service,
            fingerprint_http, fingerprint_ssh, fingerprint_ftp,
        )
        http_probe = HttpProbe()
        ssh_probe = SshProbe()
        ftp_probe = FtpProbe()
        rate_limiter = HostRateLimiter()
        findings = []
        updated: list = []

        for service in services:
            fp, label = None, None
            try:
                if is_http_service(service):
                    rate_limiter.acquire(target)
                    resp = http_probe.fetch(target, service.port, "GET", "/")
                    if resp is not None:
                        rate_limiter.acquire(target)
                        favicon = http_probe.fetch_bytes(target, service.port, "/favicon.ico")
                        rate_limiter.acquire(target)
                        # Some vendors brand their error page more than their
                        # homepage (a SonicWall's 404 body says so, its "/"
                        # doesn't) — a deliberately nonexistent path lets the
                        # tech-signature feed's error_body matchers see it.
                        error_resp = http_probe.fetch(target, service.port, "GET", "/lybra-nonexistent-check")
                        fp, label = fingerprint_http(resp, favicon, error_resp), "HTTP"
                elif (service.name or "").lower() == "ssh" or service.port == 22:
                    rate_limiter.acquire(target)
                    probed = ssh_probe.fetch(target, service.port or 22)
                    if probed is not None:
                        banner, kexinit_payload = probed
                        fp, label = fingerprint_ssh(banner, kexinit_payload), "SSH"
                elif is_ftp_service(service):
                    # Fase N's opening move (roadmap §"Fase N"): FTP volunteers
                    # its whole banner unprompted, no framing or negotiation.
                    rate_limiter.acquire(target)
                    banner = ftp_probe.fetch(target, service.port or 21)
                    if banner is not None:
                        fp, label = fingerprint_ftp(banner), "FTP"
            except Exception:
                logger.debug("Fingerprinting failed for %s:%s", target, service.port, exc_info=True)

            if fp is None:
                updated.append(service)
                continue

            findings.append(self._fingerprint_finding(service, fp.product, fp.version, label))
            if not service.product and fp.product and fp.version:
                service = replace(service, product=fp.product, version=fp.version)
            updated.append(service)

        return updated, findings

    @staticmethod
    def _fingerprint_finding(service, product: Optional[str], version: Optional[str], label: str) -> dict:
        """Build an informational Finding comparing our fingerprint to Nmap's.

        Nmap-sourced services carry a product/version to compare against; a
        self-discovered service (Fase T, no Nmap involved) has neither, and
        ``agrees_with_nmap`` would flatly return False for lack of a baseline —
        which reads as "we disagree with Nmap" even though there is nothing to
        compare. That case gets its own honest phrasing instead.
        """
        from ..lybra import agrees_with_nmap, QOD_FINGERPRINT
        own = f"{product or '?'} {version or ''}".strip()
        if service.product:
            agrees = agrees_with_nmap(product, version, service.product, service.version)
            nmap = f"{service.product or '?'} {service.version or ''}".strip()
            verdict = "concuerda con Nmap" if agrees else "no concuerda con Nmap"
            title = f"Fingerprint propio ({label}): {own} — {verdict} (Nmap: {nmap})"
        else:
            title = f"Fingerprint propio ({label}): {own} (sin datos de Nmap para comparar)"
        return {
            "title":        title,
            "category":     "fingerprint",
            "port":         service.port,
            "service":      service.name or None,
            "source":       "lybra",
            "check_id":     "lybra:fingerprint@1",
            "feed_version": "lybra-fingerprint-1",
            "qod":          QOD_FINGERPRINT,
            "confirmed":    False,
            "state":        "open",
        }

    def _detect_surface_changes(self, scan_repo, host_id: int, services: list[Service]) -> list:
        """Diff this scan's services against the host's tracked surface (Fase 5).

        Emits an informational finding for a port opening for the first time,
        for a package appearing for the first time (an ``origin="inventory"``
        service with no port, Fase 0.9), or for either kind's product/version
        changing since it was last seen — attack-surface events in their own
        right, not vulnerability guesses. Always upserts every current service
        afterwards, so the surface stays current regardless of whether
        anything changed.
        """
        existing = {
            self._surface_key(s): s for s in scan_repo.get_host_services(host_id)
        }
        # A host's very first Lybra scan establishes the baseline surface, not
        # a change to it — every port would otherwise be "new" by definition,
        # duplicating the open_port finding the matcher already emits for it.
        had_baseline = bool(existing)
        findings: list = []
        for service in services:
            protocol = service.protocol or "tcp"
            prior = existing.get(self._surface_key(service))
            if prior and had_baseline:
                findings.append(service.as_new_finding())
            elif service.product and prior.product and (
                service.product != prior.product or service.version != prior.version
            ):
                findings.append(service.as_old_finding())
            scan_repo.upsert_host_service(
                host_id=host_id, port=service.port, protocol=protocol,
                name=service.name or None, product=service.product or None,
                version=service.version or None, cpe=service.cpe or None,
            )
        return findings

    @staticmethod
    def _surface_key(service_or_row) -> tuple:
        """Identity key for surface tracking: ``(port, protocol)`` for a
        networked service, or ``(None, protocol, product)`` for a portless
        inventory service (Fase 0.9).

        A port already uniquely identifies a listening socket, so the product
        is deliberately excluded there — that is what lets a version bump on
        the *same* port read as "changed", not "closed + reopened". A
        portless service has no such anchor: without folding the product into
        the key, two different installed packages on the same host would
        collide on ``(None, protocol)`` and silently overwrite each other's
        tracked row. Works identically for a ``Service`` and a stored
        ``HostService`` row — both expose the same three attributes.
        """
        protocol = service_or_row.protocol or "tcp"
        if service_or_row.port is not None:
            return (service_or_row.port, protocol, None)
        return (None, protocol, service_or_row.product or None)

    def _launch_deep_corroborators(
        self, user_id: int, 
        target: str,
        source_scan_id: Optional[int], 
        services: list[Service]
    ) -> list:
        """Fire off Nmap/Nikto/OpenVAS as independent corroborator scans (Fase 6).

        Necessarily non-blocking: OpenVAS alone can take up to 4 hours (see its
        own ``run_scan`` timeout), so this cannot be awaited inside this job.
        Each corroborator becomes an ordinary, independently-tracked ``Scan`` —
        visible, cancellable and pollable exactly like a user-launched one. The
        returned ids are stored on the Lybra scan so ``format_scan`` can later
        merge in whichever corroborator ``Finding`` rows are ready.

        - Nmap only when ``source_scan_id`` is None (self-discovery mode) — a
          fresh Nmap run is redundant when Lybra already has Nmap-sourced
          ports for this scan.
        - Nikto only if at least one HTTP-like service was found.
        - OpenVAS always.

        Best-effort per corroborator: a launch failure for one does not affect
        the others or the Lybra scan itself.
        """
        from ..lybra import is_http_service, DEFAULT_PORTS
        ids: list = []

        if source_scan_id is None:
            try:
                ports_str = ",".join(str(p) for p in sorted(set(DEFAULT_PORTS)))
                ids.append(NmapScanManager().run_scan(
                    target_host=target, target_ports=ports_str, user_id=user_id,
                ))
            except Exception:
                logger.exception("Análisis profundo: fallo al lanzar Nmap corroborador para %s", target)

        if any(is_http_service(s) for s in services):
            try:
                ids.append(NiktoScanManager().run_scan(target_domain=target, user_id=user_id))
            except Exception:
                logger.exception("Análisis profundo: fallo al lanzar Nikto corroborador para %s", target)

        try:
            ids.append(OpenVASScanManager().run_scan(target=target, user_id=user_id))
        except Exception:
            logger.exception("Análisis profundo: fallo al lanzar OpenVAS corroborador para %s", target)

        if ids:
            logger.info("Análisis profundo: lanzados %d escaneos corroboradores para %s", len(ids), target)
        return ids

    def _previous_findings_map(self, scan_repo: ScanRepository, user_id: int, target: str, exclude_scan_id: int) -> dict:
        """Build ``dedup_key -> {state, snapshot}`` from the previous Lybra scan
        of this target, for lifecycle comparison."""
        if not user_id or not target:
            return {}
        result: dict = {}
        for pf in scan_repo.get_previous_lybra_findings(user_id, target, exclude_scan_id):
            snapshot = pf.snapshot
            key = pf.dedup_key or compute_dedup_key(snapshot)
            snapshot["dedup_key"] = key
            result[key] = {"state": pf.state or "open", "snapshot": snapshot}
        return result

    @classmethod
    def _finding_view_dict(cls, f: Finding) -> dict:
        d = f.snapshot
        d["id"] = f.id
        d["state"] = f.state
        return d

    def set_finding_state(self, finding_id: int, user_id: int, state: str):
        """Set a finding's lifecycle state (e.g. mark a risk as ``accepted``).

        Scoped to the owner: a finding of another user's scan is reported as not
        found. Returns the updated finding.
        """
        with UnitOfWork() as uow:
            repo = ScanRepository(uow)
            finding = repo.get_finding(finding_id)
            if finding is None:
                raise FindingNotFoundError(finding_id)
            scan = repo.get_by_id(finding.scan_id)
            if scan is None or scan.user_id != user_id:
                raise FindingNotFoundError(finding_id)
            finding.state = state  # type: ignore
            repo.update(finding)
            return finding

    def _create_scan_record(
        self, target: str, user_id: int, source_scan_id: Optional[int] = None,
        programed_scan_id: Optional[int] = None,
    ) -> LybraScan:  # pylint: disable=arguments-differ
        """Create and persist an LybraScan row linked to its source Nmap scan."""
        scan = LybraScan(
            target=target,
            user_id=user_id,
            started_at=utcnow_naive(),
            source_scan_id=source_scan_id,
            programed_scan_id=programed_scan_id,
        )
        with UnitOfWork() as uow:
            ScanRepository(uow).save(scan)
        return scan

    def _persist_scan_results(self, uow, scan, domain_data) -> None:
        """Persist the engine's findings (``domain_data`` is a list of dicts)."""
        ScanRepository(uow).persist_findings(scan, domain_data)

    def format_scan(self, scan_id: int, _scan=None) -> dict:
        scan = _scan or self.get_scan_by_id(scan_id)
        if not scan:
            raise ScanNotFoundError(scan_id)

        repo = build_repository(ScanRepository)
        own_findings = [self._finding_view_dict(f) for f in repo.get_findings_by_scan(scan_id)]

        deep_scan_ids = scan.deep_scan_ids or []
        if deep_scan_ids:
            corroborator_findings = [
                self._finding_view_dict(f)
                for corroborator_id in deep_scan_ids
                for f in repo.get_findings_by_scan(corroborator_id)
            ]
            display_findings = merge_findings(own_findings + corroborator_findings)
        else:
            display_findings = own_findings

        exposure = classify_exposure(scan.target)
        target_authorized = bool(
            scan.target and AuthorizedTargetManager.is_authorized(scan.user_id, scan.target)
        )

        def _priority(f: dict) -> str:
            return score_finding(
                {"cvss_score": f.get("cvss_score"), "in_kev": f.get("in_kev"),
                 "epss_score": f.get("epss_score"), "confirmed": f.get("confirmed")},
                exposure,
            )

        result = {
            "id": scan.id,
            "scanType": "lybra",
            "target": scan.target,
            "sourceScanId": scan.source_scan_id,
            "deep": bool(deep_scan_ids),
            "deepScanIds": deep_scan_ids,
            "exposure": exposure,
            "targetAuthorized": target_authorized,
            "status": getattr(scan, "status", "unknown"),
            "startedAt": isoformat_utc(scan.started_at),
            "finishedAt": isoformat_utc(scan.finished_at),  # type: ignore
            "findings": [
                {
                    "id": f.get("id"),
                    "title": f.get("title"),
                    "category": f.get("category"),
                    "port": f.get("port"),
                    "service": f.get("service"),
                    "cpe": f.get("cpe"),
                    "cveIds": f.get("cve_ids"),
                    "cvssScore": f.get("cvss_score"),
                    "epssScore": f.get("epss_score"),
                    "inKev": f.get("in_kev"),
                    "qod": f.get("qod"),
                    "confirmed": f.get("confirmed"),
                    "source": f.get("source"),
                    "state": f.get("state"),
                    "dedupKey": f.get("dedup_key"),
                    "priority": _priority(f),
                }
                for f in display_findings
            ],
            "totalFindings": len(display_findings),
            "vulnerableFindings": sum(1 for f in display_findings if f.get("category") == "outdated_software"),
            "openFindings": sum(1 for f in display_findings if f.get("state") == "open"),
            "fixedFindings": sum(1 for f in display_findings if f.get("state") == "fixed"),
        }
        self._append_document_info(scan, result)
        return result

    def append_csv_data(self, data: dict, scan: Scan, task: "_Task") -> None:
        """No-op: Lybra does not use the base CSV-logging execution path."""
        pass

