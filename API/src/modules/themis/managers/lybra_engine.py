"""LybraEngineManager — extraido de themis/managers.py (Fase 3 del refactor de estructura)."""

import logging
from dataclasses import replace
from typing import Optional
import src.modules.system.config_reading as CR
from src.modules.system.taskqueue import ITaskQueue, job_context
from src.modules.infrastructure import UnitOfWork
from src.modules.infrastructure.session import read_repo
from src.modules.shared import utcnow_naive, isoformat_utc
from ..repositories import (
    ScanRepository,
    KbRepository,
)
from ..model import (
    LybraScan,
    Scan,
    ScanStatus,
    ScanType,
)
from ..lybra import (
    LybraEngine,
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
)

from .scan import ScanManager
from .nmap import NmapScanManager
from .nikto import NiktoScanManager
from .openvas import OpenVASScanManager
from .authorized_targets import AuthorizedTargetManager


logger = logging.getLogger(__name__)


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
        discover_ports: Optional[list] = None,
        deep: bool = False,
        timeout: int = 120
    ) -> int:
        """
        Start an Lybra engine scan in one of two modes.

        - **Over a prior Nmap scan** (``source_scan_id``): analyse the services
          that scan already discovered. Ownership/type validated by the caller.
        - **Self-discovery** (``target``, optional ``discover_ports``): Lybra
          discovers the open ports itself with its own connect scan (Fase T),
          no Nmap needed. The caller validates the target (reject private, etc.).

        Args:
            deep: Fase 6 "análisis profundo" — also launch Nmap/Nikto/OpenVAS as
                independent corroborator scans (fire-and-forget; their Finding
                rows merge in at read time, see ``format_scan``).

        Returns:
            Primary key of the created LybraScan record.
        """
        if source_scan_id is not None:
            with UnitOfWork() as uow:
                source = ScanRepository(uow).get_by_id(source_scan_id)
                if not source:
                    raise ScanNotFoundError(source_scan_id)
                scan_target = source.target
        elif target is not None:
            # Self-discovery (Fase T) touches the target directly — requires
            # an authorized-targets register entry (roadmap §6), unlike
            # analysing a prior Nmap scan's already-collected services.
            scan_target = target
            if not AuthorizedTargetManager.is_authorized(user_id, scan_target):
                raise TargetNotAuthorizedError(scan_target)
        else:
            raise ValueError("run_scan requires source_scan_id or target")

        scan = self._create_scan_record(
            target=scan_target,
            user_id=user_id,
            source_scan_id=source_scan_id, # type: ignore
        )
        scan_id = scan.id

        self._tq.submit(
            func=LybraEngineManager.execute_lybra_scan, # type: ignore
            args=(scan_id, source_scan_id, discover_ports, deep),
            name=f"LybraScan-{scan_id}",
            category=self.TASK_CATEGORY, # type: ignore
            external_id=self.external_id_for(scan_id),
            timeout=timeout + self._scan_timeout_margin,
        )

        mode = f"fuente Nmap {source_scan_id}" if source_scan_id else "descubrimiento propio"
        mode += " + análisis profundo" if deep else ""
        logger.info(f"Escaneo Lybra {scan_id} iniciado ({mode})")
        return scan_id  # type: ignore

    @staticmethod
    def execute_lybra_scan(scan_id: int, source_scan_id: Optional[int] = None,
                             discover_ports: Optional[list] = None, deep: bool = False) -> None:
        """Entry point submitted to the TaskQueue. Runs the engine in the worker."""
        with job_context():
            manager = LybraEngineManager()
            manager._run_lybra( # type: ignore
                scan_id,
                source_scan_id,
                discover_ports,
                deep
            )

    def _run_lybra(
        self, scan_id: int,
        source_scan_id: Optional[int] = None,
        discover_ports: Optional[list] = None,
        deep: bool = False
    ) -> None:
        """Resolve services (from Nmap or own discovery), detect, and persist.

        This is the testable body of the scan (the ``execute_* seam → _run_*``
        pattern). Runs synchronously; safe to call directly in tests without a
        worker.
        """

        uses_existing_source: bool = source_scan_id is not None
        try:
            self.update_scan_status(scan_id, ScanStatus.RUNNING)

            # Read the scan's own target + owner once (both modes need them).
            with UnitOfWork() as uow:
                lybra_scan = ScanRepository(uow).get_by_id(scan_id)
                scan_target = lybra_scan.target if lybra_scan else None
                user_id = lybra_scan.user_id if lybra_scan else None


            # Phase 1 — resolve services, then version/informational detection
            # with the KB in-session, and load the previous scan for lifecycle.
            with UnitOfWork() as uow:
                scan_repo = ScanRepository(uow)
                kb_repo = KbRepository(uow)

                if uses_existing_source:
                    open_ports = scan_repo.get_open_ports_for_scan(source_scan_id)
                    source = scan_repo.get_by_id(source_scan_id)
                    source_host_id = source.host_id if source else None
                    source_target = source.target if source else scan_target
                    services = services_from_open_ports(open_ports)
                else:
                    # Phase 0 — self-discovery (network) happens outside any transaction.
                    discovered_ports: list = []
                    if not uses_existing_source and scan_target:
                        check_reachability = CR.is_host_reachability_check_enabled()
                        is_host_reacheable = self.is_host_reachable(
                            scan_target,
                            port=CR.get_host_reachability_check_port(),
                            timeout=CR.get_host_reachability_check_timeout(),
                        )

                        if check_reachability and not is_host_reacheable:
                            logger.warning(
                                f"Host '{scan_target}' inalcanzable. Marcando escaneo Lybra {scan_id} como FAILED"
                            )
                            self.update_scan_status(scan_id, ScanStatus.FAILED)
                            return

                        discovered = self._discover_ports(scan_target, discover_ports)
                        if discovered is None:
                            logger.error(f"Descubrimiento de puertos fallido para el escaneo Lybra {scan_id}")
                            self.update_scan_status(scan_id, ScanStatus.FAILED)
                            return

                        discovered_ports = discovered

                    source_target = scan_target
                    host = None
                    if scan_target:
                        host = scan_repo.get_host_by_ip(scan_target) or scan_repo.get_or_create_host(
                            hostname=scan_target, ip_address=scan_target,
                        )
                    source_host_id = host.id if host else None
                    services = services_from_discovered_ports(discovered_ports)

                # Fase F/R only run against a target the user has explicitly
                # authorized (roadmap §6). Self-discovery mode already
                # guarantees this at launch (see run_scan); this also covers
                # the sourceScanId mode, where the target comes from a prior
                # Nmap scan that was never itself gated by this register.
                target_authorized = bool(
                    user_id and source_target
                    and AuthorizedTargetManager.is_authorized(user_id, source_target)
                )

                # Phase 0.5 — own fingerprinting (Fase F), before the matcher runs.
                # A self-discovered service (Fase T, no Nmap involved) carries no
                # product/version at all; without this, the matcher below would
                # have nothing to look up and a self-discovery-only scan would
                # never find a single CVE. This never overrides a Nmap-sourced
                # reading — see _fingerprint_services.
                fingerprint_findings: list = []
                if source_target and target_authorized and CR.is_lybra_fingerprinting_enabled():
                    services, fingerprint_findings = self._fingerprint_services(source_target, services)

                previous_map = self._previous_findings_map(scan_repo, user_id, source_target, scan_id)

                # Phase 0.7 — surface tracking (Fase 5's "cambio de sujeto"): a
                # port opening for the first time, or a service's version
                # changing, is an attack-surface event in its own right,
                # independent of whether it happens to match a known CVE.
                surface_findings: list = []
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

            # Phase 2 — active checks over the network, outside any transaction.
            # Opt-in (they touch the target; see roadmap §6 authorized targets).
            if source_target and target_authorized and CR.is_lybra_active_checks_enabled():
                findings_data.extend(self._run_active_checks(source_target, services))

            # Phase 2.7 — deep analysis (Fase 6): launch Nmap/Nikto/OpenVAS as
            # independent corroborator scans. Fire-and-forget — their Finding
            # rows are merged in only at read time (format_scan), never written
            # into this scan's own findings_data.
            deep_scan_ids: list = []
            if deep and source_target:
                deep_scan_ids = self._launch_deep_corroborators(user_id, source_target, source_scan_id, services)

            # Phase 2.5 — correlation: key, merge duplicates/sources, set lifecycle.
            for finding in findings_data:
                finding["host_id"] = source_host_id
                finding["dedup_key"] = compute_dedup_key(finding)
            findings_data = merge_findings(findings_data)

            # Lifecycle (open/fixed/regressed/accepted) models a vulnerability's
            # persistent state - it does not fit a point-in-time event like a
            # fingerprint reading or a surface_change notification. Carrying an
            # event forward as "fixed" once it stops recurring would read as
            # nonsense ("the new-port-opened event has been fixed") and, worse,
            # re-emit the same finding on every later unchanged scan. Events
            # always stay "open" and skip the carry-forward machinery entirely.
            trackable = [f for f in findings_data if f.get("category") not in self._EVENT_CATEGORIES]
            events = [f for f in findings_data if f.get("category") in self._EVENT_CATEGORIES]
            for event in events:
                event["state"] = "open"
            trackable_previous = {
                key: prev for key, prev in previous_map.items()
                if prev["snapshot"].get("category") not in self._EVENT_CATEGORIES
            }
            findings_data = apply_lifecycle(trackable, trackable_previous) + events

            # Phase 3 — persist everything.
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
        """Run the declarative check runtime against the target's HTTP and TLS services.

        Best-effort: a runtime failure (unreachable host, etc.) yields no active
        findings rather than failing the whole scan. Safe mode only.
        """
        from ..lybra import load_checks, CheckRuntime, HttpProbe, HostRateLimiter, TlsProbe
        try:
            runtime = CheckRuntime(
                load_checks(),
                HttpProbe().fetch,
                mode="safe",
                rate_limiter=HostRateLimiter(),
                tls_fetch=TlsProbe().fetch,
            )
            return runtime.run(target, services)
        except Exception:
            logger.exception("Lybra active checks failed for %s", target)
            return []

    def _fingerprint_services(self, target: str, services: list) -> tuple:
        """Run Lybra's own HTTP/SSH dissectors; fill identification gaps and
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
            HttpProbe, SshProbe, HostRateLimiter, is_http_service,
            fingerprint_http, fingerprint_ssh,
        )
        http_probe = HttpProbe()
        ssh_probe = SshProbe()
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
                        fp, label = fingerprint_http(resp, favicon), "HTTP"
                elif (service.name or "").lower() == "ssh" or service.port == 22:
                    rate_limiter.acquire(target)
                    probed = ssh_probe.fetch(target, service.port or 22)
                    if probed is not None:
                        banner, kexinit_payload = probed
                        fp, label = fingerprint_ssh(banner, kexinit_payload), "SSH"
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

    def _detect_surface_changes(self, scan_repo, host_id: int, services: list) -> list:
        """Diff this scan's services against the host's tracked surface (Fase 5).

        Emits an informational finding for a port opening for the first time,
        or for a service's product/version changing since it was last seen —
        attack-surface events in their own right, not vulnerability guesses.
        Always upserts every current service afterwards, so the surface stays
        current regardless of whether anything changed.
        """
        existing = {
            (s.port, s.protocol): s for s in scan_repo.get_host_services(host_id)
        }
        # A host's very first Lybra scan establishes the baseline surface, not
        # a change to it — every port would otherwise be "new" by definition,
        # duplicating the open_port finding the matcher already emits for it.
        had_baseline = bool(existing)
        findings: list = []
        for service in services:
            protocol = service.protocol or "tcp"
            prior = existing.get((service.port, protocol))
            if prior is None:
                if had_baseline:
                    findings.append(self._surface_finding(
                        service, f"Nuevo puerto abierto: {service.port}/{protocol} ({service.name or 'desconocido'})"
                    ))
            elif service.product and prior.product and (
                service.product != prior.product or service.version != prior.version
            ):
                findings.append(self._surface_finding(
                    service,
                    f"Cambio de versión detectado en el puerto {service.port}: "
                    f"{prior.product} {prior.version or ''} -> {service.product} {service.version or ''}".strip()
                ))
            scan_repo.upsert_host_service(
                host_id=host_id, port=service.port, protocol=protocol,
                name=service.name or None, product=service.product or None,
                version=service.version or None, cpe=service.cpe or None,
            )
        return findings

    @staticmethod
    def _surface_finding(service, title: str) -> dict:
        """Build an informational Finding for an attack-surface change (Fase 5)."""
        return {
            "title":        title,
            "category":     "surface_change",
            "port":         service.port,
            "service":      service.name or None,
            "source":       "lybra",
            "check_id":     "lybra:surface-change@1",
            "feed_version": "lybra-surface-1",
            "qod":          QOD_OPEN_PORT,
            "confirmed":    True,
            "state":        "open",
        }

    def _launch_deep_corroborators(self, user_id: int, target: str,
                                   source_scan_id: Optional[int], services) -> list:
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

    def _previous_findings_map(self, scan_repo, user_id, target, exclude_scan_id) -> dict:
        """Build ``dedup_key -> {state, snapshot}`` from the previous Lybra scan
        of this target, for lifecycle comparison."""
        if not user_id or not target:
            return {}
        result: dict = {}
        for pf in scan_repo.get_previous_lybra_findings(user_id, target, exclude_scan_id):
            snapshot = self._finding_snapshot(pf)
            key = pf.dedup_key or compute_dedup_key(snapshot)
            snapshot["dedup_key"] = key
            result[key] = {"state": pf.state or "open", "snapshot": snapshot}
        return result

    @staticmethod
    def _finding_snapshot(f) -> dict:
        """Plain-dict copy of a Finding's columns (to recreate a 'fixed' ghost).

        Deliberately excludes ``id``/``state``: this dict gets handed to
        ``persist_findings`` (``Finding(scan_id=..., **data)``) when carrying a
        lifecycle ghost forward — an explicit ``id`` there would collide with an
        existing primary key on flush. Use :meth:`_finding_view_dict` for
        anything display-only (never persisted).
        """
        return {
            "host_id": f.host_id, "title": f.title, "category": f.category,
            "port": f.port, "service": f.service, "cpe": f.cpe, "cve_ids": f.cve_ids,
            "cvss_score": f.cvss_score, "cvss_vector": f.cvss_vector,
            "epss_score": f.epss_score, "in_kev": f.in_kev,
            "exploit_maturity": f.exploit_maturity, "source": f.source,
            "check_id": f.check_id, "feed_version": f.feed_version,
            "dedup_key": f.dedup_key, "qod": f.qod, "confirmed": f.confirmed,
        }

    @staticmethod
    def _finding_view_dict(f) -> dict:
        """``_finding_snapshot`` plus ``id``/``state``, for display only (Fase 6
        read-time deep merge in ``format_scan``) — never pass this to
        ``persist_findings``."""
        d = LybraEngineManager._finding_snapshot(f)
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

    def _create_scan_record(self, target: str, user_id: int, source_scan_id: int) -> LybraScan:  # pylint: disable=arguments-differ
        """Create and persist an LybraScan row linked to its source Nmap scan."""
        scan = LybraScan(
            target=target,
            user_id=user_id,
            started_at=utcnow_naive(),
            source_scan_id=source_scan_id,
        )
        with UnitOfWork() as uow:
            ScanRepository(uow).save(scan)
        return scan

    def _persist_scan_results(self, uow, scan, domain_data) -> None:
        """Persist the engine's findings (``domain_data`` is a list of dicts)."""
        ScanRepository(uow).persist_findings(scan, domain_data)

    def format_scan(self, scan_id: int) -> dict:
        scan = self.get_scan_by_id(scan_id)
        if not scan:
            raise ScanNotFoundError(scan_id)

        repo = read_repo(ScanRepository)
        own_findings = [self._finding_view_dict(f) for f in repo.get_findings_by_scan(scan_id)]

        # Fase 6 "análisis profundo": merge in the corroborator scans' own
        # Finding rows at READ time — never persisted here. merge_findings
        # (Fase 5) already groups by dedup_key regardless of which scan wrote
        # each row, so this is the same fusion logic used within a single scan,
        # just applied across scan_ids. A corroborator still mid-run simply has
        # no Finding rows yet and contributes nothing until it finishes.
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

