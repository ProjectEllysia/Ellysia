"""EllysiaEngineManager — extraido de sentinel/managers.py (Fase 3 del refactor de estructura)."""

import logging
from datetime import datetime
from typing import Optional
import src.modules.system.config_reading as CR
from src.modules.system.taskqueue import ITaskQueue, job_context
from src.modules.infrastructure import UnitOfWork
from src.modules.infrastructure.session import read_repo
from ..repositories import (
    ScanRepository,
    KbRepository,
)
from ..model import (
    EllysiaScan,
    Scan,
    ScanStatus,
    ScanType,
)
from ..ellysia import (
    EllysiaEngine,
    services_from_open_ports,
    services_from_discovered_ports,
    compute_dedup_key,
    merge_findings,
    apply_lifecycle,
    classify_exposure,
    score_finding,
)
from ..services import _Task
from ..exceptions import (
    ScanNotFoundError,
    FindingNotFoundError,
)

from .scan import ScanManager
from .nmap import NmapScanManager
from .nikto import NiktoScanManager
from .openvas import OpenVASScanManager


logger = logging.getLogger(__name__)


@ScanManager.register(ScanType.ELLYSIA)
class EllysiaEngineManager(ScanManager):
    """
    Manager for Ellysia's own vulnerability engine.

    Unlike the other scanners it launches no external subprocess: in the current
    phase (Fase 0) it takes the services discovered by a previous Nmap scan
    (``source_scan_id``) and produces normalized :class:`Finding` rows through the
    :class:`EllysiaEngine`. Because that work is a fast, in-memory pass (no
    network), it does not go through the base ``_execute_scan`` (built for
    long-running subprocess tasks); the body lives in ``_run_ellysia`` and the
    worker entry point ``execute_ellysia_scan`` just wraps it in ``job_context``.

    Example:
    >>> manager = EllysiaEngineManager()
    >>> scan_id = manager.run_scan(source_scan_id=42, user_id=1)
    """

    SCAN_TYPE = ScanType.ELLYSIA
    _MODEL = EllysiaScan
    _strategy_class = None  # ponytail: no PDF for Ellysia yet; wire a strategy when reports land

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
        Start an Ellysia engine scan in one of two modes.

        - **Over a prior Nmap scan** (``source_scan_id``): analyse the services
          that scan already discovered. Ownership/type validated by the caller.
        - **Self-discovery** (``target``, optional ``discover_ports``): Ellysia
          discovers the open ports itself with its own connect scan (Fase T),
          no Nmap needed. The caller validates the target (reject private, etc.).

        Args:
            deep: Fase 6 "análisis profundo" — also launch Nmap/Nikto/OpenVAS as
                independent corroborator scans (fire-and-forget; their Finding
                rows merge in at read time, see ``format_scan``).

        Returns:
            Primary key of the created EllysiaScan record.
        """
        if source_scan_id is not None:
            with UnitOfWork() as uow:
                source = ScanRepository(uow).get_by_id(source_scan_id)
                if not source:
                    raise ScanNotFoundError(source_scan_id)
                scan_target = source.target
        elif target is not None:
            scan_target = target
        else:
            raise ValueError("run_scan requires source_scan_id or target")

        scan = self._create_scan_record(
            target=scan_target,
            user_id=user_id,
            source_scan_id=source_scan_id, # type: ignore
        )
        scan_id = scan.id

        self._tq.submit(
            func=EllysiaEngineManager.execute_ellysia_scan,
            args=(scan_id, source_scan_id, discover_ports, deep),
            name=f"EllysiaScan-{scan_id}",
            category=self.TASK_CATEGORY,
            external_id=self.external_id_for(scan_id),
            timeout=timeout + self._scan_timeout_margin,
        )

        mode = f"fuente Nmap {source_scan_id}" if source_scan_id else "descubrimiento propio"
        mode += " + análisis profundo" if deep else ""
        logger.info(f"Escaneo Ellysia {scan_id} iniciado ({mode})")
        return scan_id  # type: ignore

    @staticmethod
    def execute_ellysia_scan(scan_id: int, source_scan_id: Optional[int] = None,
                             discover_ports: Optional[list] = None, deep: bool = False) -> None:
        """Entry point submitted to the TaskQueue. Runs the engine in the worker."""
        with job_context():
            EllysiaEngineManager()._run_ellysia(
                scan_id,
                source_scan_id,
                discover_ports,
                deep
            )

    def _run_ellysia(
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
                ellysia_scan = ScanRepository(uow).get_by_id(scan_id)
                scan_target = ellysia_scan.target if ellysia_scan else None
                user_id = ellysia_scan.user_id if ellysia_scan else None


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
                                f"Host '{scan_target}' inalcanzable. Marcando escaneo Ellysia {scan_id} como FAILED"
                            )
                            self.update_scan_status(scan_id, ScanStatus.FAILED)
                            return

                        discovered = self._discover_ports(scan_target, discover_ports)
                        if discovered is None:
                            logger.error(f"Descubrimiento de puertos fallido para el escaneo Ellysia {scan_id}")
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

                previous_map = self._previous_findings_map(scan_repo, user_id, source_target, scan_id)

                engine = EllysiaEngine(
                    cve_lookup=kb_repo.cves_for_cpe,
                    kev_lookup=lambda cve_id: kb_repo.get_kev(cve_id) is not None,
                    epss_lookup=lambda cve_id: getattr(kb_repo.get_epss(cve_id), "score", None),
                )
                findings_data = engine.analyze(services)

            # Phase 2 — active checks over the network, outside any transaction.
            # Opt-in (they touch the target; see roadmap §6 authorized targets).
            if source_target and CR.is_ellysia_active_checks_enabled():
                findings_data.extend(self._run_active_checks(source_target, services))

            # Phase 2.3 — own fingerprinting (Fase F), calibrated against Nmap.
            if source_target and CR.is_ellysia_fingerprinting_enabled():
                findings_data.extend(self._run_fingerprinting(source_target, services))

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
            findings_data = apply_lifecycle(findings_data, previous_map)

            # Phase 3 — persist everything.
            with UnitOfWork() as uow:
                scan_repo = ScanRepository(uow)
                scan = scan_repo.get_by_id(scan_id)
                scan.host_id = source_host_id
                scan.deep_scan_ids = deep_scan_ids or None  # type: ignore
                self._persist_scan_results(uow, scan, findings_data)
                scan.status = ScanStatus.FINISHED.value  # type: ignore
                scan.finished_at = datetime.now()  # type: ignore

            logger.info(f"Escaneo Ellysia {scan_id} completado: {len(findings_data)} hallazgos")

        except Exception as e:
            logger.error(f"Error en escaneo Ellysia {scan_id}: {e}", exc_info=True)
            self.update_scan_status(scan_id, ScanStatus.FAILED)

    def _discover_ports(self, target: str, discover_ports) -> Optional[list]:
        """Discover open ports with Ellysia's own connect scan (Fase T).

        Returns ``None`` (not ``[]``) when discovery itself failed unexpectedly,
        as opposed to running cleanly and finding zero open ports. The caller
        must not conflate the two: treating a failed probe as "everything is
        closed" would falsely mark previously-open findings as fixed once
        lifecycle correlation runs.
        """
        from ..ellysia import scan_ports_sync
        try:
            return scan_ports_sync(target, discover_ports)
        except Exception:
            logger.exception("Ellysia port discovery failed for %s", target)
            return None

    def _run_active_checks(self, target: str, services) -> list:
        """Run the declarative check runtime against the target's HTTP services.

        Best-effort: a runtime failure (unreachable host, etc.) yields no active
        findings rather than failing the whole scan. Safe mode only.
        """
        from ..ellysia import load_checks, CheckRuntime, HttpProbe, HostRateLimiter
        try:
            runtime = CheckRuntime(
                load_checks(),
                HttpProbe().fetch,
                mode="safe",
                rate_limiter=HostRateLimiter(),
            )
            return runtime.run(target, services)
        except Exception:
            logger.exception("Ellysia active checks failed for %s", target)
            return []

    def _run_fingerprinting(self, target: str, services) -> list:
        """Run Ellysia's own HTTP/SSH dissectors and record agreement with Nmap.

        Informational only (Fase F): a fingerprint finding never feeds
        vulnerability confidence — it exists to accumulate the concordance
        evidence the roadmap's Definition of Done requires before Nmap `-sV`
        can be demoted to a fallback for a service family. Best-effort per
        service; a probe failure just skips that service.
        """
        from ..ellysia import (
            HttpProbe, SshProbe, HostRateLimiter, is_http_service,
            fingerprint_http, fingerprint_ssh,
        )
        http_probe = HttpProbe()
        ssh_probe = SshProbe()
        rate_limiter = HostRateLimiter()
        findings = []

        for service in services:
            try:
                if is_http_service(service):
                    rate_limiter.acquire(target)
                    resp = http_probe.fetch(target, service.port, "GET", "/")
                    if resp is None:
                        continue
                    rate_limiter.acquire(target)
                    favicon = http_probe.fetch_bytes(target, service.port, "/favicon.ico")
                    fp = fingerprint_http(resp, favicon)
                    findings.append(self._fingerprint_finding(service, fp.product, fp.version, "HTTP"))
                elif (service.name or "").lower() == "ssh" or service.port == 22:
                    rate_limiter.acquire(target)
                    probed = ssh_probe.fetch(target, service.port or 22)
                    if probed is None:
                        continue
                    banner, kexinit_payload = probed
                    fp = fingerprint_ssh(banner, kexinit_payload)
                    findings.append(self._fingerprint_finding(service, fp.product, fp.version, "SSH"))
            except Exception:
                logger.debug("Fingerprinting failed for %s:%s", target, service.port, exc_info=True)
        return findings

    @staticmethod
    def _fingerprint_finding(service, product: Optional[str], version: Optional[str], label: str) -> dict:
        """Build an informational Finding comparing our fingerprint to Nmap's.

        Nmap-sourced services carry a product/version to compare against; a
        self-discovered service (Fase T, no Nmap involved) has neither, and
        ``agrees_with_nmap`` would flatly return False for lack of a baseline —
        which reads as "we disagree with Nmap" even though there is nothing to
        compare. That case gets its own honest phrasing instead.
        """
        from ..ellysia import agrees_with_nmap, QOD_FINGERPRINT
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
            "source":       "ellysia",
            "check_id":     "ellysia:fingerprint@1",
            "feed_version": "ellysia-fingerprint-1",
            "qod":          QOD_FINGERPRINT,
            "confirmed":    False,
            "state":        "open",
        }

    def _launch_deep_corroborators(self, user_id: int, target: str,
                                   source_scan_id: Optional[int], services) -> list:
        """Fire off Nmap/Nikto/OpenVAS as independent corroborator scans (Fase 6).

        Necessarily non-blocking: OpenVAS alone can take up to 4 hours (see its
        own ``run_scan`` timeout), so this cannot be awaited inside this job.
        Each corroborator becomes an ordinary, independently-tracked ``Scan`` —
        visible, cancellable and pollable exactly like a user-launched one. The
        returned ids are stored on the Ellysia scan so ``format_scan`` can later
        merge in whichever corroborator ``Finding`` rows are ready.

        - Nmap only when ``source_scan_id`` is None (self-discovery mode) — a
          fresh Nmap run is redundant when Ellysia already has Nmap-sourced
          ports for this scan.
        - Nikto only if at least one HTTP-like service was found.
        - OpenVAS always.

        Best-effort per corroborator: a launch failure for one does not affect
        the others or the Ellysia scan itself.
        """
        from ..ellysia import is_http_service, DEFAULT_PORTS
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
        """Build ``dedup_key -> {state, snapshot}`` from the previous Ellysia scan
        of this target, for lifecycle comparison."""
        if not user_id or not target:
            return {}
        result: dict = {}
        for pf in scan_repo.get_previous_ellysia_findings(user_id, target, exclude_scan_id):
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
        d = EllysiaEngineManager._finding_snapshot(f)
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

    def _create_scan_record(self, target: str, user_id: int, source_scan_id: int) -> EllysiaScan:  # pylint: disable=arguments-differ
        """Create and persist an EllysiaScan row linked to its source Nmap scan."""
        scan = EllysiaScan(
            target=target,
            user_id=user_id,
            started_at=datetime.now(),
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

        def _priority(f: dict) -> str:
            return score_finding(
                {"cvss_score": f.get("cvss_score"), "in_kev": f.get("in_kev"),
                 "epss_score": f.get("epss_score"), "confirmed": f.get("confirmed")},
                exposure,
            )

        result = {
            "id": scan.id,
            "scanType": "ellysia",
            "target": scan.target,
            "sourceScanId": scan.source_scan_id,
            "deep": bool(deep_scan_ids),
            "deepScanIds": deep_scan_ids,
            "exposure": exposure,
            "status": getattr(scan, "status", "unknown"),
            "startedAt": scan.started_at.isoformat(),
            "finishedAt": scan.finished_at.isoformat() if scan.finished_at else None,  # type: ignore
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
        """No-op: Ellysia does not use the base CSV-logging execution path."""
        pass

