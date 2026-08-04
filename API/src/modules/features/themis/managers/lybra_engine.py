"""LybraEngineManager — extraido de themis/managers.py (Fase 3 del refactor de estructura)."""

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
)
from ..model import (
    Finding,
    LybraScan,
    Scan,
    ScanStatus,
    ScanType,
)
from ..lybra import (
    LybraEngine,
    Service,
    compute_dedup_key,
    merge_findings,
    apply_lifecycle,
    classify_exposure,
    score_finding,
    QOD_OPEN_PORT,
    QOD_FINGERPRINT,
    default_dissectors,
    agrees_with_nmap,
    HostRateLimiter,
    load_checks,
    CheckRuntime,
    HttpProbe,
    TlsProbe,
    NetworkProbe,
    default_script_plugins,
    is_http_service,
    DEFAULT_PORTS,
    scan_ports_sync,
    scan_udp_ports_sync,
)
from ..lybra.ingest import select_for_services, translate_all
from ..services import _Task, LybraPrintingStrategy
from ..services.nuclei_templates import NucleiTemplateStore
from ..exceptions import (
    ScanNotFoundError,
    FindingNotFoundError,
)

from .scan import ScanManager
from .thirdparty_scans_managers import NmapScanManager, NiktoScanManager, NucleiScanManager
from .authorized_target import AuthorizedTargetManager


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
        services: Optional[List[Service]] = None,
        discover_ports: Optional[list] = None,
        deep: bool = False,
        timeout: int = 120,
        programed_scan_id: Optional[int] = None,
        asset_id: Optional[int] = None,
    ) -> int:
        """
        Start an Lybra engine scan in one of three modes.

        - **Over a prior Nmap scan** (``source_scan_id``): analyse the services
          that scan already discovered. Ownership/type validated by the caller.
        - **External payload** (``services`` + ``target``): analyse a
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
            deep: Fase 6 "análisis profundo" — also launch Nmap/Nikto/Nuclei as
                independent corroborator scans (fire-and-forget; their Finding
                rows merge in at read time, see ``format_scan``). In the
                external-payload mode, this additionally requires ``target`` to
                be in the authorized-targets register, since deep corroborators
                touch the network and payload targets are otherwise never
                validated (see ``_run_lybra``).
            programed_scan_id: Set when launched by the scheduler (Themis
                scheduled scans), same convention as the other scan managers.
            asset_id: Fase I — the Hygeia asset whose inventory produced
                ``services``. Recorded on the scan row for provenance and
                grouping; it is never an input to the analysis itself, which
                is why it does not travel in the TaskQueue args.

        Returns:
            Primary key of the created LybraScan record.
        """
        from .lybra_sources import ServiceSource  # ciclo de imports: lybra_sources importa este módulo

        source = ServiceSource.build_for_args(source_scan_id, services, discover_ports)
        scan_target = source.scan_target(user_id, target)

        scan = self._create_scan_record(
            target=scan_target,
            user_id=user_id,
            source_scan_id=source_scan_id, # type: ignore
            programed_scan_id=programed_scan_id,
            asset_id=asset_id,
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

        mode = source.label + (" + análisis profundo" if deep else "")
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
        from .lybra_sources import ServiceSource

        source = ServiceSource.build_for_args(source_scan_id, services_payload, discover_ports)
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

                resolved = source.resolve_services(scan_repo, self, source_target)
                if resolved is None:
                    self.update_scan_status(scan_id, ScanStatus.FAILED)
                    return
                services, source_host_id, source_target = resolved.services, resolved.host_id, resolved.target

                fingerprint_findings: list = []
                if (
                    source.probes_target_network
                    and source_target
                    and is_target_authorized
                    and CR.lybra_config().fingerprinting_enabled
                ):
                    services, fingerprint_findings = self._fingerprint_services(
                        source_target,
                        services
                    )

                previous_map = self._previous_findings_map(
                    scan_repo,
                    user_id,
                    source_target,
                    scan_id
                )

                surface_findings: list = []
                if source_host_id:
                    surface_findings = self._detect_surface_changes(scan_repo, source_host_id, services)

                engine = LybraEngine(
                    cve_lookup=kb_repo.cves_for_cpe,
                    kev_lookup=lambda cve_id: kb_repo.get_kev(cve_id) is not None,
                    epss_lookup=lambda cve_id: getattr(kb_repo.get_epss(cve_id), "score", None),
                    product_alias_lookup=kb_repo.resolve_product_alias,
                )
                findings_data = engine.analyze(services)
                findings_data.extend(fingerprint_findings)
                findings_data.extend(surface_findings)

            if source.probes_target_network and source_target and is_target_authorized and CR.lybra_config().active_checks:
                findings_data.extend(self._run_active_checks(source_target, services))

            deep_scan_ids: list = []
            if deep and source_target:
                if source.deep_requires_authorization and not is_target_authorized:
                    logger.info(
                        f"Análisis profundo omitido para el escaneo Lybra {scan_id}: objetivo no autorizado"
                    )
                else:
                    deep_scan_ids = self._launch_deep_corroborators(
                        user_id, source_target, source, services
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
        try:
            return scan_ports_sync(target, discover_ports)
        except Exception:
            logger.exception("Lybra port discovery failed for %s", target)
            return None

    def _discover_udp_ports(self, target: str) -> list:
        """Discover open UDP ports via the curated probe table (Fase N/Ronda 1).

        Unlike :meth:`_discover_ports`, this never returns ``None``: UDP
        silence is *by definition* indistinguishable from "nothing there", so
        a probe failure carries no information that would justify discarding
        an otherwise good TCP discovery result — best-effort, ``[]`` on any
        error. Always uses :data:`UDP_PROBES` (never the caller's TCP port
        list): a user-supplied ``discover_ports`` is a TCP list.
        """
        try:
            return scan_udp_ports_sync(target)
        except Exception:
            logger.exception("Lybra UDP port discovery failed for %s", target)
            return []

    def _run_active_checks(self, target: str, services) -> list:
        """Run the check runtime against the target's HTTP, TLS, network (Fase N)
        and script (Fase R) services.

        Best-effort: a runtime failure (unreachable host, etc.) yields no active
        findings rather than failing the whole scan. Safe mode only.
        """
        try:
            runtime = CheckRuntime(
                load_checks() + self._ingested_checks(services),
                HttpProbe().fetch,
                mode="safe",
                rate_limiter=HostRateLimiter(),
                tls_fetch=TlsProbe().fetch,
                network_open=NetworkProbe().open,
                script_plugins=default_script_plugins(),
            )
            return runtime.run(target, services)
        except Exception:
            logger.exception("Lybra active checks failed for %s", target)
            return []

    def _ingested_checks(self, services) -> list:
        """Checks traducidos del árbol de plantillas de Nuclei (Fase R).

        Desactivado por defecto: hasta que el censo de la Fase U4 diga que la
        ingesta merece la pena, esto devuelve una lista vacía y el motor corre
        exactamente con su feed propio, como hasta ahora.

        La selección (:func:`select_for_services`) se aplica **aquí**, antes de
        construir el runtime, y no dentro de él: el feed propio no debe pagar
        nada por que esta capa exista. Sin ese filtro previo, miles de
        plantillas por servicio a 0,2 s de limitador serían horas de tráfico
        contra el objetivo.

        Best-effort igual que el resto del método: si el árbol no está o algo
        falla, se sigue con el feed propio en vez de hundir el escaneo.
        """
        if not CR.lybra_ingest_config().enabled:
            return []
        try:
            store = NucleiTemplateStore()
            if not store.is_available:
                logger.warning(
                    "Ingesta de plantillas activada pero no hay árbol de plantillas; "
                    "se sigue solo con el feed propio"
                )
                return []
            translated = translate_all(
                (document for _path, document in store.iter_templates()),
                store.version,
            )
            return select_for_services(
                translated,
                services,
                min_severity=CR.lybra_ingest_config().min_severity,
                max_checks=CR.lybra_ingest_config().max_checks,
            )
        except Exception:
            logger.exception("Fallo ingiriendo plantillas de Nuclei; se sigue con el feed propio")
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

        Best-effort per service; a probe failure just skips that service. The
        dissector selection itself is a registry lookup
        (:func:`~..lybra.default_dissectors`), not an if/elif chain — adding
        protocol N+1 to Fase N never touches this method again, only that
        registry.

        Returns:
            A ``(services, findings)`` tuple: the service list with any newly
            identified product/version filled in, and the informational
            fingerprint findings.
        """
        dissectors = default_dissectors()
        rate_limiter = HostRateLimiter()
        findings = []
        updated: list = []

        for service in services:
            dissector = next((d for d in dissectors if d.applies(service)), None)
            result = None
            if dissector is not None:
                try:
                    result = dissector.probe(target, service, rate_limiter)
                except Exception:
                    logger.debug("Fingerprinting failed for %s:%s", target, service.port, exc_info=True)

            if result is None:
                updated.append(service)
                continue

            findings.append(self._fingerprint_finding(service, result.product, result.version, result.label))
            if not service.product and result.product and result.version:
                service = replace(service, product=result.product, version=result.version)
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
            "protocol":     service.protocol,
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
            if prior is None:
                if had_baseline:
                    findings.append(self._surface_finding(service, self._new_surface_title(service, protocol)))
            elif service.product and prior.product and (
                service.product != prior.product or service.version != prior.version
            ):
                findings.append(self._surface_finding(
                    service, self._changed_surface_title(service, prior)
                ))
            scan_repo.upsert_host_service(
                host_id=host_id, port=service.port, protocol=protocol,
                name=service.name or None, product=service.product or None,
                version=service.version or None, cpe=service.cpe or None,
            )
        return findings

    @staticmethod
    def _new_surface_title(service, protocol: str) -> str:
        """Title for a first-seen port or package (Fase 0.9 adds the latter)."""
        if service.port is not None:
            return f"Nuevo puerto abierto: {service.port}/{protocol} ({service.name or 'desconocido'})"
        return f"Nuevo paquete instalado: {service.label}"

    @staticmethod
    def _changed_surface_title(service, prior) -> str:
        """Title for a product/version change on a tracked port or package."""
        change = f"{prior.product} {prior.version or ''} -> {service.product} {service.version or ''}".strip()
        if service.port is not None:
            return f"Cambio de versión detectado en el puerto {service.port}: {change}"
        return f"Cambio de versión detectado en el paquete {service.product}: {change}"

    @staticmethod
    def _surface_finding(service, title: str) -> dict:
        """Build an informational Finding for an attack-surface change (Fase 5).

        ``service`` falls back to ``product`` when there is no service name —
        for a portless (inventory-origin) service this is also what
        ``compute_dedup_key`` uses to disambiguate two different packages that
        would otherwise both hash to the same "port=None" identity (Fase 0.9).
        Mirrors the same fallback in ``engine.py``'s finding builders.
        """
        return {
            "title":        title,
            "category":     "surface_change",
            "port":         service.port,
            "service":      service.name or service.product or None,
            "protocol":     service.protocol,
            "source":       "lybra",
            "check_id":     "lybra:surface-change@1",
            "feed_version": "lybra-surface-1",
            "qod":          QOD_OPEN_PORT,
            "confirmed":    True,
            "state":        "open",
        }

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
        source: "ServiceSource",
        services: list[Service]
    ) -> list:
        """Fire off Nmap/Nikto/Nuclei as independent corroborator scans (Fase 6).

        Necessarily non-blocking: Nmap and Nikto against a real network target
        are not instantaneous either, so this cannot be awaited inside this
        job. Each corroborator becomes an ordinary, independently-tracked
        ``Scan`` — visible, cancellable and pollable exactly like a
        user-launched one. The returned ids are stored on the Lybra scan so
        ``format_scan`` can later merge in whichever corroborator ``Finding``
        rows are ready.

        - Nmap only when ``source.launches_nmap_corroborator`` — a fresh Nmap
          run is redundant when Lybra already has Nmap-sourced ports for this
          scan (the Nmap-source mode is the only one that says no).
        - Nikto and Nuclei only if at least one HTTP-like service was found —
          both are HTTP-only tools (Fase U2: Nuclei gains the exact same
          condition that already gates Nikto, now that U1 gives it a
          ``run_scan`` of its own).

        Best-effort per corroborator: a launch failure for one does not affect
        the others or the Lybra scan itself.

        OpenVAS **used to** launch here unconditionally — the only automatic
        invocation of it anywhere in the pipeline, and the reason a deep
        analysis could quietly cost up to four hours. Removed in E0 of the
        OpenVAS teardown (roadmap §7/§6.3, Ronda 0): with Fase U closed,
        Nmap + Nikto + Nuclei is the corroborator pool the roadmap targets.
        """
        ids: list = []

        if source.launches_nmap_corroborator:
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
                ids.append(NucleiScanManager().run_scan(target=target, user_id=user_id))
            except Exception:
                logger.exception("Análisis profundo: fallo al lanzar Nuclei corroborador para %s", target)

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
        programed_scan_id: Optional[int] = None, asset_id: Optional[int] = None,
    ) -> LybraScan:  # pylint: disable=arguments-differ
        """Create and persist an LybraScan row linked to its source Nmap scan."""
        scan = LybraScan(
            target=target,
            user_id=user_id,
            started_at=utcnow_naive(),
            source_scan_id=source_scan_id,
            programed_scan_id=programed_scan_id,
            asset_id=asset_id,
        )
        with UnitOfWork() as uow:
            ScanRepository(uow).save(scan)
        return scan

    def _persist_scan_results(self, uow, scan, domain_data) -> None:
        """Persist the engine's findings (``domain_data`` is a list of dicts)."""
        ScanRepository(uow).persist_findings(scan, domain_data)

    def get_scans_paginated(  # pylint: disable=arguments-differ
        self, user_id: int, page: int = 1, per_page: int = 10,
        asset_id=ScanRepository.PANEL_SCANS,
    ):
        """Paginated Lybra scans, split by origin (Fase I).

        Overrides the base implementation, which filters by ``scan_type``
        alone, so that the ordinary Lybra feed shows only what the user
        launched from the Themis panel. Scans produced from a Hygeia asset's
        software inventory are browsed per-agent instead — mixing them into
        the same list would bury the handful of scans a user actually asked
        for under one per agent per re-analysis.

        Args:
            asset_id: ``ScanRepository.PANEL_SCANS`` (default) for panel-launched
                scans, an ``int`` for one asset's scans, or ``None`` for all.
        """
        repo = build_repository(ScanRepository)
        items, total_count = repo.get_lybra_scans_paginated(user_id, page, per_page, asset_id)
        return [self.format_scan(item.id, _scan=item) for item in items], total_count

    def delete_scans_for_asset(self, asset_id: int) -> int:
        """Delete every Lybra scan produced from a Hygeia asset's inventory.

        The explicit cleanup that ``LybraScan.asset_id`` needs for lack of a
        ``ForeignKey`` cascade (see the model). Goes through ``delete_scan``
        per scan so each one's generated PDFs are removed from disk too.

        This is the Themis-side entry point Hygeia calls when an asset is
        deleted; Themis itself never invokes it.

        Returns:
            How many scans were deleted.
        """
        scan_ids = build_repository(ScanRepository).get_lybra_scan_ids_for_asset(asset_id)
        deleted = sum(1 for scan_id in scan_ids if self.delete_scan(scan_id))
        if deleted:
            logger.info(f"Eliminados {deleted} escaneos Lybra del activo Hygeia {asset_id}")
        return deleted

    @staticmethod
    def exposure_for(scan) -> str:
        """Contextual exposure of a Lybra scan, for Fase 5's priority scoring.

        Normally that is just ``classify_exposure(target)``. An inventory scan
        (Fase I) is the exception: it never observed the target's network at
        all, so its "target" is a Hygeia asset's bare hostname, not a reachable
        surface. ``classify_exposure`` recognises internal *suffixes*
        (``.local``, ``.lan``...) but not a bare ``DESKTOP-ABC``, so it would
        call such a host "public" and push every finding up one severity band
        on the strength of a naming artefact. Reporting these as private is
        both safer and more honest: an installed package says nothing about
        what the host exposes — that remains Themis's territory, not Hygeia's.

        Lives here rather than in ``correlation.py`` because it needs the scan
        row, and that module is deliberately ORM-free (pure functions over
        plain values).
        """
        if getattr(scan, "asset_id", None):
            return "private"
        return classify_exposure(scan.target)

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

        exposure = self.exposure_for(scan)
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
            "assetId": scan.asset_id,
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
                    "cpeResolved": f.get("cpe_resolved"),
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

