"""LybraEngineManager — extraido de themis/managers.py (Fase 3 del refactor de estructura)."""

import logging
from dataclasses import replace
from typing import List, Optional
import src.modules.system.config_reading as CR
from src.modules.accounts import LimitKey, QuotaManager
from src.modules.system.taskqueue import ITaskQueue, job_context
from src.modules.infrastructure import UnitOfWork
from src.modules.infrastructure.session import build_repository
from src.modules.shared import assert_owned, utcnow_naive, isoformat_utc
from ...repositories import (
    ScanRepository,
    KbRepository,
)
from ...model import (
    Finding,
    LybraScan,
    Scan,
    ScanStatus,
    ScanType,
)
from ...lybra import (
    LybraEngine,
    Service,
    compute_dedup_key,
    merge_findings,
    apply_lifecycle,
    classify_exposure,
    finding_to_json,
    QOD_OPEN_PORT,
    default_dissectors,
    DissectorResult,
    identify_unknown_service,
    HostRateLimiter,
    kb_feed_version,
    load_checks,
    CheckRuntime,
    HttpProbe,
    TlsProbe,
    NetworkProbe,
    default_script_plugins,
    scan_ports_sync,
    scan_udp_ports_sync,
)
from ...lybra.ingest import select_for_services, translate_all
from ...services import _Task
from ...services.nuclei_templates import NucleiTemplateStore
from ...exceptions import (
    ScanNotFoundError,
    FindingNotFoundError,
)

from ..scan import ScanManager
from ..authorized_target import AuthorizedTargetManager
from .sources import ServiceSource, DiscoveryProbes


logger = logging.getLogger(__name__)


@ScanManager.register(ScanType.LYBRA)
class LybraEngineManager(ScanManager):
    """
    Manager for Lybra's own vulnerability engine.

    Unlike the other scanners it launches no external subprocess: it discovers
    the target's services itself (Fase T) — or takes a services list the caller
    already resolved — and produces normalized :class:`Finding` rows through the
    :class:`LybraEngine`. Because that work is a fast, in-memory pass (no
    network), it does not go through the base ``_execute_scan`` (built for
    long-running subprocess tasks); the body lives in ``_run_lybra`` and the
    worker entry point ``execute_lybra_scan`` just wraps it in ``job_context``.

    Example:
    >>> manager = LybraEngineManager()
    >>> scan_id = manager.run_scan(target="scanme.nmap.org", user_id=1)
    """

    SCAN_TYPE = ScanType.LYBRA
    _MODEL = LybraScan
    SCHEDULED_REQUIRED_ARGS = ("target",)

    # Categories that are point-in-time events, not persistent vulnerability
    # state - excluded from lifecycle tracking (see Phase 2.5 in _run_lybra).
    _EVENT_CATEGORIES = {"fingerprint", "surface_change"}

    def __init__(self, task_queue: ITaskQueue | None = None) -> None:
        super().__init__(task_queue)

    @classmethod
    def scheduled_run_kwargs(cls, arguments: dict) -> dict:
        """target obligatorio + discover_ports opcional (B1). Un escaneo
        programado siempre es autodescubrimiento (Fase T) — nunca tiene un
        payload de services que programar.

        Un ``ProgramedScan`` creado antes de L52 puede llevar todavía una clave
        ``deep`` en su columna JSON ``arguments``; se ignora sin más, que es lo
        que hace este método con cualquier argumento que no reconozca."""
        kwargs = super().scheduled_run_kwargs(arguments)
        kwargs["discover_ports"] = arguments.get("discover_ports")
        return kwargs

    def run_scan(self,
        user_id: int,
        target: Optional[str] = None,  # pylint: disable=arguments-differ
        services: Optional[List[Service]] = None,
        discover_ports: Optional[list] = None,
        timeout: int = 120,
        programed_scan_id: Optional[int] = None,
        asset_id: Optional[int] = None,
    ) -> int:
        """
        Start an Lybra engine scan in one of two modes.

        - **External payload** (``services`` + ``target``): analyse a
          services list the caller already resolved — a Hygeia inventory
          adapter is the motivating case, but any in-process producer of a
          ``List[Service]`` qualifies. No network discovery, fingerprinting or
          active checks run in this mode by default (see ``_run_lybra``); it
          exists precisely for services data that came from *not* touching the
          target's network. ``target`` is still required — it is the host
          identity findings get attached to.
        - **Self-discovery** (``target``, optional ``discover_ports``): Lybra
          discovers the open ports itself with its own connect scan (Fase T).
          The caller validates the target (reject private, etc.).

        Args:
            programed_scan_id: Set when launched by the scheduler (Themis
                scheduled scans), same convention as the other scan managers.
            asset_id: Fase I — the Hygeia asset whose inventory produced
                ``services``. Recorded on the scan row for provenance and
                grouping; it is never an input to the analysis itself, which
                is why it does not travel in the TaskQueue args.

        Returns:
            Primary key of the created LybraScan record.
        """
        source = ServiceSource.build_for_args(services, discover_ports)
        scan_target = source.valid_scan_target(user_id, target)

        # La cuota se consume aquí y no en el endpoint: por este método pasan
        # también el flujo programado (scheduling.py llama a run_scan
        # directamente) y la puerta de Hygeia. Es la misma lección que dejó el
        # arreglo SSRF de los escáneres — lo que vive solo en el endpoint HTTP
        # se lo saltan los otros caminos.
        #
        # Y va después de resolver el objetivo, no antes: un objetivo inválido
        # no debe gastar cuota. Se cobra justo antes de crear el registro.
        QuotaManager().consume(user_id, LimitKey.THEMIS_LYBRA_SCANS)

        scan = self._create_scan_record(
            target=scan_target,
            user_id=user_id,
            programed_scan_id=programed_scan_id,
            asset_id=asset_id,
        )
        scan_id = scan.id

        self._task_queue.submit(
            func=LybraEngineManager.execute_lybra_scan, # type: ignore
            args=(scan_id, discover_ports, services),
            name=f"LybraScan-{scan_id}",
            category=self.TASK_CATEGORY, # type: ignore
            external_id=self.external_id_for(scan_id),
            timeout=timeout + self._scan_timeout_margin,
        )

        logger.info(f"Escaneo Lybra {scan_id} iniciado ({source.label})")
        return scan_id  # type: ignore

    @staticmethod
    def execute_lybra_scan(
        scan_id: int,
        discover_ports: Optional[list] = None,
        services: Optional[List[Service]] = None
    ) -> None:
        """Entry point submitted to the TaskQueue. Runs the engine in the worker."""
        with job_context():
            manager = LybraEngineManager()
            manager._run_lybra( # type: ignore
                scan_id,
                discover_ports,
                services,
            )

    def _run_lybra(
        self,
        scan_id: int,
        discover_ports: Optional[list] = None,
        services_payload: Optional[List[Service]] = None,
    ) -> None:
        """Resolve services (own discovery or a payload), detect, persist.

        This is the testable body of the scan (the ``execute_* seam → _run_*``
        pattern). Runs synchronously; safe to call directly in tests without a
        worker.
        """
        source = ServiceSource.build_for_args(services_payload, discover_ports)
        probes = DiscoveryProbes(
            is_host_reachable=self.is_host_reachable,
            discover_ports=self._discover_ports,
            discover_udp_ports=self._discover_udp_ports,
        )
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

                resolved = source.resolve_services(scan_repo, probes, source_target)
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
                    feed_version=kb_feed_version(kb_repo.knowledge_state()),
                )
                findings_data = engine.analyze(services)
                findings_data.extend(fingerprint_findings)
                findings_data.extend(surface_findings)

            if source.probes_target_network and source_target and is_target_authorized and CR.lybra_config().active_checks:
                findings_data.extend(self._run_active_checks(source_target, services))

            for finding in findings_data:
                finding["host_id"] = source_host_id
                finding["dedup_key"] = compute_dedup_key(finding)
            findings_data = merge_findings(findings_data)

            trackable = [finding for finding in findings_data if finding.get("category") not in self._EVENT_CATEGORIES]
            events = [finding for finding in findings_data if finding.get("category") in self._EVENT_CATEGORIES]
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

        Esa defensa estuvo puesta y sin poder dispararse: ``scan_ports_sync``
        sólo sabía devolver una lista, así que un objetivo que bloqueaba el
        barrido a mitad de camino llegaba aquí como ``[]`` —un informe
        tranquilizador sobre un host con servicios abiertos, y peor aún, un
        ciclo de vida que marcaba como corregidos los hallazgos anteriores—.
        Desde L48-c el transporte distingue "todo cerrado" de "no me han
        dejado mirar" y devuelve ``None`` en el segundo caso, que es lo que
        este método siempre esperó recibir.
        """
        try:
            discovered = scan_ports_sync(target, discover_ports)
        except Exception:
            logger.exception("Lybra port discovery failed for %s", target)
            return None
        if discovered is None:
            logger.error(
                "Descubrimiento bloqueado para %s: el host respondió al chequeo de "
                "alcanzabilidad y después ningún puerto contestó. El escaneo falla "
                "en vez de reportar un objetivo limpio.",
                target,
            )
        return discovered

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
        """Run Lybra's own HTTP/SSH/FTP dissectors and identify each service.

        Fase F. La identificación que sale de aquí **es** la identificación del
        servicio: alimenta el matcher de versiones (``LybraEngine._resolve_cpe``)
        y deja además un hallazgo informativo con lo que se leyó.

        Hasta L52 no era así. Un servicio que ya traía producto y versión de un
        escaneo Nmap previo era intocable — la lectura propia no podía
        sobrescribirlo, sólo emitir un veredicto de «concuerda / no concuerda
        con Nmap». Ese modo de arranque ya no existe, y con él se fue la
        subordinación: un motor cuyo propio análisis no puede prevalecer sobre
        el de otra herramienta no es independiente. La comparación con Nmap
        sigue siendo posible, pero como **medición**, desde el arnés de pruebas
        (``tests/oracle/_concordance.py``), no dentro del producto.

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

        cascade_config = CR.lybra_config()
        for service in services:
            dissector = next((dissector for dissector in dissectors if dissector.applies(service)), None)
            result = None
            if dissector is not None:
                try:
                    result = dissector.probe(target, service, rate_limiter)
                except Exception:
                    logger.debug("Fingerprinting failed for %s:%s", target, service.port, exc_info=True)
            elif (service.protocol or "tcp").lower() != "udp":
                # Ningún dissector reclama este servicio, que hasta L10 quería
                # decir "se acabó": la aplicabilidad se decide por nombre o por
                # número de puerto, y en el camino de autodescubrimiento el
                # nombre sale a su vez de una tabla de puertos. Un MySQL en el
                # 33060 o un SSH en el 2222 quedaban completamente ciegos.
                #
                # La cascada pregunta en vez de suponer (ver
                # ``fingerprinting/cascade.py``). Sólo TCP: leer un saludo
                # ofrecido no significa nada sobre un datagrama.
                try:
                    result = identify_unknown_service(
                        target, service, dissectors, rate_limiter,
                        banner_timeout=cascade_config.banner_timeout,
                        max_blind_probes=cascade_config.max_blind_probes,
                    )
                except Exception:
                    logger.debug("Cascade failed for %s:%s", target, service.port, exc_info=True)

            if result is None:
                updated.append(service)
                continue

            findings.append(self._fingerprint_finding(service, result))
            findings.extend(self._layer_findings(service, result))
            if result.product and result.version:
                service = replace(service, product=result.product, version=result.version)
            updated.append(service)

        return updated, findings

    @classmethod
    def _layer_findings(cls, service, result) -> list:
        """Un hallazgo informativo por cada capa de servidor adicional (L48-b).

        Un puerto HTTP no siempre lo atiende **un** programa: la topología más
        corriente que existe —un nginx de proxy inverso por delante de un
        Apache— son dos, y hasta ahora el motor sólo podía reportar uno. La
        medición real lo destapó: cinco servicios en tres hosts donde Lybra
        decía ``nginx`` y Nmap decía ``Apache httpd``, sin que ninguno de los
        dos estuviera equivocado.

        Reportar las dos capas es la respuesta honesta. Las dos están expuestas
        y las dos tienen CVEs; elegir una en silencio produce falsos negativos
        por un lado y falsos positivos por el otro.
        """
        return [
            cls._fingerprint_finding(
                service,
                DissectorResult(product, version, f"{result.label} {role}", qod=result.qod),
            )
            for product, version, role in getattr(result, "extra_layers", ())
        ]

    @staticmethod
    def _fingerprint_finding(service, result) -> dict:
        """Build an informational Finding stating what Lybra identified.

        Es una constatación, no un veredicto: dice qué vio el motor y con qué
        dissector. Antes de L52 el título comparaba la lectura propia con la de
        Nmap («concuerda / no concuerda con Nmap»), lo que convertía un dato
        propio en una nota al pie sobre otra herramienta.

        El ``qod`` lo pone el dissector (L18). Era una constante para todos, de
        modo que una versión leída de una cabecera ``Server`` explícita y otra
        deducida de una página de error valían lo mismo; ahora cada lectura
        dice cuánto se fía de sí misma. Sigue sin alimentar la confianza de
        ninguna vulnerabilidad — ver ``dispatch.QOD_FINGERPRINT``.
        """
        own = f"{result.product or '?'} {result.version or ''}".strip()
        title = f"Fingerprint propio ({result.label}): {own}"
        return {
            "title":        title,
            "category":     "fingerprint",
            "port":         service.port,
            "service":      service.name or None,
            "protocol":     service.protocol,
            "source":       "lybra",
            "check_id":     "lybra:fingerprint@1",
            "feed_version": "lybra-fingerprint-1",
            "qod":          result.qod,
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
            self._surface_key(service): service for service in scan_repo.get_host_services(host_id)
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

    # _previous_findings_map: usa el default de ScanManager (A6).

    @classmethod
    def _finding_view_dict(cls, finding: Finding) -> dict:
        view = finding.snapshot
        view["id"] = finding.id
        view["state"] = finding.state
        return view

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
            # El finding se busca por su propio id, pero la propiedad se
            # verifica sobre el scan al que pertenece (E5): FindingNotFoundError
            # se lanza con finding_id para no revelar el scan_id ajeno.
            assert_owned(ScanRepository, finding.scan_id, user_id,
                         lambda _scan_id: FindingNotFoundError(finding_id), uow=uow)
            finding.state = state  # type: ignore
            repo.update(finding)
            return finding

    def _create_scan_record(
        self, target: str, user_id: int,
        programed_scan_id: Optional[int] = None, asset_id: Optional[int] = None,
    ) -> LybraScan:  # pylint: disable=arguments-differ
        """Create and persist an LybraScan row.

        Delegates to ``ScanManager._create_scan_record`` (A4), passing
        LybraScan's extra columns via ``**extra``. Antes esta clase no
        llamaba ``uow.commit_for_handoff()`` como las demás — inconsistencia
        real, no deliberada: ``run_scan()`` encola en TaskQueue justo después
        (mismo patrón que Nmap/Nikto/Nuclei), así que el worker en otro
        proceso también necesita ver esta fila ya confirmada.
        """
        return super()._create_scan_record(
            target=target, user_id=user_id, programed_scan_id=programed_scan_id,
            asset_id=asset_id,
        )

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

    def latest_findings_by_asset(self, user_id: int, asset_ids: List[int]) -> dict:
        """Hallazgos del último análisis por activo Hygeia, en un par de queries.

        Es lo que la rejilla de agentes de Themis necesita para pintar el
        "N hallazgos" de cada tarjeta sin un request por activo: el
        ``totalFindings`` del último escaneo de inventario del activo, o
        ``None`` (ausente del dict) si nunca se analizó.

        Args:
            user_id:   Dueño de los escaneos.
            asset_ids: Activos cuyo último recuento se quiere.

        Returns:
            Dict ``{asset_id: count}`` solo con los activos que ya tienen
            algún análisis.
        """
        if not asset_ids:
            return {}
        repo = build_repository(ScanRepository)
        latest = repo.get_latest_scan_by_asset(user_id, asset_ids)
        counts = repo.count_findings_by_scan([scan.id for scan in latest])
        return {
            scan.asset_id: counts.get(scan.id, 0)
            for scan in latest
            if scan.asset_id is not None
        }

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
        # Todos los hallazgos de un escaneo Lybra son de Lybra: hasta L52 aquí
        # se fundían además los de los escaneos corroboradores (Nmap/Nikto/
        # Nuclei) que el "análisis profundo" lanzaba, bajo la firma de Lybra.
        display_findings = [self._finding_view_dict(finding) for finding in repo.get_findings_by_scan(scan_id)]

        exposure = self.exposure_for(scan)
        target_authorized = bool(
            scan.target and AuthorizedTargetManager.is_authorized(scan.user_id, scan.target)
        )

        json_findings = [finding_to_json(display_finding, exposure) for display_finding in display_findings]

        result = {
            "id": scan.id,
            "scanType": "lybra",
            "target": scan.target,
            "assetId": scan.asset_id,
            "exposure": exposure,
            "targetAuthorized": target_authorized,
            "status": getattr(scan, "status", "unknown"),
            "startedAt": isoformat_utc(scan.started_at),
            "finishedAt": isoformat_utc(scan.finished_at),  # type: ignore
            "findings": json_findings,
            "totalFindings": len(json_findings),
            "vulnerableFindings": sum(1 for display_finding in display_findings if display_finding.get("category") == "outdated_software"),
            "openFindings": sum(1 for display_finding in display_findings if display_finding.get("state") == "open"),
            "fixedFindings": sum(1 for display_finding in display_findings if display_finding.get("state") == "fixed"),
        }
        self._append_document_info(scan, result)
        return result

    def append_csv_data(self, data: dict, scan: Scan, task: "_Task") -> None:
        """No-op: Lybra does not use the base CSV-logging execution path."""
        pass

