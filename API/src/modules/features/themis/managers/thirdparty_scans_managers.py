"""NmapScanManager, NiktoScanManager — herramientas de terceros
(extraidas de themis/managers.py, Fase 3 del refactor de estructura; unificadas
en un solo fichero porque cada una es pequeña y comparten la misma forma)."""

import logging
from typing import Callable, Optional
import src.modules.system.config_reading as CR
from src.modules.system.taskqueue import job_context
from src.modules.infrastructure import UnitOfWork
from src.modules.infrastructure.session import build_repository
from src.modules.shared import utcnow_naive, isoformat_utc
from ..repositories import ScanRepository
from ..model import (
    NmapScan,
    NiktoScan,
    NucleiScan,
    Scan,
    ScanType,
)
from ..lybra import (
    compute_dedup_key,
    nikto_incident_to_finding,
    nuclei_result_to_finding,
    finding_to_json,
    merge_findings,
    apply_lifecycle,
    classify_exposure,
)
from ..services import (
    NmapResultProcessor,
    NiktoResultProcessor,
    NucleiResultProcessor,
    _Task,
)
from ..exceptions import ScanNotFoundError, TargetNotAuthorizedError

from .scan import ScanManager


logger = logging.getLogger(__name__)


@ScanManager.register(ScanType.NMAP)
class NmapScanManager(ScanManager):
    SCAN_TYPE = ScanType.NMAP
    _MODEL = NmapScan
    _RICH_LOADER = "get_nmap_rich"

    """
    Manager for Nmap network security scans.

    Handles Nmap scan execution, result processing, and async PDF generation.

    Example:
    >>> manager = NmapScanManager(user)
    >>> scan_id = manager.run_scan(target_host="192.168.1.1", target_ports="1-1000")
    """

    def __init__(self):
        super().__init__()
        self.result_processor = NmapResultProcessor()

    def run_scan(
            self,
            target_host: str,
            target_ports: str,
            user_id: int,
            timeout: int = 300,
            programed_scan_id: Optional[int] = None
    ) -> int:  # pylint: disable=arguments-differ
        """
        Start an Nmap scan in a background thread.

        Args:
            target_host:  Target IP address or hostname.
            target_ports: Port range to scan (e.g., "1-1000").
            timeout:      Maximum scan duration in seconds.

        Returns:
            Primary key of the created NmapScan record.
        """
        try:
            # Rechazo de IP privada aquí (no solo en el endpoint HTTP): el
            # flujo programado (scheduling._run_nmap_scan) llama a run_scan()
            # directo, sin pasar por validate_targets() — mismo hueco que C3
            # (OpenVAS), mismo patrón de cierre.
            ScanManager.reject_private_ip(target_host)

            scan    = self._create_scan_record(
                target=target_host,
                user_id=user_id,
                programed_scan_id=programed_scan_id,
            )
            scan_id = scan.id

            self._tq.submit(
                func=NmapScanManager.execute_nmap_scan,
                args=(scan_id, target_host, target_ports, timeout),
                name=f"NmapScan-{scan_id}",
                category=self.TASK_CATEGORY,
                external_id=self.external_id_for(scan_id),
                timeout=timeout + self._scan_timeout_margin,
            )

            logger.info(f"Escaneo Nmap {scan_id} iniciado")
            return scan_id

        except (OSError, RuntimeError) as e:
            logger.error(f"Error iniciando escaneo Nmap: {e}", exc_info=True)
            raise

    @staticmethod
    def execute_nmap_scan(scan_id: int, target_host: str, target_ports: str, timeout: int) -> None:
        """Entry point submitted to the TaskQueue. Executes the Nmap scan with progress and cancellation support."""
        with job_context() as job:
            from src.modules.features.themis.services.tasks import NmapScanTask

            task = NmapScanTask(
                target_host=target_host,
                target_ports=target_ports,
                timeout=timeout,
                progress_callback=job.progress,
            )
            NmapScanManager()._execute_scan(scan_id, task, cancel_check=job.cancelled)

    # _create_scan_record: NmapScan no necesita columnas extra — usa el
    # default de ScanManager (A4).

    def _process_results(self, processor, results, target: str):
        """Nmap's processor also needs ``target`` to resolve the scanned host
        (B2) — every other scan type's processor only needs ``results``,
        which is what ``ScanManager._process_results`` gives it."""
        return processor.process(results, target)

    def _persist_scan_results(self, uow, scan, domain_data) -> None:
        """Persist Nmap host and port data into the database."""
        host_data, ports_data = domain_data
        scan_repo = ScanRepository(uow)
        host = scan_repo.get_or_create_host(
            hostname    = host_data["hostname"],
            ip_address  = host_data["ip_address"],
            mac_address = host_data["mac_address"],
            vendor      = host_data["vendor"],
        )
        scan_repo.persist_nmap_results(scan, host, ports_data)

    def format_scan(self, scan_id: int, _scan=None) -> dict:
        scan = _scan or self.get_scan_by_id(scan_id)
        if not scan:
            raise ScanNotFoundError(scan_id)

        result = {
            "id": scan.id,
            "scanType": "nmap",
            "target": scan.target,
            "status": getattr(scan, "status", "unknown"),
            "startedAt": isoformat_utc(scan.started_at),
            "finishedAt": isoformat_utc(scan.finished_at), # type: ignore
            "openPorts": [
                {
                    "port": f"{p.port_id}/{p.port.protocol}",
                    "reason": p.reason,
                    "product": p.product,
                    "version": p.version,
                }
                for p in scan.open_ports_relation
            ],
            "totalOpenPorts": len(scan.open_ports_relation),
        }
        self._append_document_info(scan, result)
        return result

    def append_csv_data(self, data: dict, scan: Scan, task: "_Task") -> None:
        data["target_host"] = scan.target
        data["target_ports"] = getattr(task, "target_ports", "")
        data["timeout_sec"] = task.timeout


@ScanManager.register(ScanType.NIKTO)
class NiktoScanManager(ScanManager):
    SCAN_TYPE = ScanType.NIKTO
    _MODEL = NiktoScan
    _RICH_LOADER = "get_nikto_rich"

    """
    Manager for Nikto web vulnerability scans.

    Example:
    >>> manager = NiktoScanManager(user)
    >>> scan_id = manager.run_scan(target_domain="example.com")
    """

    def __init__(self):
        super().__init__()
        self.result_processor = NiktoResultProcessor()

    def run_scan(self, target_domain: str, user_id: int, timeout: int = 6000, programed_scan_id: Optional[int] = None) -> int:  # pylint: disable=arguments-differ
        """
        Start a Nikto scan in a background thread.

        Args:
            target_domain: Target domain or hostname.
            timeout:       Maximum scan duration in seconds.

        Returns:
            Primary key of the created NiktoScan record.
        """
        try:
            # Rechazo de IP privada aquí (no solo en el endpoint HTTP, ver
            # validate_web_target): el flujo programado
            # (scheduling._run_nikto_scan) llama a run_scan() directo — mismo
            # hueco que C3 (OpenVAS), mismo patrón de cierre. Nikto escanea
            # por hostname/URL, así que hay que resolver antes de rechazar.
            from src.modules.shared import normalize_target
            resolved_ip, _ = normalize_target(target_domain)
            ScanManager.reject_private_ip(resolved_ip)

            scan = self._create_scan_record(
                target=target_domain,
                user_id=user_id,
                programed_scan_id=programed_scan_id,
            )
            scan_id = scan.id

            self._tq.submit(
                func=NiktoScanManager.execute_nikto_scan,
                args=(scan_id, target_domain, timeout),
                name=f"NiktoScan-{scan_id}",
                category=self.TASK_CATEGORY,
                external_id=self.external_id_for(scan_id),
                timeout=timeout + self._scan_timeout_margin,
            )

            logger.info(f"Escaneo Nikto {scan_id} iniciado")
            return scan_id # type: ignore

        except (OSError, RuntimeError) as e:
            logger.error(f"Error iniciando escaneo Nikto: {e}", exc_info=True)
            raise

    @staticmethod
    def execute_nikto_scan(scan_id: int, target_domain: str, timeout: int) -> None:
        """Entry point submitted to the TaskQueue. Executes the Nikto scan with progress and cancellation support."""
        with job_context() as job:
            from src.modules.features.themis.services.tasks import NiktoScanTask

            task = NiktoScanTask(
                target_domain=target_domain,
                timeout=timeout,
                progress_callback=job.progress,
            )
            NiktoScanManager()._execute_scan(scan_id, task, cancel_check=job.cancelled)

    # _create_scan_record: NiktoScan no necesita columnas extra — usa el
    # default de ScanManager (A4).

    def _persist_scan_results(self, uow, scan, domain_data) -> None:
        """Persist Nikto incidents and associate a host."""
        incidents_data = domain_data
        scan_repo = ScanRepository(uow)

        from src.modules.shared._endpoints import normalize_target
        ip, host = normalize_target(scan.target, resolve_hostname=True)
        host = scan_repo.get_or_create_host(
            hostname   = host or ip or scan.target,
            ip_address = ip or scan.target,
        )

        scan_repo.persist_nikto_results(scan, host, incidents_data)

        # Additive: also record each incident as a normalized Finding, so a
        # future cross-scanner correlation pass (Fase 6) has something to fuse
        # against Lybra/Nuclei findings on the same host. Does not replace
        # the NiktoIncident write above — the PDF report and history charts
        # still read that (see lybra/adapters.py for why).
        findings = []
        for inc_data in incidents_data:
            finding = nikto_incident_to_finding(inc_data)
            finding["host_id"] = host.id
            finding["dedup_key"] = compute_dedup_key(finding)
            findings.append(finding)
        scan_repo.persist_findings(scan, findings)

    def format_scan(self, scan_id: int, _scan=None) -> dict:
        scan = _scan or self.get_scan_by_id(scan_id)
        if not scan:
            raise ScanNotFoundError(scan_id)

        result = {
            "id": scan.id,
            "scanType": "nikto",
            "target": scan.target,
            "status": getattr(scan, "status", "unknown"),
            "startedAt": isoformat_utc(scan.started_at),
            "finishedAt": isoformat_utc(scan.finished_at), # type: ignore
            "incidents": [
                {
                    "osvdbId": i.osvdb_id,
                    "method": i.method,
                    "url": i.url,
                    "description": i.description,
                    "severity": getattr(i, "severity", "UNKNOWN"),
                    "discoveredAt": isoformat_utc(i.discovered_at),
                }
                for i in scan.incidents
            ],
            "totalIncidents": len(scan.incidents),
        }
        self._append_document_info(scan, result)
        return result

    def append_csv_data(self, data: dict, scan: Scan, task: "_Task") -> None:
        data["target_domain"] = scan.target
        data["timeout_sec"] = getattr(scan, "timeout", task.timeout) if hasattr(scan, "timeout") else task.timeout


@ScanManager.register(ScanType.NUCLEI)
class NucleiScanManager(ScanManager):
    """
    Manager for Nuclei template-based vulnerability scans (roadmap Fase U1).

    Unlike Nikto, Nuclei writes no result table of its own — every
    hallazgo vive directamente en ``Finding`` vía ``nuclei_result_to_finding``,
    la misma forma que ``LybraEngineManager`` ya adoptó. Eso es lo que le deja
    entrar gratis en la deduplicación multifuente, el ciclo de vida
    ``open``/``fixed``/``regressed`` y el scoring contextual de la Fase 5.

    Example:
    >>> manager = NucleiScanManager()
    >>> scan_id = manager.run_scan(target="https://example.com", user_id=1)
    """
    SCAN_TYPE = ScanType.NUCLEI
    _MODEL = NucleiScan
    # _RICH_LOADER no se define: sin relaciones ORM propias que precargar,
    # igual que LybraScan (ver ScanManager._RICH_LOADER).

    def __init__(self) -> None:
        super().__init__()
        self.result_processor = NucleiResultProcessor()

    def run_scan(  # pylint: disable=arguments-differ
        self,
        target: str,
        user_id: int,
        severities: Optional[list] = None,
        tags: Optional[list] = None,
        rate_limit: Optional[int] = None,
        request_timeout: Optional[int] = None,
        timeout: Optional[int] = None,
        programed_scan_id: Optional[int] = None,
    ) -> int:
        """
        Start a Nuclei scan in a background thread.

        Args:
            target:          Target URL/host — se resuelve y se autoriza antes
                de llegar aquí (ver ``endpoints.start_nuclei_scan``).
            severities:      Perfil acotado de severidades (p. ej.
                ``["critical", "high", "medium"]``). Sin esto, Nuclei con el
                feed completo son miles de peticiones — no es un detalle de
                afinado, es la diferencia entre una herramienta usable y una
                que satura al objetivo en su primer uso.
            tags:            Tags de plantillas opcionales (p. ej. ``["cve"]``).
            rate_limit:      Peticiones/segundo máximas.
            request_timeout: Timeout por petición HTTP individual (segundos).
            timeout:         Timeout total del escaneo (segundos).

        Returns:
            Primary key of the created NucleiScan record.
        """
        try:
            # Rechazo de IP privada + gate de objetivos autorizados aquí (no
            # solo en el endpoint HTTP, ver validate_web_target y
            # start_nuclei_scan): el flujo programado
            # (scheduling._run_nuclei_scan) llama a run_scan() directo — mismo
            # hueco que C3 (OpenVAS), mismo patrón de cierre. Nuclei toca el
            # objetivo desde el día uno, así que además del rechazo de IP
            # privada exige estar en el registro de objetivos autorizados,
            # igual que hace el endpoint.
            from src.modules.shared import normalize_target
            from .authorized_target import AuthorizedTargetManager
            resolved_ip, _ = normalize_target(target)
            ScanManager.reject_private_ip(resolved_ip)
            if not AuthorizedTargetManager.is_authorized(user_id, resolved_ip):
                raise TargetNotAuthorizedError(target)

            resolved_timeout = int(timeout) if timeout is not None else int(CR.nuclei_config().timeout)
            scan = self._create_scan_record(
                target=target,
                user_id=user_id,
                programed_scan_id=programed_scan_id,
            )
            scan_id = scan.id

            self._tq.submit(
                func=NucleiScanManager.execute_nuclei_scan,
                args=(scan_id, target, severities, tags, rate_limit, request_timeout, resolved_timeout),
                name=f"NucleiScan-{scan_id}",
                category=self.TASK_CATEGORY,
                external_id=self.external_id_for(scan_id),
                timeout=resolved_timeout + self._scan_timeout_margin,
            )

            logger.info(f"Escaneo Nuclei {scan_id} iniciado")
            return scan_id

        except (OSError, RuntimeError) as e:
            logger.error(f"Error iniciando escaneo Nuclei: {e}", exc_info=True)
            raise

    @staticmethod
    def execute_nuclei_scan(
        scan_id: int, target: str,
        severities: Optional[list], tags: Optional[list],
        rate_limit: Optional[int], request_timeout: Optional[int],
        timeout: int,
    ) -> None:
        """Entry point submitted to the TaskQueue. Executes the Nuclei scan with progress and cancellation support."""
        with job_context() as job:
            from src.modules.features.themis.services.tasks import NucleiScanTask

            task = NucleiScanTask(
                target=target,
                severities=severities,
                tags=tags,
                rate_limit=rate_limit,
                request_timeout=request_timeout,
                timeout=timeout,
                progress_callback=job.progress,
            )
            NucleiScanManager()._execute_scan(scan_id, task, cancel_check=job.cancelled)

    # _create_scan_record: NucleiScan no necesita columnas extra — usa el
    # default de ScanManager (A4).

    def _execute_scan(
        self,
        scan_id: int,
        task,
        skip_normalize: bool = False,
        cancel_check: Optional[Callable[[], bool]] = None,
    ) -> None:
        """
        Override: after the base execution, patch every Finding's
        ``feed_version`` with the live templates version the binary reported.

        ``_persist_scan_results`` (called inside the base ``_execute_scan``,
        on a *different* manager instance — ``thread_manager =
        self.__class__()``) has no access to this ``task``, so findings are
        persisted first with the config-level fallback
        (``CR.nuclei_config().templates_version``) and corrected here once the
        real value is available — the same persist-now/patch-post-hoc shape
        any scanner uses when a value is only known after the subprocess has
        already produced its output.
        """
        super()._execute_scan(scan_id, task, skip_normalize, cancel_check)

        templates_version = getattr(task, "templates_version", None)
        if templates_version:
            try:
                with UnitOfWork() as uow:
                    ScanRepository(uow).set_feed_version_for_scan(
                        scan_id, f"nuclei-templates-{templates_version}"
                    )
            except (OSError, RuntimeError) as e:
                logger.error(
                    f"Error actualizando feed_version para escaneo Nuclei {scan_id}: {e}",
                    exc_info=True,
                )

    def _persist_scan_results(self, uow, scan, domain_data) -> None:
        """Persist Nuclei findings as normalized Finding rows.

        Three things happen beyond the raw adapter mapping: results sharing a
        template collapse via ``merge_findings`` (Nuclei repeats the same
        template once per ``matched-at``, so one exposed path found on three
        URLs of the same host would otherwise become three rows), and
        ``apply_lifecycle`` compares against this target's previous Nuclei
        scan so ``state`` is genuinely ``fixed``/``regressed``/``open`` instead
        of always ``open`` — the two things that make Nuclei "enter for free"
        into Fase 5's correlation, per the roadmap.
        """
        results_data = domain_data
        scan_repo = ScanRepository(uow)

        from src.modules.shared._endpoints import normalize_target
        ip, host = normalize_target(scan.target, resolve_hostname=True)
        host_row = scan_repo.get_or_create_host(
            hostname   = host or ip or scan.target,
            ip_address = ip or scan.target,
        )

        previous_map = self._previous_findings_map(scan_repo, scan.user_id, scan.target, scan.id)

        # Fallback usado hasta que _execute_scan lo corrija con la versión
        # real leída del binario (ver el override de arriba).
        default_feed_version = CR.nuclei_config().templates_version

        findings = []
        for result_data in results_data:
            finding = nuclei_result_to_finding(result_data, feed_version=default_feed_version)
            finding["host_id"] = host_row.id
            finding["dedup_key"] = compute_dedup_key(finding)
            findings.append(finding)

        findings = merge_findings(findings)
        findings = apply_lifecycle(findings, previous_map)

        scan_repo.persist_findings(scan, findings)

    # _previous_findings_map: usa el default de ScanManager (A6).

    def format_scan(self, scan_id: int, _scan=None) -> dict:
        scan = _scan or self.get_scan_by_id(scan_id)
        if not scan:
            raise ScanNotFoundError(scan_id)

        repo = build_repository(ScanRepository)
        exposure = classify_exposure(scan.target)

        findings = []
        for f in repo.get_findings_by_scan(scan_id):
            d = f.snapshot
            d["id"] = f.id
            d["state"] = f.state
            findings.append(d)

        json_findings = [finding_to_json(f, exposure) for f in findings]

        result = {
            "id": scan.id,
            "scanType": "nuclei",
            "target": scan.target,
            "exposure": exposure,
            "status": getattr(scan, "status", "unknown"),
            "startedAt": isoformat_utc(scan.started_at),
            "finishedAt": isoformat_utc(scan.finished_at),  # type: ignore
            "findings": json_findings,
            "totalFindings": len(json_findings),
            "criticalCount": sum(1 for f in json_findings if f.get("priority") == "CRITICAL"),
            "highCount": sum(1 for f in json_findings if f.get("priority") == "HIGH"),
            "confirmedFindings": sum(1 for f in json_findings if f.get("confirmed")),
        }
        self._append_document_info(scan, result)
        return result

    def append_csv_data(self, data: dict, scan: Scan, task: "_Task") -> None:
        data["target"] = scan.target
        data["severities"] = ",".join(getattr(task, "severities", None) or [])
        data["tags"] = ",".join(getattr(task, "tags", None) or [])
        data["rate_limit"] = getattr(task, "rate_limit", "")
        data["timeout_sec"] = task.timeout
