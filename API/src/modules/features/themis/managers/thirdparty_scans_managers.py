"""NmapScanManager, NiktoScanManager, OpenVASScanManager — herramientas de terceros
(extraidas de themis/managers.py, Fase 3 del refactor de estructura; unificadas
en un solo fichero porque cada una es pequeña y comparten la misma forma)."""

import logging
import uuid
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
    OpenVASScan,
    NucleiScan,
    Scan,
    ScanType,
)
from ..lybra import (
    compute_dedup_key,
    nikto_incident_to_finding,
    openvas_result_to_finding,
    nuclei_result_to_finding,
    merge_findings,
    apply_lifecycle,
    classify_exposure,
    score_finding,
)
from ..services import (
    NmapResultProcessor,
    NmapPrintingStrategy,
    NiktoResultProcessor,
    NiktoPrintingStrategy,
    OpenVASResultProcessor,
    OpenVASPrintingStrategy,
    OpenVASTask,
    NucleiResultProcessor,
    NucleiPrintingStrategy,
    _Task,
)
from ..exceptions import ScanNotFoundError, TargetNotAuthorizedError

from .scan import ScanManager


logger = logging.getLogger(__name__)


@ScanManager.register(ScanType.NMAP)
class NmapScanManager(ScanManager):
    SCAN_TYPE = ScanType.NMAP
    _MODEL = NmapScan
    _strategy_class = NmapPrintingStrategy
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

    def _create_scan_record(self, target: str, user_id: int, programed_scan_id: Optional[int] = None) -> NmapScan: # pylint: disable=arguments-differ
        """Create and persist an NmapScan row."""
        scan = NmapScan(target=target, user_id=user_id, started_at=utcnow_naive(), programed_scan_id=programed_scan_id)
        with UnitOfWork() as uow:
            ScanRepository(uow).save(scan)
            # Durable antes de encolar: el worker corre en otro proceso.
            uow.commit_for_handoff()
        return scan

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
    _strategy_class = NiktoPrintingStrategy
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

    def _create_scan_record(self, target: str, user_id: int, programed_scan_id: Optional[int] = None) -> NiktoScan: # pylint: disable=arguments-differ
        """Create and persist a NiktoScan row."""
        scan = NiktoScan(target=target, user_id=user_id, started_at=utcnow_naive(), programed_scan_id=programed_scan_id)
        with UnitOfWork() as uow:
            ScanRepository(uow).save(scan)
            # Durable antes de encolar: el worker corre en otro proceso.
            uow.commit_for_handoff()
        return scan

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
        # against Lybra/OpenVAS findings on the same host. Does not replace
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


@ScanManager.register(ScanType.OPENVAS)
class OpenVASScanManager(ScanManager):
    """
    Manager for OpenVAS vulnerability scans.

    Reads OpenVAS connection parameters from the configuration module on init.

    Class Attributes:
        SCAN_CONFIGS: Known scan configuration UUIDs.
        PORT_LISTS:   Known port list UUIDs.

    Example:
    >>> manager = OpenVASScanManager(user)
    ... scan_id = manager.run_scan(target="192.168.1.1")
    """

    # A8: propiedades en vez de atributos de clase — los bloques de config ya
    # vienen cacheados, así que leerlos en el punto de uso es igual de barato
    # pero recoge los cambios aplicados vía PUT /system sin reiniciar el proceso
    # (antes solo se leían una vez, al importar la clase).
    @property
    def SCAN_CONFIGS(self) -> dict:
        return CR.openvas_tool_configs().scan_configs

    @property
    def PORT_LISTS(self) -> dict:
        return CR.openvas_tool_configs().port_list

    SCAN_TYPE = ScanType.OPENVAS
    _MODEL = OpenVASScan
    _strategy_class = OpenVASPrintingStrategy
    _RICH_LOADER = "get_openvas_rich"

    def __init__(self) -> None:
        super().__init__()

        config = CR.get_openvas_environment()
        self.hostname  = config["hostname"]
        self.port      = config["port"]
        self.username  = config["username"]
        self.password  = config["password"]

        self.result_processor = OpenVASResultProcessor()

    def run_scan(               # pylint: disable=arguments-differ
        self,
        target: str,
        user_id: int,
        scan_config: str = "full_fast",
        skip_normalize: bool = False,
        programed_scan_id: Optional[int] = None,
    ) -> int:
        """
        Start an OpenVAS scan in a background thread.

        Args:
            target:         Target IP address or hostname.
            scan_config:    Scan configuration key (default: 'full_fast').
            skip_normalize: Skip target normalization if True.

        Returns:
            Primary key of the created OpenVASScan record.
        """
        try:
            if not skip_normalize:
                # OpenVAS solo admite un host por escaneo: resolver aquí (en vez
                # de confiar en el caller) cierra el hueco por el que el flujo
                # programado lanzaba un target sin validar (multi-host o IP
                # privada) — el endpoint HTTP ya validaba, este manager no.
                from src.modules.shared import normalize_target
                target, _ = normalize_target(target)
                skip_normalize = True
            ScanManager.reject_private_ip(target)

            config_id = self.SCAN_CONFIGS.get(scan_config, self.SCAN_CONFIGS["full_fast"])
            scan      = self._create_scan_record(
                target=target,
                user_id=user_id,
                programed_scan_id=programed_scan_id,
            )
            scan_id   = scan.id

            self._tq.submit(
                func=OpenVASScanManager.execute_openvas_scan,
                args=(scan_id, target, config_id, skip_normalize),
                name=f"OpenVASScan-{scan_id}",
                category=self.TASK_CATEGORY,
                external_id=self.external_id_for(scan_id),
                timeout=CR.openvas_config().timeout,
            )

            logger.info(f"Escaneo OpenVAS {scan_id} iniciado")
            return scan_id # type: ignore

        except (OSError, RuntimeError) as e:
            logger.error(f"Error iniciando escaneo OpenVAS: {e}", exc_info=True)
            raise

    @staticmethod
    def execute_openvas_scan(scan_id: int, target: str, scan_config_id: str, skip_normalize: bool) -> None:
        """Entry point submitted to the TaskQueue. Executes the OpenVAS scan with progress and cancellation support."""
        with job_context() as job:
            from src.modules.features.themis.services.tasks import OpenVASTask

            manager = OpenVASScanManager()
            task = OpenVASTask(
                target=target,
                hostname=manager.hostname,
                port=manager.port,
                username=manager.username,
                password=manager.password,
                scan_config=scan_config_id,
                progress_callback=job.progress,
            )
            manager._execute_scan(scan_id, task, skip_normalize, cancel_check=job.cancelled)

    def _create_scan_record(self, target: str, user_id: int, programed_scan_id: Optional[int] = None) -> OpenVASScan: # pylint: disable=arguments-differ
        """Create and persist an OpenVASScan row with placeholder task/report IDs."""
        placeholder = f"PENDING_{uuid.uuid4()}"
        scan = OpenVASScan(
            target    = target,
            user_id   = user_id,
            task_id   = placeholder,
            report_id = placeholder,
            programed_scan_id = programed_scan_id,
        )
        with UnitOfWork() as uow:
            ScanRepository(uow).save(scan)
            # Durable antes de encolar: el worker corre en otro proceso.
            uow.commit_for_handoff()
        return scan

    def _execute_scan(
        self,
        scan_id: int,
        task: OpenVASTask,
        skip_normalize: bool = False,
        cancel_check: Optional[Callable[[], bool]] = None,
    ) -> None:
        """
        Override: after the base execution, persist the OpenVAS task/report IDs.

        Args:
            scan_id:        Primary key of the scan.
            task:           OpenVASTask instance.
            skip_normalize: Skip IP normalization if True.
            cancel_check:   Optional callable returning True to cancel the scan.
        """
        from src.modules.shared._endpoints import normalize_target
        if not skip_normalize:
            target_ip, _ = normalize_target(task.target)
            task.target  = target_ip # type: ignore

        super()._execute_scan(scan_id, task, skip_normalize, cancel_check)

        if task.task_id:
            try:
                with UnitOfWork() as uow:
                    scan = ScanRepository(uow).get_by_id(scan_id)
                    if scan:
                        scan.task_id   = task.task_id
                        scan.report_id = task.report_id
            except (OSError, RuntimeError) as e:
                logger.error(
                    f"Error actualizando task_id/report_id para escaneo {scan_id}: {e}",
                    exc_info=True
                )

    def _persist_scan_results(self, uow, scan, domain_data) -> None:
        """Persist OpenVAS vulnerabilities, hosts, and scan results."""
        vulnerabilities_data, scan_results_data, _ = domain_data
        scan_repo = ScanRepository(uow)

        vulnerability_map = {}
        for vuln_data in vulnerabilities_data:
            vuln = scan_repo.get_or_create_vulnerability(vuln_data)
            vulnerability_map[vuln.nvt_oid] = vuln

        scan_repo.persist_openvas_results(scan, scan_results_data, vulnerability_map)

        # Additive: also record each result as a normalized Finding (see
        # lybra/adapters.py). Does not replace the OpenVASScanResult write
        # above — the PDF report and history charts still read that.
        host_cache: dict = {}
        findings = []
        for result_data in scan_results_data:
            vuln = vulnerability_map.get(result_data["nvt_oid"])
            if vuln is None:
                continue
            host_ip = result_data["host_ip"]
            if host_ip not in host_cache:
                host_cache[host_ip] = scan_repo.get_or_create_host(hostname=host_ip, ip_address=host_ip)
            finding = openvas_result_to_finding(vuln, result_data)
            finding["host_id"] = host_cache[host_ip].id
            finding["dedup_key"] = compute_dedup_key(finding)
            findings.append(finding)
        scan_repo.persist_findings(scan, findings)

    def format_scan(self, scan_id: int, _scan=None) -> dict:
        scan = _scan or self.get_scan_by_id(scan_id)
        if not scan:
            raise ScanNotFoundError(scan_id)

        result = {
            "id": scan.id,
            "scanType": "openvas",
            "target": scan.target,
            "taskId": scan.task_id,
            "reportId": scan.report_id,
            "status": getattr(scan, "status", "unknown"),
            "startedAt": isoformat_utc(scan.started_at),
            "finishedAt": isoformat_utc(scan.finished_at), # type: ignore
            "vulnerabilities": [
                {
                    "nvtOid": r.vulnerability.nvt_oid,
                    "name": r.vulnerability.name,
                    "severityScore": r.vulnerability.severity_score,
                    "severityClass": r.vulnerability.severity_class,
                    "cvssBaseScore": r.vulnerability.cvss_base_score,
                    "cvssVector": r.vulnerability.cvss_vector,
                    "cveIds": r.vulnerability.cve_ids,
                    "description": r.vulnerability.description,
                    "solution": r.vulnerability.solution,
                    "solutionType": r.vulnerability.solution_type,
                    "affectedSoftware": r.vulnerability.affected_software,
                    "hostIp": r.host.ip_address if r.host else None,
                    "hostName": r.host.hostname if r.host else None,
                }
                for r in scan.results
            ],
            "totalVulnerabilities": len(scan.results),
            "criticalCount": sum(1 for r in scan.results if r.vulnerability.severity_class == "Critical"),
            "highCount": sum(1 for r in scan.results if r.vulnerability.severity_class == "High"),
            "severityBreakdown": {
                "critical": sum(1 for r in scan.results if r.vulnerability.severity_class == "Critical"),
                "high": sum(1 for r in scan.results if r.vulnerability.severity_class == "High"),
                "medium": sum(1 for r in scan.results if r.vulnerability.severity_class == "Medium"),
                "low": sum(1 for r in scan.results if r.vulnerability.severity_class == "Low"),
                "info": sum(1 for r in scan.results if r.vulnerability.severity_class == "Log"),
            },
        }
        self._append_document_info(scan, result)
        return result

    def append_csv_data(self, data: dict, scan: Scan, task: "_Task") -> None:
        data["scan_config"] = getattr(scan, "scan_config_name", "")
        data["skip_normalize"] = getattr(scan, "skip_normalize", False)


@ScanManager.register(ScanType.NUCLEI)
class NucleiScanManager(ScanManager):
    """
    Manager for Nuclei template-based vulnerability scans (roadmap Fase U1).

    Unlike Nikto/OpenVAS, Nuclei writes no result table of its own — every
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
    _strategy_class = NucleiPrintingStrategy
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

    def _create_scan_record(self, target: str, user_id: int, programed_scan_id: Optional[int] = None) -> NucleiScan:  # pylint: disable=arguments-differ
        """Create and persist a NucleiScan row."""
        scan = NucleiScan(target=target, user_id=user_id, started_at=utcnow_naive(), programed_scan_id=programed_scan_id)
        with UnitOfWork() as uow:
            ScanRepository(uow).save(scan)
            # Durable antes de encolar: el worker corre en otro proceso.
            uow.commit_for_handoff()
        return scan

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
        real value is available. Mirrors how ``OpenVASScanManager`` patches
        ``task_id``/``report_id`` onto the scan row post-hoc, for the same
        structural reason.
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

    @staticmethod
    def _previous_findings_map(scan_repo: ScanRepository, user_id: int, target: str, exclude_scan_id: int) -> dict:
        """Build ``dedup_key -> {state, snapshot}`` from the previous Nuclei
        scan of this target, for lifecycle comparison. Mirrors
        ``LybraEngineManager._previous_findings_map`` — same shape, own scan
        type."""
        if not user_id or not target:
            return {}
        result: dict = {}
        for pf in scan_repo.get_previous_findings(user_id, target, ScanType.NUCLEI.value, exclude_scan_id):
            snapshot = pf.snapshot
            key = pf.dedup_key or compute_dedup_key(snapshot)
            snapshot["dedup_key"] = key
            result[key] = {"state": pf.state or "open", "snapshot": snapshot}
        return result

    def format_scan(self, scan_id: int, _scan=None) -> dict:
        scan = _scan or self.get_scan_by_id(scan_id)
        if not scan:
            raise ScanNotFoundError(scan_id)

        repo = build_repository(ScanRepository)
        exposure = classify_exposure(scan.target)

        def _priority(f: dict) -> str:
            return score_finding(
                {"cvss_score": f.get("cvss_score"), "in_kev": f.get("in_kev"),
                 "epss_score": f.get("epss_score"), "confirmed": f.get("confirmed")},
                exposure,
            )

        findings = []
        for f in repo.get_findings_by_scan(scan_id):
            d = f.snapshot
            d["id"] = f.id
            d["state"] = f.state
            d["priority"] = _priority(d)
            findings.append(d)

        result = {
            "id": scan.id,
            "scanType": "nuclei",
            "target": scan.target,
            "exposure": exposure,
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
                    "priority": f.get("priority"),
                }
                for f in findings
            ],
            "totalFindings": len(findings),
            "criticalCount": sum(1 for f in findings if f.get("priority") == "CRITICAL"),
            "highCount": sum(1 for f in findings if f.get("priority") == "HIGH"),
            "confirmedFindings": sum(1 for f in findings if f.get("confirmed")),
        }
        self._append_document_info(scan, result)
        return result

    def append_csv_data(self, data: dict, scan: Scan, task: "_Task") -> None:
        data["target"] = scan.target
        data["severities"] = ",".join(getattr(task, "severities", None) or [])
        data["tags"] = ",".join(getattr(task, "tags", None) or [])
        data["rate_limit"] = getattr(task, "rate_limit", "")
        data["timeout_sec"] = task.timeout
