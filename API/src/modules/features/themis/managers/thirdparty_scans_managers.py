"""NmapScanManager, NiktoScanManager, OpenVASScanManager — herramientas de terceros
(extraidas de themis/managers.py, Fase 3 del refactor de estructura; unificadas
en un solo fichero porque cada una es pequeña y comparten la misma forma)."""

import logging
import uuid
from typing import Callable, Optional
import src.modules.system.config_reading as CR
from src.modules.system.taskqueue import job_context
from src.modules.infrastructure import UnitOfWork
from src.modules.shared import utcnow_naive, isoformat_utc
from ..repositories import ScanRepository
from ..model import (
    NmapScan,
    NiktoScan,
    OpenVASScan,
    Scan,
    ScanType,
)
from ..lybra import (
    compute_dedup_key,
    nikto_incident_to_finding,
    openvas_result_to_finding,
)
from ..services import (
    NmapResultProcessor,
    NmapPrintingStrategy,
    NiktoResultProcessor,
    NiktoPrintingStrategy,
    OpenVASResultProcessor,
    OpenVASPrintingStrategy,
    OpenVASTask,
    _Task,
)
from ..exceptions import ScanNotFoundError

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

    # A8: propiedades en vez de atributos de clase — CR.get_openvas_*() ya
    # cachea con @_lazy_load, así que leerlas en el punto de uso es igual de
    # barato pero recoge cambios de config aplicados vía PUT /system sin
    # reiniciar el proceso (antes solo se leían una vez, al importar la clase).
    @property
    def SCAN_CONFIGS(self) -> dict:
        return CR.get_openvas_scan_configs()

    @property
    def PORT_LISTS(self) -> dict:
        return CR.get_openvas_port_list()

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
                timeout=CR.get_openvas_task_timeout(),
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
