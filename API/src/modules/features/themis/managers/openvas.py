"""OpenVASScanManager — extraido de themis/managers.py (Fase 3 del refactor de estructura)."""

import logging
import uuid
from typing import Callable, Optional
import src.modules.system.config_reading as CR
from src.modules.system.taskqueue import job_context
from src.modules.infrastructure import UnitOfWork
from src.modules.shared import isoformat_utc
from ..repositories import ScanRepository
from ..model import (
    OpenVASScan,
    Scan,
    ScanType,
)
from ..lybra import (
    compute_dedup_key,
    openvas_result_to_finding,
)
from ..services import (
    OpenVASResultProcessor,
    OpenVASPrintingStrategy,
    OpenVASTask,
    _Task,
)
from ..exceptions import ScanNotFoundError

from .scan import ScanManager


logger = logging.getLogger(__name__)


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

