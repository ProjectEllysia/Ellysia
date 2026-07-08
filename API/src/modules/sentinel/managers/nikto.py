"""NiktoScanManager — extraido de sentinel/managers.py (Fase 3 del refactor de estructura)."""

import logging
from typing import Optional
from src.modules.system.taskqueue import job_context
from src.modules.infrastructure import UnitOfWork
from src.modules.shared import utcnow_naive
from ..repositories import ScanRepository
from ..model import (
    NiktoScan,
    Scan,
    ScanType,
)
from ..lybra import (
    compute_dedup_key,
    nikto_incident_to_finding,
)
from ..services import (
    NiktoResultProcessor,
    NiktoPrintingStrategy,
    _Task,
)
from ..exceptions import ScanNotFoundError

from .scan import ScanManager


logger = logging.getLogger(__name__)


@ScanManager.register(ScanType.NIKTO)
class NiktoScanManager(ScanManager):
    SCAN_TYPE = ScanType.NIKTO
    _MODEL = NiktoScan
    _strategy_class = NiktoPrintingStrategy

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
            from src.modules.sentinel.services.tasks import NiktoScanTask

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

    def format_scan(self, scan_id: int) -> dict:
        scan = self.get_scan_by_id(scan_id)
        if not scan:
            raise ScanNotFoundError(scan_id)

        result = {
            "id": scan.id,
            "scanType": "nikto",
            "target": scan.target,
            "status": getattr(scan, "status", "unknown"),
            "startedAt": scan.started_at.isoformat(),
            "finishedAt": scan.finished_at.isoformat() if scan.finished_at else None, # type: ignore
            "incidents": [
                {
                    "osvdbId": i.osvdb_id,
                    "method": i.method,
                    "url": i.url,
                    "description": i.description,
                    "severity": getattr(i, "severity", "UNKNOWN"),
                    "discoveredAt": i.discovered_at.isoformat() if i.discovered_at else None,
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

