"""NiktoScanManager — extraido de thirdparty_scans_managers.py (D2 en
plans/deuda-tecnica-y-calidad.md: ver el docstring de nmap.py para el porqué)."""

import logging
from typing import Optional

from src.modules.system.taskqueue import job_context
from src.modules.shared import isoformat_utc
from ..repositories import ScanRepository
from ..model import NiktoScan, Scan, ScanType
from ..lybra import compute_dedup_key, nikto_incident_to_finding
from ..services import NiktoResultProcessor, _Task
from ..exceptions import ScanNotFoundError

from .scan import ScanManager


logger = logging.getLogger(__name__)


@ScanManager.register(ScanType.NIKTO)
class NiktoScanManager(ScanManager):
    SCAN_TYPE = ScanType.NIKTO
    _MODEL = NiktoScan
    _RICH_LOADER = "get_nikto_rich"
    SCHEDULED_REQUIRED_ARGS = ("target_domain",)

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

            self._task_queue.submit(
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
        for incident_data in incidents_data:
            finding = nikto_incident_to_finding(incident_data)
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
