"""NmapScanManager — extraido de thirdparty_scans_managers.py (D2 en
plans/deuda-tecnica-y-calidad.md: el fichero unificaba Nmap/Nikto/Nuclei
"porque cada uno era pequeño y compartía la misma forma"; con A4 (base
_create_scan_record) y A6 (base _previous_findings_map) ya no comparten
apenas cuerpo, así que la unificación dejó de pagarse sola)."""

import logging
from typing import Optional

from src.modules.accounts import LimitKey, QuotaManager
from src.modules.system.taskqueue import job_context
from src.modules.shared import isoformat_utc
from ..repositories import ScanRepository
from ..model import NmapScan, Scan, ScanType
from ..services import NmapResultProcessor, _Task
from ..exceptions import ScanNotFoundError

from .scan import ScanManager


logger = logging.getLogger(__name__)


@ScanManager.register(ScanType.NMAP)
class NmapScanManager(ScanManager):
    SCAN_TYPE = ScanType.NMAP
    _MODEL = NmapScan
    _RICH_LOADER = "get_nmap_rich"
    SCHEDULED_REQUIRED_ARGS = ("target_host", "target_ports")

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

            # Después de validar y justo antes de crear el registro: un objetivo
            # rechazado no gasta cuota. Aquí y no en el endpoint, porque el flujo
            # programado entra por este mismo método.
            QuotaManager().consume(user_id, LimitKey.THEMIS_THIRDPARTY_SCANS)

            scan = self._create_scan_and_dispatch(
                target=target_host,
                user_id=user_id,
                programed_scan_id=programed_scan_id,
                func=NmapScanManager.execute_nmap_scan,
                job_name="NmapScan",
                trailing_args=(target_host, target_ports, timeout),
                timeout=timeout,
            )
            scan_id = scan.id

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
                    "port": f"{open_port.port_id}/{open_port.port.protocol}",
                    "reason": open_port.reason,
                    "product": open_port.product,
                    "version": open_port.version,
                }
                for open_port in scan.open_ports_relation
            ],
            "totalOpenPorts": len(scan.open_ports_relation),
        }
        self._append_document_info(scan, result)
        return result

    def append_csv_data(self, data: dict, scan: Scan, task: "_Task") -> None:
        data["target_host"] = scan.target
        data["target_ports"] = getattr(task, "target_ports", "")
        data["timeout_sec"] = task.timeout
