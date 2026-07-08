"""ScanHistoryManager — extraido de themis/managers.py (Fase 3 del refactor de estructura)."""

import logging
from typing import List
import src.modules.system.config_reading as CR
from src.modules.infrastructure import UnitOfWork
from ..repositories import ScanRepository
from ..model import ScanType
from ..services import HistoryStatsService


logger = logging.getLogger(__name__)


class ScanHistoryManager:
    """
    Manager for per-host historical scan statistics.

    Orchestrates UnitOfWork + ScanRepository + HistoryStatsService to produce
    the chart-ready payload consumed by both the REST endpoint and the PDF
    report. Every query is scoped to the owning user, so a user can only ever
    see statistics built from their own scans.
    """

    def list_scanned_hosts(self, user_id: int) -> List[dict]:
        """Return the distinct hosts the user has finished scanning."""
        with UnitOfWork() as uow:
            return ScanRepository(uow).get_scanned_targets(user_id)

    def get_stats(self, user_id: int) -> dict:
        """Return the user's scan counts grouped by type.

        Args:
            user_id: Owner user primary key (scopes the counts to this user).

        Returns:
            A dict with per-type counts (``nmap``/``nikto``/``openvas``/
            ``lybra``) plus a ``total`` (see ``ScanRepository.get_stats``).
        """
        with UnitOfWork() as uow:
            return ScanRepository(uow).get_stats(user_id)

    def get_host_history(self, user_id: int, target: str, scan_type: ScanType) -> dict:
        """Build the historical statistics payload for a host + tool.

        Args:
            user_id:   Owner user primary key (enforces the security scope).
            target:    The scanned host.
            scan_type: The tool discriminator (nmap/nikto/openvas).

        Returns:
            JSON-serializable statistics payload (see HistoryStatsService.build).
        """
        scan_type = ScanType(scan_type)
        limit = CR.get_themis_history_size()
        with UnitOfWork() as uow:
            scans = ScanRepository(uow).get_recent_finished(
                user_id, target, scan_type, limit
            )
            scans = list(reversed(scans))  # ascending (oldest -> newest) for charting
            return HistoryStatsService().build(scans, scan_type, target)

