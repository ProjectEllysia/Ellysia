"""KbSyncManager — extraido de sentinel/managers.py (Fase 3 del refactor de estructura)."""

import logging
from datetime import timedelta
from typing import List, Optional
import src.modules.system.config_reading as CR
from src.modules.infrastructure import UnitOfWork
from src.modules.shared import utcnow_naive
from ..repositories import KbRepository


logger = logging.getLogger(__name__)


class KbSyncManager:
    """Populates and refreshes the local vulnerability KB (the Lybra Feed).

    Pulls NVD (incremental, by ``lastModified`` window), CISA-KEV and FIRST-EPSS
    and upserts them via :class:`KbRepository`. The fetch/ingest split lives in
    ``lybra.kb``; this manager only orchestrates and owns the DB transactions.
    NVD is written in batches so a large delta never becomes one giant
    transaction; the initial full backfill is an operational one-off (run
    ``sync_nvd`` with a wide window) rather than something the nightly job does.
    """

    NVD_BATCH_SIZE = 200

    def sync_kev(self, url: str) -> int:
        """Mirror the CISA KEV catalogue. Returns the number of entries upserted."""
        from ..lybra import fetch_kev, ingest_kev
        count = 0
        with UnitOfWork() as uow:
            repo = KbRepository(uow)
            for vuln in fetch_kev(url):
                row = ingest_kev(vuln)
                if row:
                    repo.upsert_kev(row)
                    count += 1
        logger.info("KB: KEV sync upserted %d entries", count)
        return count

    def sync_epss(self, url: str) -> int:
        """Mirror the current EPSS scores. Returns the number of rows upserted."""
        from ..lybra import fetch_epss, parse_epss_rows
        csv_text = fetch_epss(url)
        count = 0
        with UnitOfWork() as uow:
            repo = KbRepository(uow)
            for row in parse_epss_rows(csv_text):
                repo.upsert_epss(row)
                count += 1
        logger.info("KB: EPSS sync upserted %d rows", count)
        return count

    def sync_nvd(self, base_url: str, window_days: int = 8, api_key: Optional[str] = None) -> int:
        """Mirror NVD CVEs modified in the last ``window_days``. Returns the count."""
        from ..lybra import iter_nvd_pages, ingest_nvd_cve
        last_start, last_end = self._nvd_window(window_days)

        count = 0
        batch: List[tuple] = []
        for item in iter_nvd_pages(base_url, last_start, last_end, api_key):
            parsed = ingest_nvd_cve(item)
            if parsed:
                batch.append(parsed)
            if len(batch) >= self.NVD_BATCH_SIZE:
                self._flush_cves(batch)
                count += len(batch)
                batch = []
        if batch:
            self._flush_cves(batch)
            count += len(batch)
        logger.info("KB: NVD sync upserted %d CVEs (window %dd)", count, window_days)
        return count

    def _flush_cves(self, batch: List[tuple]) -> None:
        with UnitOfWork() as uow:
            repo = KbRepository(uow)
            for cve_row, cpe_matches in batch:
                repo.upsert_cve(cve_row, cpe_matches)

    @staticmethod
    def _nvd_window(days: int) -> tuple[str, str]:
        """NVD-formatted (lastModStartDate, lastModEndDate) for the last ``days``."""
        fmt = "%Y-%m-%dT%H:%M:%S.000"
        end = utcnow_naive()
        start = end - timedelta(days=days)
        return start.strftime(fmt), end.strftime(fmt)

    def sync_all(self) -> dict:
        """Run every configured source once; return a per-source count summary."""
        sources = CR.get_kb_sources()
        summary: dict = {}
        if sources.get("kev"):
            summary["kev"] = self.sync_kev(sources["kev"])
        if sources.get("epss"):
            summary["epss"] = self.sync_epss(sources["epss"])
        if sources.get("nvd"):
            summary["nvd"] = self.sync_nvd(
                sources["nvd"],
                window_days=CR.get_kb_nvd_window_days(),
                api_key=CR.get_kb_nvd_api_key(),
            )
        logger.info("KB sync complete: %s", summary)
        return summary

    @staticmethod
    def execute_kb_sync() -> None:
        """Scheduled entry point (APScheduler). Runs the full sync, best-effort."""
        from src.modules.infrastructure.unit_of_work import close_all
        try:
            KbSyncManager().sync_all()
        except Exception:
            logger.exception("KB sync failed")
        finally:
            close_all()

