"""KbSyncManager y KbQueryManager — escritura y lectura de la KB local.

``KbSyncManager`` se extrajo de themis/managers.py (Fase 3 del refactor de
estructura). ``KbQueryManager`` es posterior y es el contrato de lectura que
consumen otros módulos.
"""

import logging
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
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
        """Mirror the current EPSS scores. Returns the number of rows upserted.

        The feed carries a score for essentially every known CVE (300k+ rows),
        so this goes through ``bulk_upsert_epss`` rather than one row at a time.
        """
        from ..lybra import fetch_epss, parse_epss_rows
        csv_text = fetch_epss(url)
        with UnitOfWork() as uow:
            count = KbRepository(uow).bulk_upsert_epss(list(parse_epss_rows(csv_text)))
        logger.info("KB: EPSS sync upserted %d rows", count)
        return count

    def sync_nvd(self, base_url: str, window_days: int = 8, api_key: Optional[str] = None) -> int:
        """Mirror NVD CVEs modified in the last ``window_days``. Returns the count.

        This is the incremental (delta) sync the nightly job runs — ``window_days``
        is expected to stay well under NVD's 120-day per-request cap. For a wide
        historical range, use :meth:`sync_nvd_backfill` instead, which chunks.
        """
        end = utcnow_naive()
        start = end - timedelta(days=window_days)
        count = self.sync_nvd_backfill(base_url, start, end, api_key=api_key)
        logger.info("KB: NVD sync upserted %d CVEs (window %dd)", count, window_days)
        return count

    # NVD's CVE API 2.0 documents a 120-day cap on the lastModStartDate/
    # lastModEndDate span (and does 404 past it) — but empirically or, unrelated
    # to that documented cap, it also silently *drops* the date filter and
    # returns the entire ~350k-CVE catalog once the span exceeds roughly 20-25
    # days, with no error to signal it. Observed directly against the live API:
    # 18 days -> 9397 results (sane), 25 days -> 346605 (the whole catalog).
    # 14 days is comfortably inside the safe zone, so a wide backfill chunks
    # there rather than at the documented-but-unsafe 120-day limit.
    _NVD_MAX_WINDOW_DAYS = 14

    def sync_nvd_backfill(
        self, base_url: str, start: datetime, end: Optional[datetime] = None,
        api_key: Optional[str] = None,
    ) -> int:
        """One-off historical mirror of every NVD CVE modified between ``start``
        and ``end`` (default: now), chunked into ``_NVD_MAX_WINDOW_DAYS`` windows
        to stay inside the range NVD actually filters correctly (see that
        constant's docstring). Meant to be run manually/operationally once (see
        the module docstring) — the nightly job only does small deltas.

        Returns the total number of CVEs upserted across all chunks.
        """
        from ..lybra import iter_nvd_pages, ingest_nvd_cve
        end = end or utcnow_naive()
        fmt = "%Y-%m-%dT%H:%M:%S.000"

        total = 0
        chunk_start = start
        first = True
        while chunk_start < end:
            if not first:
                # A chunk with only one page never sleeps internally (no next
                # page to wait for); without a pause here, two consecutive
                # single-page chunks would fire back to back and risk a 429.
                time.sleep(6.0)
            first = False

            chunk_end = min(chunk_start + timedelta(days=self._NVD_MAX_WINDOW_DAYS), end)
            count = 0
            batch: List[tuple] = []
            for item in iter_nvd_pages(
                base_url, chunk_start.strftime(fmt), chunk_end.strftime(fmt), api_key,
            ):
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
            logger.info(
                "KB: NVD backfill chunk %s -> %s upserted %d CVEs",
                chunk_start.date(), chunk_end.date(), count,
            )
            total += count
            chunk_start = chunk_end
        return total

    def _flush_cves(self, batch: List[tuple]) -> None:
        with UnitOfWork() as uow:
            repo = KbRepository(uow)
            for cve_row, cpe_matches in batch:
                repo.upsert_cve(cve_row, cpe_matches)

    def rebuild_cpe_product_index(self) -> int:
        """Rebuild the CPE product-name index (Fase I-b, paso 2). See
        ``KbRepository.rebuild_cpe_product_index`` for the algorithm."""
        with UnitOfWork() as uow:
            return KbRepository(uow).rebuild_cpe_product_index()

    def sync_all(self) -> dict:
        """Run every configured source once; return a per-source count summary."""
        sources = CR.knowledge_base_config().sources
        summary: dict = {}
        if sources.get("kev"):
            summary["kev"] = self.sync_kev(sources["kev"])
        if sources.get("epss"):
            summary["epss"] = self.sync_epss(sources["epss"])
        if sources.get("nvd"):
            summary["nvd"] = self.sync_nvd(
                sources["nvd"],
                window_days=CR.knowledge_base_config().nvd_window_days,
                api_key=CR.knowledge_base_config().nvd_api_key,
            )
            # Only worth rebuilding when NVD's CpeMatch rows might have
            # changed — the index is entirely derived from that table.
            summary["cpeProductAliases"] = self.rebuild_cpe_product_index()
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


# =============================================================================
# CONSULTA DE LA BASE DE CONOCIMIENTO (contrato público entre módulos)
# =============================================================================
#
# La KB es un espejo local de NVD/KEV/EPSS que ya se refresca cada noche, y
# tiene más consumidores potenciales que el escáner: Aegis necesita saber qué
# ha sido notable en los productos de una organización para redactar sus
# píldoras, y hasta ahora se lo preguntaba por HTTP a cve.circl.lu — que es
# otro espejo de NVD, más lento, sin KEV ni EPSS y con la red de por medio.
#
# Este manager es la puerta por la que entran esos consumidores. Devuelve
# dataclasses planas, nunca entidades del ORM: una CveEntry viva fuera de la
# sesión que la cargó es una fuente de DetachedInstanceError, y además ata al
# consumidor al esquema de Themis. El acoplamiento se queda en la forma de
# estos DTOs.


@dataclass(frozen=True)
class CveAdvisory:
    """Un CVE de la KB local, listo para consumir fuera de Themis."""

    cve_id:      str
    vendor:      str
    product:     str
    published:   Optional[datetime] = None
    severity:    str = ""
    cvss_score:  Optional[float] = None
    description: str = ""
    """Texto de NVD. **En inglés** — la KB guarda deliberadamente ``lang='en'``.
    Sirve como contexto para un modelo que redacte en otro idioma; mostrarlo
    tal cual a un usuario final sería una regresión."""
    kev:         bool = False
    """Aparece en el catálogo de CISA de vulnerabilidades explotadas."""
    epss:        Optional[float] = None
    """Probabilidad estimada de explotación en 30 días (0-1)."""

    @property
    def url(self) -> str:
        return f"https://nvd.nist.gov/vuln/detail/{self.cve_id}"


@dataclass(frozen=True)
class KbProduct:
    """Un producto del índice CPE, para poblar un selector."""

    vendor:       str
    product:      str
    display_name: str


class KbQueryManager:
    """Lectura de la KB local para otros módulos.

    Solo lee: la escritura es de :class:`KbSyncManager`. Usa
    ``build_repository`` en vez de ``UnitOfWork`` justamente por eso — no
    demarca transacción porque no hay nada que confirmar.
    """

    def advisories_for_products(
        self,
        products: List[tuple],
        since: datetime,
        min_cvss: Optional[float] = None,
        limit_per_product: int = 5,
        limit_total: int = 20,
    ) -> List[CveAdvisory]:
        """Avisos recientes para unas coordenadas CPE, enriquecidos con KEV/EPSS.

        Args:
            products: pares ``(vendor, product)``.
            since: fecha de publicación mínima.
            min_cvss: suelo de CVSS opcional.
            limit_per_product: tope por producto, para que uno ruidoso no
                desplace a los demás.
            limit_total: tope global tras ordenar por fecha.

        Returns:
            Los avisos, del más reciente al más antiguo.
        """
        from src.modules.infrastructure.session import build_repository

        repo = build_repository(KbRepository)
        rows = repo.recent_cves_for_products(
            products, since, min_cvss=min_cvss, limit_per_product=limit_per_product,
        )
        if not rows:
            return []

        # Dos consultas en lote para todo el conjunto, no dos por CVE.
        cve_ids = [cve.cve_id for _, _, cve in rows]
        kev_ids = repo.kev_ids_in(cve_ids)
        epss_by_id = repo.epss_scores_for(cve_ids)

        advisories = [
            CveAdvisory(
                cve_id      = cve.cve_id,
                vendor      = vendor,
                product     = product,
                published   = cve.published,
                severity    = cve.severity or "",
                cvss_score  = cve.cvss_score,
                description = cve.description or "",
                kev         = cve.cve_id in kev_ids,
                epss        = epss_by_id.get(cve.cve_id),
            )
            for vendor, product, cve in rows
        ]
        advisories.sort(key=lambda a: a.published or datetime.min, reverse=True)
        return advisories[:limit_total]

    def search_products(self, term: str, limit: int = 20) -> List[KbProduct]:
        """Productos del índice CPE que empiezan por ``term``."""
        from src.modules.infrastructure.session import build_repository

        rows = build_repository(KbRepository).search_products(term, limit=limit)
        return [
            KbProduct(vendor=vendor, product=product, display_name=display_name)
            for vendor, product, display_name in rows
        ]

    def resolve_products(self, names: List[str]) -> List[tuple]:
        """Traduce nombres de producto a coordenadas CPE ``(vendor, product)``.

        Para resolución automática (el inventario de un agente), donde sí
        importa que el índice descarte los nombres ambiguos: elegir un vendor
        al azar para "git" casaría CVEs contra software que no es. Los nombres
        que no resuelven se descartan en silencio, que es lo correcto para un
        inventario lleno de software sin presencia en NVD.
        """
        from src.modules.infrastructure.session import build_repository
        from ..lybra import normalize_product_name

        repo = build_repository(KbRepository)
        resolved: list[tuple] = []
        for name in names:
            key = normalize_product_name(name or "")
            if not key:
                continue
            pair = repo.resolve_product_alias(key)
            if pair and pair not in resolved:
                resolved.append(pair)
        return resolved

