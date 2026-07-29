"""
Repositories for the Themis security scanning module.

Provides typed data access for Scan, its polymorphic subtypes
(NmapScan, NiktoScan, OpenVASScan), and ThemisDocument.

Classes:
    ScanRepository:                Repository for Scan and its polymorphic subtypes.
    ThemisReportRepository:    Repository for ThemisDocument (PDF reports).

Usage:
    with UnitOfWork() as uow:
        scan_repo = ScanRepository(uow)
        doc_repo  = ThemisReportRepository(uow)

        scan = scan_repo.get_by_id(42)
        docs = doc_repo.get_documents_by_user(user_id=1)

        # Persist
        scan_repo.save(NmapScan(target="10.0.0.1", user_id=1))

        # Commits automatically on context-manager exit.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import List, Optional, Tuple

from sqlalchemy import update as sa_update
from sqlalchemy.orm import Session, joinedload
from src.modules.infrastructure import BaseRepository, UnitOfWork
from src.modules.shared import utcnow_naive

from .model import (
    AuthorizedTarget,
    CpeMatch,
    CpeProductAlias,
    CveEntry,
    LybraScan,
    EpssScore,
    Finding,
    Host,
    HostService,
    KevEntry,
    NiktoIncident,
    NiktoScan,
    NmapScan,
    OpenPort,
    OpenVASVulnerability,
    OpenVASScan,
    OpenVASScanResult,
    Port,
    ProgramedScan,
    Scan,
    ScanFolder,
    ScanStatus,
    ScanType,
    ThemisDocument,
    Traceroute,
)

logger = logging.getLogger(__name__)


class ScanRepository(BaseRepository[Scan]):
    """
    Repository for the Scan entity and its polymorphic subtypes.

    Inherits all generic CRUD and query operations from BaseRepository[Scan]
    and adds domain-specific query methods for the Themis module.

    Polymorphism is handled transparently by SQLAlchemy: querying Scan
    returns instances of NmapScan, NiktoScan, or OpenVASScan depending
    on the `scan_type` discriminator column.

    Attributes:
        _model:  Scan (inherited from BaseRepository).
        _uow:    Active Unit of Work (inherited from BaseRepository).

    Example:
    >>> with UnitOfWork() as uow:
    ...     repo = ScanRepository(uow)
    ...     scan = NmapScan(target="192.168.1.1", user_id=1)
    ...     repo.save(scan)
    """
    
    _HISTORY_OPTIONS = {
        ScanType.NMAP: (
            NmapScan,
            lambda: [joinedload(NmapScan.open_ports_relation).joinedload(OpenPort.port)],
        ),
        ScanType.NIKTO: (
            NiktoScan,
            lambda: [joinedload(NiktoScan.incidents)],
        ),
        ScanType.OPENVAS: (
            OpenVASScan,
            lambda: [joinedload(OpenVASScan.results).joinedload(OpenVASScanResult.vulnerability)],
        ),
    }


    def __init__(self, uow: UnitOfWork | None = None, session: Session | None = None) -> None:
        super().__init__(Scan, uow=uow, session=session)

    # =========================================================================
    # TYPED GETTERS BY SUBTYPE
    # =========================================================================

    def get_by_id_and_type(self, scan_type: type[Scan], scan_id: int):
        return self._session.get(scan_type, scan_id)

    # =========================================================================
    # EAGER-LOADED QUERIES (background-thread use only)
    # ─────────────────────────────────────────────────────────────────────────
    # These methods eagerly load relationships via joinedload so that objects
    # remain usable after the per-job session is reset at the job boundary
    # (job_context / Scheduler.execute call close_all()), where lazy loading is
    # no longer available. Foreground (request-context) code should use
    # get_by_id_and_type() instead — lazy loading works with request-scoped
    # sessions.
    # =========================================================================

    def get_nmap_rich(self, scan_id: int) -> Optional[NmapScan]:
        """[Background thread] Retrieve NmapScan with relationships eagerly loaded."""
        return (
            self._session.query(NmapScan)
            .filter(NmapScan.id == scan_id)
            .options(
                joinedload(NmapScan.open_ports_relation).joinedload(OpenPort.port),
                joinedload(NmapScan.host),
            )
            .one_or_none()
        )

    def get_nikto_rich(self, scan_id: int) -> Optional[NiktoScan]:
        """[Background thread] Retrieve NiktoScan with relationships eagerly loaded."""
        return (
            self._session.query(NiktoScan)
            .filter(NiktoScan.id == scan_id)
            .options(joinedload(NiktoScan.incidents), joinedload(NiktoScan.host))
            .one_or_none()
        )

    def get_openvas_rich(self, scan_id: int) -> Optional[OpenVASScan]:
        """[Background thread] Retrieve OpenVASScan with relationships eagerly loaded."""
        return (
            self._session.query(OpenVASScan)
            .filter(OpenVASScan.id == scan_id)
            .options(
                joinedload(OpenVASScan.host),
                joinedload(OpenVASScan.results).joinedload(OpenVASScanResult.vulnerability),
                joinedload(OpenVASScan.results).joinedload(OpenVASScanResult.host),
            )
            .one_or_none()
        )

    def get_by_type_and_user(
        self,
        scan_type: type[Scan],
        user_id: int
    ) -> List[Scan]:
        return (
            self._session.query(scan_type)
            .filter(scan_type.user_id == user_id)
            .all()
        )
    
    # =========================================================================
    # DOMAIN QUERIES
    # =========================================================================

    def get_by_user(self, user_id: int) -> List[Scan]:
        return (
            self._session.query(Scan)
            .filter(Scan.user_id == user_id)
            .order_by(Scan.started_at.desc())
            .all()
        )

    def get_scans_by_type_paginated(
        self,
        user_id: int,
        scan_type: ScanType,
        page: int = 1,
        per_page: int = 10,
    ):
        """
        Retrieve a paginated list of scans for a user filtered by scan type.

        Args:
            user_id:   Owner user primary key.
            scan_type: ScanType enum value.
            page:      1‑based page number.
            per_page:  Items per page.

        Returns:
            Tuple of (items: List[Scan], total_count: int).
        """
        return self.paginate(
            page=page,
            per_page=per_page,
            filters={"user_id": user_id, "scan_type": scan_type},
            order_by=Scan.started_at.desc(),
        )

    # Sentinela de "solo los lanzados desde el panel de Themis" para
    # ``get_lybra_scans_paginated``. Hace falta un valor propio porque ``None``
    # ya significa otra cosa ahí ("no filtres, dame todos"), y lo que hay que
    # expresar es un ``asset_id IS NULL`` — que ``paginate`` no sabe formular,
    # ya que filtra por igualdad.
    PANEL_SCANS = "panel"

    def get_lybra_scans_paginated(
        self,
        user_id: int,
        page: int = 1,
        per_page: int = 10,
        asset_id=PANEL_SCANS,
    ):
        """
        Paginated Lybra scans for a user, filtered by where they came from.

        Args:
            user_id:  Owner user primary key.
            page:     1-based page number.
            per_page: Items per page.
            asset_id: :data:`PANEL_SCANS` (the default) for the scans launched
                from the Themis panel — those with no Hygeia asset behind them;
                an ``int`` for one asset's inventory scans (Fase I); or ``None``
                for every Lybra scan regardless of origin.

        Returns:
            Tuple of (items: List[LybraScan], total_count: int).
        """
        query = self._session.query(LybraScan).filter(LybraScan.user_id == user_id)
        if asset_id is self.PANEL_SCANS:
            query = query.filter(LybraScan.asset_id.is_(None))
        elif asset_id is not None:
            query = query.filter(LybraScan.asset_id == asset_id)

        total_count = query.count()
        items = (
            query.order_by(LybraScan.started_at.desc())
            .offset((page - 1) * per_page)
            .limit(per_page)
            .all()
        )
        return items, total_count

    def get_lybra_scan_ids_for_asset(self, asset_id: int) -> List[int]:
        """Ids of every Lybra scan produced from one Hygeia asset's inventory.

        The counterpart to ``LybraScan.asset_id`` being a soft reference with
        no ``ForeignKey``: there is no database-level cascade to lean on, so
        the asset's owner module has to clean up explicitly. Only the ids are
        returned because the actual deletion goes through
        ``LybraEngineManager.delete_scans_for_asset`` → ``delete_scan``, which
        also removes each scan's generated PDFs from disk — a bulk row delete
        here would leave those orphaned.
        """
        rows = (
            self._session.query(LybraScan.id)
            .filter(LybraScan.asset_id == asset_id)
            .all()
        )
        return [row[0] for row in rows]

    def get_stats(self, user_id: int) -> dict:
        """
        Return scan counts grouped by type for a user.

        Returns:
            Dict with keys ``total``, ``nmap``, ``nikto``, ``openvas``.
        """
        from sqlalchemy import func

        results = (
            self._session.query(Scan.scan_type, func.count(Scan.id))
            .filter(Scan.user_id == user_id)
            .group_by(Scan.scan_type)
            .all()
        )
        counts = {"nmap": 0, "nikto": 0, "openvas": 0, "lybra": 0}
        for scan_type_val, count in results:
            key = scan_type_val.value if hasattr(scan_type_val, "value") else str(scan_type_val)
            if key in counts:
                counts[key] = count
        counts["total"] = sum(counts.values())
        return counts

    def get_by_target(self, target: str) -> List[Scan]:
        return self.get_all_by_field("target", target)

    def get_by_status(self, status: ScanStatus) -> List[Scan]:
        return (
            self._session.query(Scan)
            .filter(Scan.status == status.value)
            .all()
        )

    def get_active_scans(self) -> List[Scan]:
        return (
            self._session.query(Scan)
            .filter(
                Scan.status.in_([ScanStatus.PENDING.value, ScanStatus.RUNNING.value])
            )
            .order_by(Scan.started_at.asc())
            .all()
        )

    def get_frequent_scans(self, user_id: int) -> List[Scan]:
        return (
            self._session.query(Scan)
            .filter(Scan.user_id == user_id, Scan.frequent.is_(True))
            .all()
        )

    def has_active_run_for_programed(self, programed_scan_id: int) -> bool:
        """True si el escaneo programado ya tiene una ejecución pending/running."""
        return (
            self._session.query(Scan)
            .filter(
                Scan.programed_scan_id == programed_scan_id,
                Scan.status.in_([ScanStatus.PENDING.value, ScanStatus.RUNNING.value]),
            )
            .first()
            is not None
        )

    def get_by_host(self, host_id: int) -> List[Scan]:
        return self.get_all_by_field("host_id", host_id)

    # =========================================================================
    # HISTORY QUERIES
    # =========================================================================

    def get_scanned_targets(self, user_id: int) -> List[dict]:
        """Return the distinct hosts a user has finished scanning.

        Grouped by (target, scan_type) so the frontend can offer a per-tool
        host selector. Only finished scans are considered.

        Returns:
            List of dicts: ``{"target", "scanType", "scanCount", "lastScannedAt"}``.
        """
        from sqlalchemy import func

        rows = (
            self._session.query(
                Scan.target,
                Scan.scan_type,
                func.count(Scan.id),
                func.max(Scan.started_at),
            )
            .filter(
                Scan.user_id == user_id,
                Scan.status == ScanStatus.FINISHED.value,
            )
            .group_by(Scan.target, Scan.scan_type)
            .order_by(func.max(Scan.started_at).desc())
            .all()
        )
        return [
            {
                "target": target,
                "scanType": scan_type.value if hasattr(scan_type, "value") else str(scan_type),
                "scanCount": count,
                "lastScannedAt": last_scanned,
            }
            for target, scan_type, count, last_scanned in rows
        ]

    def get_recent_finished(
        self,
        user_id: int,
        target: str,
        scan_type: ScanType,
        limit: int,
    ) -> List[Scan]:
        """Return the user's last ``limit`` finished scans of a host + tool.

        Findings relationships are eagerly loaded. Ordered newest-first; the
        service reverses the list to ascending order for charting.
        """

        scan_type = ScanType(scan_type)
        model, options_factory = self._HISTORY_OPTIONS[scan_type]
        return (
            self._session.query(model)
            .filter(
                model.user_id == user_id,
                model.target == target,
                model.status == ScanStatus.FINISHED.value,
            )
            .options(*options_factory())
            .order_by(model.started_at.desc())
            .limit(limit)
            .all()
        )

    # =========================================================================
    # FOLDER QUERIES
    # =========================================================================

    def get_by_folder(self, folder_id: int, user_id: int) -> List[Scan]:
        """Return scans inside a folder, ordered by start time descending."""
        return (
            self._session.query(Scan)
            .filter(
                Scan.folder_id == folder_id,
                Scan.user_id == user_id,
            )
            .order_by(Scan.started_at.desc())
            .all()
        )

    def get_unfoldered_by_user(self, user_id: int) -> List[Scan]:
        """Return scans without a folder, ordered by start time descending."""
        return (
            self._session.query(Scan)
            .filter(
                Scan.user_id == user_id,
                Scan.folder_id.is_(None),
            )
            .order_by(Scan.started_at.desc())
            .all()
        )

    def set_folder(self, scan: Scan, folder: ScanFolder) -> Scan:
        """Assign a scan to a folder."""
        scan.folder = folder
        return self.update(scan)

    def unset_folder(self, scan: Scan) -> Scan:
        """Remove a scan from its folder."""
        scan.folder_id = None
        return self.update(scan)

    # =========================================================================
    # STATUS TRANSITIONS
    # =========================================================================

    def update_status(self, scan: Scan, status: ScanStatus) -> Scan:
        scan.status = status.value # type: ignore

        terminal = {ScanStatus.FINISHED, ScanStatus.FAILED, ScanStatus.CANCELLED}
        if status in terminal and scan.finished_at is None:
            scan.finished_at = utcnow_naive() # type: ignore

        return self.update(scan)

    def update_status_if(
        self,
        scan_id: int,
        expected: set[ScanStatus],
        status: ScanStatus,
    ) -> bool:
        """Compare-and-swap: transiciona el estado solo si sigue siendo uno de
        ``expected``. Devuelve True si la transición ocurrió.

        Cierra la carrera entre ``cancel_scan`` (API) y el worker terminando el
        escaneo (proceso aparte): sin un UPDATE atómico con WHERE, la última
        escritura gana sin importar cuál refleja la realidad — un escaneo con
        resultados puede mostrarse como cancelado, o un cancelado puede
        sobrescribirse silenciosamente a 'finished'.
        """
        values: dict = {"status": status.value}

        terminal = {ScanStatus.FINISHED, ScanStatus.FAILED, ScanStatus.CANCELLED}
        if status in terminal:
            values["finished_at"] = utcnow_naive()

        result = self._session.execute(
            sa_update(Scan)
            .where(Scan.id == scan_id, Scan.status.in_([s.value for s in expected]))
            .values(**values)
        )
        return result.rowcount > 0

    def get_or_create_host(
        self,
        hostname: str,
        ip_address: str,
        mac_address: str = "",
        vendor: str = ""
    ) -> Host:
        """Get or create a Host row using upsert to avoid race conditions."""
        from sqlalchemy.dialects.postgresql import insert as pg_insert

        host = self._session.query(Host).filter(Host.hostname == hostname).first()
        if host:
            return host

        stmt = pg_insert(Host).values(
            hostname    = hostname,
            ip_address  = ip_address,
            mac_address = mac_address or "",
            vendor      = vendor,
        ).on_conflict_do_nothing(index_elements=["hostname"])

        self._session.execute(stmt)
        self._session.flush()

        return self._session.query(Host).filter(Host.hostname == hostname).first()

    def get_host_by_ip(self, ip_address: str) -> Optional[Host]:
        """Return any existing Host row for this IP, regardless of hostname.

        Used by callers that only know a bare IP (e.g. Lybra's self-discovery
        mode) so they reuse the Host record another scanner already created for
        the same physical target — Nmap, say, which may know a resolved
        hostname — instead of creating a duplicate keyed by the bare IP (Host
        is unique on ``hostname``, so "10.0.0.5" and "server.example.com" would
        otherwise become two rows for the same machine).
        """
        return (
            self._session.query(Host)
            .filter(Host.ip_address == ip_address)
            .order_by(Host.id.asc())
            .first()
        )

    def get_or_create_port(self, protocol: str) -> Port:
        """Get or create a Port row by its protocol string."""
        port = self._session.query(Port).filter(Port.protocol == protocol).one_or_none()
        if port:
            return port

        new_port = Port(protocol=protocol)
        self._session.add(new_port)
        self._session.flush()
        return new_port

    def get_or_create_nikto_incident(self, inc_data: dict) -> NiktoIncident:
        """Get or create a NiktoIncident row by its unique fields."""
        existing = self._session.query(NiktoIncident).filter(
            NiktoIncident.description == inc_data["description"],
            NiktoIncident.url         == inc_data["url"],
            NiktoIncident.method      == inc_data["method"],
        ).first()

        if existing:
            return existing

        incident = NiktoIncident(
            description = inc_data["description"],
            osvdb_id    = inc_data["osvdb_id"],
            method      = inc_data["method"],
            url         = inc_data["url"],
            severity    = inc_data["severity"],
        )
        self._session.add(incident)
        self._session.flush()
        return incident

    def get_or_create_vulnerability(self, vuln_data: dict) -> OpenVASVulnerability:
        """Get or create an OpenVASVulnerability row by NVT OID."""
        nvt_oid = vuln_data["nvt_oid"]
        vuln = self._session.query(OpenVASVulnerability).filter(
            OpenVASVulnerability.nvt_oid == nvt_oid
        ).one_or_none()

        if vuln:
            return vuln

        vuln = OpenVASVulnerability(**vuln_data)
        self._session.add(vuln)
        self._session.flush()
        return vuln

    def persist_nmap_results(self, scan, host, ports_data) -> None:
        """Persist Nmap host and port data into the database."""
        scan.host_id = host.id

        for port_info in ports_data:
            port = self.get_or_create_port(port_info["protocol"])
            if port not in scan.target_ports:
                scan.target_ports.append(port)

            open_port = OpenPort(
                nmap_scan_id = scan.id,
                port_id      = port.id,
                reason       = port_info["reason"],
                product      = port_info["product"],
                version      = port_info["version"],
                given_use    = port_info["given_use"],
                cpe          = port_info.get("cpe") or None,
            )
            self._session.add(open_port)

    def persist_nikto_results(self, scan, host, incidents_data) -> None:
        """Persist Nikto incidents and associate a host."""
        for inc_data in incidents_data:
            incident = self.get_or_create_nikto_incident(inc_data)
            if incident not in scan.incidents:
                scan.incidents.append(incident)

        scan.host = host

    def persist_openvas_results(self, scan, results_data, vulnerability_map) -> None:
        """Persist OpenVAS scan results."""
        for result_data in results_data:
            host = self.get_or_create_host(
                hostname   = result_data["host_ip"],
                ip_address = result_data["host_ip"],
            )

            scan_result = OpenVASScanResult(
                openvas_scan_id  = scan.id,
                vulnerability_id = vulnerability_map[result_data["nvt_oid"]].id,
                host_id          = host.id,
            )
            self._session.add(scan_result)

    # =========================================================================
    # LYBRA ENGINE
    # =========================================================================

    def get_lybra_rich(self, scan_id: int) -> Optional[LybraScan]:
        """[Background thread] Retrieve an LybraScan by id.

        No relationships are eager-loaded because Findings are queried
        separately via ``get_findings_by_scan`` (they are not modelled as an
        ORM relationship on the scan).
        """
        return (
            self._session.query(LybraScan)
            .filter(LybraScan.id == scan_id)
            .one_or_none()
        )

    def get_open_ports_for_scan(self, nmap_scan_id: int) -> List[OpenPort]:
        """Return the OpenPort rows of an Nmap scan (the services Lybra reads).

        Eager-loads the related Port so the caller can read ``protocol`` after
        the session closes (Lybra runs in a background worker).
        """
        return (
            self._session.query(OpenPort)
            .filter(OpenPort.nmap_scan_id == nmap_scan_id)
            .options(joinedload(OpenPort.port))
            .all()
        )

    def persist_findings(self, scan: Scan, findings_data: List[dict]) -> None:
        """Persist a batch of normalized Finding rows for a scan.

        Args:
            scan: The scan that produced the findings (its id is used as scan_id).
            findings_data: List of dicts with Finding column values.
        """
        for data in findings_data:
            self._session.add(Finding(scan_id=scan.id, **data))

    def get_findings_by_scan(self, scan_id: int) -> List[Finding]:
        """Return all findings of a scan, newest first."""
        return (
            self._session.query(Finding)
            .filter(Finding.scan_id == scan_id)
            .order_by(Finding.id.asc())
            .all()
        )

    def get_finding(self, finding_id: int) -> Optional[Finding]:
        """Return a single finding by id (or None)."""
        return self._session.get(Finding, finding_id)

    def get_previous_lybra_findings(
        self, user_id: int, target: str, exclude_scan_id: int
    ) -> List[Finding]:
        """Return the findings of the user's previous finished Lybra scan of a
        target (for lifecycle comparison), or an empty list if there is none."""
        prev = (
            self._session.query(LybraScan)
            .filter(
                LybraScan.user_id == user_id,
                LybraScan.target == target,
                LybraScan.status == ScanStatus.FINISHED.value,
                LybraScan.id != exclude_scan_id,
            )
            .order_by(LybraScan.started_at.desc())
            .first()
        )
        return self.get_findings_by_scan(prev.id) if prev else []

    def get_host_services(self, host_id: int) -> List[HostService]:
        """Return a host's currently-tracked attack surface (Fase 5)."""
        return (
            self._session.query(HostService)
            .filter(HostService.host_id == host_id)
            .all()
        )

    def upsert_host_service(
        self, host_id: int, port: Optional[int], protocol: str,
        name: Optional[str], product: Optional[str], version: Optional[str], cpe: Optional[str],
    ) -> None:
        """Record a service as currently open, creating or refreshing its row.

        Bumps ``last_seen_at`` and the identification fields (only when the new
        scan actually resolved something — an unresolved rescan must not erase
        a product/version a previous scan already found) on every call, so a
        service's row always reflects its most recent observation.

        ``port`` is ``None`` for a portless, ``origin="inventory"`` service
        (Fase 0.9) — an installed package with nothing listening. A port
        already uniquely identifies which row to touch; without a port, the
        lookup keys on ``product`` too, otherwise two different packages on
        the same host would collide on the same ``(host, NULL, protocol)``
        row and silently overwrite each other.
        """
        filters = [
            HostService.host_id == host_id,
            HostService.port == port,
            HostService.protocol == protocol,
        ]
        if port is None:
            filters.append(HostService.product == product)
        existing = (
            self._session.query(HostService)
            .filter(*filters)
            .first()
        )
        now = utcnow_naive()
        if existing is None:
            self._session.add(HostService(
                host_id=host_id, port=port, protocol=protocol, name=name,
                product=product, version=version, cpe=cpe,
                first_seen_at=now, last_seen_at=now,
            ))
            return
        existing.last_seen_at = now
        existing.name = name or existing.name
        existing.product = product or existing.product
        existing.version = version or existing.version
        existing.cpe = cpe or existing.cpe


class ThemisReportRepository(BaseRepository[ThemisDocument]):
    """
    Repository for the ThemisDocument entity (PDF reports).

    Attributes:
        _model:  ThemisDocument (inherited from BaseRepository).
        _uow:    Active Unit of Work (inherited from BaseRepository).

    Example:
    >>> with UnitOfWork() as uow:
    ...     repo = ThemisReportRepository(uow)
    ...     doc  = repo.get_by_id(1)
    ...     repo.delete(doc)
    """

    def __init__(self, uow: UnitOfWork | None = None, session: Session | None = None) -> None:
        super().__init__(ThemisDocument, uow=uow, session=session)

    def get_document(self, scan_id: int) -> Optional[ThemisDocument]:
        return (
            self._session.query(ThemisDocument)
            .filter(ThemisDocument.scan_id == scan_id)
            .one_or_none()
        )

    def get_latest_document(self, scan_id: int) -> Optional[ThemisDocument]:
        return (
            self._session.query(ThemisDocument)
            .filter(ThemisDocument.scan_id == scan_id)
            .order_by(ThemisDocument.created_at.desc())
            .first()
        )

    def get_documents_by_user(self, user_id: int) -> List[ThemisDocument]:
        return (
            self._session.query(ThemisDocument)
            .filter(ThemisDocument.user_id == user_id)
            .order_by(ThemisDocument.created_at.desc())
            .all()
        )

    def get_documents_by_scan(self, scan_id: int) -> List[ThemisDocument]:
        return (
            self._session.query(ThemisDocument)
            .filter(ThemisDocument.scan_id == scan_id)
            .order_by(ThemisDocument.created_at.desc())
            .all()
        )


class ScanFolderRepository(BaseRepository[ScanFolder]):
    """
    Repository for the ScanFolder entity.

    Manages user-created folders that group security scans. A scan can belong
    to at most one folder; deleting a folder leaves its scans unassigned.

    Attributes:
        _model:  ScanFolder (inherited from BaseRepository).
        _uow:    Active Unit of Work (inherited from BaseRepository).
    """

    def __init__(self, uow: UnitOfWork | None = None, session: Session | None = None) -> None:
        super().__init__(ScanFolder, uow=uow, session=session)

    def get_by_user(self, user_id: int) -> List[ScanFolder]:
        """Return all folders for a user, newest first."""
        return (
            self._session.query(ScanFolder)
            .filter(ScanFolder.user_id == user_id)
            .order_by(ScanFolder.created_at.desc())
            .all()
        )

    def get_by_id_and_user(self, folder_id: int, user_id: int) -> Optional[ScanFolder]:
        """Return a folder only if it belongs to the given user."""
        return (
            self._session.query(ScanFolder)
            .filter(ScanFolder.id == folder_id, ScanFolder.user_id == user_id)
            .one_or_none()
        )


class TracerouteRepository(BaseRepository[Traceroute]):
    """
    Repository for the Traceroute entity (cached network paths to targets).

    One row per (user_id, target); ``upsert`` refreshes the cached hops in
    place so the cache never grows unbounded for a repeatedly-scanned host.
    """

    def __init__(self, uow: UnitOfWork | None = None, session: Session | None = None) -> None:
        super().__init__(Traceroute, uow=uow, session=session)

    def get_by_user_and_target(self, user_id: int, target: str) -> Optional[Traceroute]:
        """Return the cached traceroute for a user + target, or None."""
        return (
            self._session.query(Traceroute)
            .filter(Traceroute.user_id == user_id, Traceroute.target == target)
            .one_or_none()
        )

    def upsert(self, user_id: int, target: str, hops: list) -> Traceroute:
        """Create or refresh the cached traceroute for a user + target."""
        existing = self.get_by_user_and_target(user_id, target)
        if existing:
            existing.hops = hops
            existing.hop_count = len(hops)
            existing.created_at = utcnow_naive()
            return self.update(existing)

        trace = Traceroute(
            user_id=user_id,
            target=target,
            hops=hops,
            hop_count=len(hops),
        )
        return self.save(trace)


class KbRepository(BaseRepository[CveEntry]):
    """Repository for the local vulnerability knowledge base (the Lybra Feed).

    Persists the mirrored NVD/KEV/EPSS data and answers the matcher's central
    question via :meth:`cves_for_cpe`. All upserts are keyed by ``cve_id`` so a
    re-sync updates in place instead of duplicating.
    """

    def __init__(self, uow: UnitOfWork | None = None, session: Session | None = None) -> None:
        super().__init__(CveEntry, uow=uow, session=session)

    # =========================================================================
    # MATCHER QUERY
    # =========================================================================

    def cves_for_cpe(self, vendor: str, product: str, version: str) -> List[CveEntry]:
        """Return the CVEs affecting ``vendor:product`` at ``version``.

        Filters candidate applicability rows by (vendor, product) in SQL, then
        applies the version-range logic in Python (see ``lybra.kb``). Results
        are de-duplicated by CVE.
        """
        from .lybra import version_in_range

        candidates = (
            self._session.query(CpeMatch)
            .filter(CpeMatch.vendor == vendor, CpeMatch.product == product)
            .options(joinedload(CpeMatch.cve))
            .all()
        )
        seen: set[int] = set()
        result: List[CveEntry] = []
        for match in candidates:
            if version_in_range(version, match) and match.cve_id not in seen:
                seen.add(match.cve_id)
                result.append(match.cve)
        return result

    def resolve_product_alias(self, normalized_name: str) -> Optional[Tuple[str, str]]:
        """Look up a normalized product name in the automated CPE index (Fase I-b, paso 2).

        The third and last strategy ``LybraEngine._resolve_cpe`` tries, after
        an embedded CPE and the curated alias feed both miss. See
        :meth:`rebuild_cpe_product_index` for how the index is built and why a
        name that used to be ambiguous is never in it.
        """
        row = (
            self._session.query(CpeProductAlias)
            .filter(CpeProductAlias.normalized_name == normalized_name)
            .one_or_none()
        )
        return (row.vendor, row.product) if row else None

    def rebuild_cpe_product_index(self) -> int:
        """Rebuild ``CpeProductAlias`` from the current ``CpeMatch`` table (Fase I-b, paso 2).

        Indexes every distinct ``(vendor, product)`` pair in ``CpeMatch`` under
        **two** normalized keys (:func:`~.lybra.kb.normalize_product_name`),
        because a desktop inventory and NVD name the same software differently:

        1. The product alone — ``microsoft:edge`` → ``"edge"``. This is NVD's
           own vocabulary, read literally.
        2. Vendor and product together — ``microsoft:edge`` → ``"microsoft
           edge"``. Windows inventories overwhelmingly prefix the vendor into
           the display name ("Microsoft Edge", "Adobe Acrobat", "GitHub CLI",
           "Oracle VirtualBox"), which key 1 alone can never match: NVD's
           ``product`` column almost never repeats the vendor.

        Key 1 **wins on collision**: it is the direct reading, while key 2 is a
        derived convenience, so where both exist the direct one is kept and the
        derived one only fills genuine gaps. This mirrors the precedence
        ``LybraEngine._resolve_cpe`` already applies across its three
        strategies (more-direct evidence first), and it is what makes adding
        key 2 a pure addition — measured against a full NVD mirror it adds
        ~118k resolvable names while removing exactly zero.

        Ambiguity is discarded **within each key space independently**: a
        normalized name that more than one distinct pair maps to is dropped
        entirely rather than resolved to either candidate — e.g. the literal
        NVD product ``"git"`` belongs to at least half a dozen unrelated
        vendors (a Jenkins plugin, a firmware component, the real Git SCM...),
        and picking one at random would risk matching CVEs against the wrong
        software. That specific, verified case is exactly what
        ``feeds/product_aliases.json`` (paso 3) exists to override by hand.

        A full delete-and-reinsert rather than an incremental diff: this runs
        once per KB sync (nightly, at most), so the cost is a non-issue, and it
        is what lets a pair that stops being unique correctly fall back out of
        the index instead of a stale row lingering.

        Returns:
            The number of alias rows written.
        """
        from .lybra import normalize_product_name

        pairs = self._session.query(CpeMatch.vendor, CpeMatch.product).distinct().all()
        by_product: dict[str, set] = {}
        by_vendor_product: dict[str, set] = {}
        for vendor, product in pairs:
            key = normalize_product_name(product)
            if key:
                by_product.setdefault(key, set()).add((vendor, product))
            vendor_key = normalize_product_name(f"{vendor} {product}")
            if vendor_key:
                by_vendor_product.setdefault(vendor_key, set()).add((vendor, product))

        def unambiguous(grouped: dict) -> dict:
            return {key: next(iter(c)) for key, c in grouped.items() if len(c) == 1}

        resolved = unambiguous(by_product)
        for key, pair in unambiguous(by_vendor_product).items():
            resolved.setdefault(key, pair)   # key 1 wins; key 2 only fills gaps

        self._session.query(CpeProductAlias).delete()
        for key, (vendor, product) in resolved.items():
            self._session.add(CpeProductAlias(normalized_name=key, vendor=vendor, product=product))
        self._session.flush()
        logger.info(
            "KB: CPE product index rebuilt (%d aliases: %d product names, %d vendor-qualified)",
            len(resolved), len(by_product), len(by_vendor_product),
        )
        return len(resolved)

    def get_kev(self, cve_id: str) -> Optional[KevEntry]:
        return self._session.query(KevEntry).filter(KevEntry.cve_id == cve_id).one_or_none()

    def get_epss(self, cve_id: str) -> Optional[EpssScore]:
        return self._session.query(EpssScore).filter(EpssScore.cve_id == cve_id).one_or_none()

    def get_cves_with_matches(self, cve_ids: List[str]) -> List[CveEntry]:
        """Bulk-fetch CveEntry rows (with their CpeMatch rows eager-loaded) for a
        list of CVE ids. Used to enrich a report with description/CWE/fixed-version
        context in one query instead of one per finding."""
        if not cve_ids:
            return []
        return (
            self._session.query(CveEntry)
            .filter(CveEntry.cve_id.in_(cve_ids))
            .options(joinedload(CveEntry.cpe_matches))
            .all()
        )

    def counts(self) -> dict:
        """Row counts per KB table (for the sync summary / health checks)."""
        return {
            "cves": self._session.query(CveEntry).count(),
            "cpeMatches": self._session.query(CpeMatch).count(),
            "kev": self._session.query(KevEntry).count(),
            "epss": self._session.query(EpssScore).count(),
        }

    # =========================================================================
    # UPSERTS (keyed by cve_id; a re-sync updates in place)
    # =========================================================================

    def upsert_cve(self, cve_row: dict, cpe_matches: List[dict]) -> CveEntry:
        """Insert or update a CVE and replace its applicability rows."""
        cve = self._session.query(CveEntry).filter(CveEntry.cve_id == cve_row["cve_id"]).one_or_none()
        if cve is None:
            cve = CveEntry(**cve_row)
            self._session.add(cve)
        else:
            for key, value in cve_row.items():
                setattr(cve, key, value)
            for old in list(cve.cpe_matches):
                self._session.delete(old)
        self._session.flush()

        for match_row in cpe_matches:
            self._session.add(CpeMatch(cve_id=cve.id, **match_row))
        return cve

    def upsert_kev(self, kev_row: dict) -> KevEntry:
        kev = self._session.query(KevEntry).filter(KevEntry.cve_id == kev_row["cve_id"]).one_or_none()
        if kev is None:
            kev = KevEntry(**kev_row)
            self._session.add(kev)
        else:
            for key, value in kev_row.items():
                setattr(kev, key, value)
        return kev

    def upsert_epss(self, epss_row: dict) -> EpssScore:
        epss = self._session.query(EpssScore).filter(EpssScore.cve_id == epss_row["cve_id"]).one_or_none()
        if epss is None:
            epss = EpssScore(**epss_row)
            self._session.add(epss)
        else:
            for key, value in epss_row.items():
                setattr(epss, key, value)
        return epss

    def bulk_upsert_epss(self, rows: List[dict], chunk_size: int = 5000) -> int:
        """Upsert many EPSS rows in one round-trip per chunk.

        The EPSS feed carries a score for essentially every known CVE
        (300k+ rows). ``upsert_epss`` does one SELECT-then-add per row, which
        at that volume takes on the order of hours; a single ``INSERT ...
        ON CONFLICT DO UPDATE`` per chunk is the same operation done at
        Postgres speed instead of ORM speed.
        """
        from sqlalchemy.dialects.postgresql import insert as pg_insert

        total = 0
        for i in range(0, len(rows), chunk_size):
            chunk = rows[i:i + chunk_size]
            if not chunk:
                continue
            stmt = pg_insert(EpssScore).values(chunk)
            stmt = stmt.on_conflict_do_update(
                index_elements=["cve_id"],
                set_={"score": stmt.excluded.score, "percentile": stmt.excluded.percentile,
                      "scored_at": stmt.excluded.scored_at},
            )
            self._session.execute(stmt)
            total += len(chunk)
        return total


class ProgramedScanRepository(BaseRepository[ProgramedScan]):
    """
    Repository for the ProgramedScan entity (scheduled/recurring scans).

    Manages programed scan lifecycle: querying by user and type,
    restoring active jobs on scheduler startup, and recording run timestamps.

    Attributes:
        _model:  ProgramedScan (inherited from BaseRepository).
        _uow:    Active Unit of Work (inherited from BaseRepository).

    Example:
    >>> with UnitOfWork() as uow:
    ...     repo = ProgramedScanRepository(uow)
    ...     ps = repo.get_by_id(ps_id)
    ...     repo.update_run_timestamps(ps, last_run=now, next_run=next_run)
    """

    def __init__(self, uow: UnitOfWork | None = None, session: Session | None = None) -> None:
        super().__init__(ProgramedScan, uow=uow, session=session)

    # =========================================================================
    # QUERY METHODS
    # =========================================================================

    def get_by_user(self, user_id: int) -> List[ProgramedScan]:
        """
        Retrieve all programed scans for a user, ordered by creation date.

        Args:
            user_id: User primary key.

        Returns:
            List of ProgramedScan instances sorted newest‑first.
        """
        return (
            self._session.query(ProgramedScan)
            .filter(ProgramedScan.user_id == user_id)
            .order_by(ProgramedScan.created_at.desc())
            .all()
        )

    def get_active_by_user(self, user_id: int) -> List[ProgramedScan]:
        """
        Retrieve active programed scans for a user.

        Args:
            user_id: User primary key.

        Returns:
            List of active ProgramedScan instances.
        """
        return (
            self._session.query(ProgramedScan)
            .filter(
                ProgramedScan.user_id == user_id,
                ProgramedScan.is_active.is_(True),
            )
            .order_by(ProgramedScan.created_at.desc())
            .all()
        )

    def get_by_user_and_type(self, user_id: int, scan_type: ScanType) -> List[ProgramedScan]:
        """
        Retrieve programed scans for a user filtered by scan type.

        Args:
            user_id:    User primary key.
            scan_type:  Scan type discriminator ("nmap", "nikto", "openvas").

        Returns:
            List of matching ProgramedScan instances.
        """
        return (
            self._session.query(ProgramedScan)
            .filter(
                ProgramedScan.user_id == user_id,
                ProgramedScan.scan_type == scan_type,
            )
            .order_by(ProgramedScan.created_at.desc())
            .all()
        )

    def get_all_active(self) -> List[ProgramedScan]:
        """
        Retrieve all active programed scans regardless of user.

        Used on scheduler startup to restore all scheduled jobs from the
        database after a restart.

        Returns:
            List of active ProgramedScan instances.
        """
        return (
            self._session.query(ProgramedScan)
            .filter(ProgramedScan.is_active.is_(True))
            .order_by(ProgramedScan.created_at.desc())
            .all()
        )

    # =========================================================================
    # MUTATION METHODS
    # =========================================================================

    def update_run_timestamps(
        self,
        ps: ProgramedScan,
        last_run: datetime,
        next_run: Optional[datetime],
    ) -> ProgramedScan:
        """
        Record a completed execution of a programed scan.

        Both timestamps are computed by the caller (the Scheduler owns the
        scheduling math, this repository only persists). ``next_run`` may be
        ``None`` for one-shot schedules.

        Args:
            ps:        The ProgramedScan that executed.
            last_run:  Timestamp of the execution just performed (naive UTC).
            next_run:  Timestamp of the next planned execution (naive UTC).

        Returns:
            The same ProgramedScan instance after flush.
        """
        ps.last_run_at = last_run  # type: ignore
        ps.next_run_at = next_run  # type: ignore
        return self.update(ps)

    def create(
        self,
        user_id: int,
        scan_type: ScanType,
        arguments: dict,
        schedule_type: str,
        schedule_config: dict,
        next_run_at: Optional[datetime],
    ) -> ProgramedScan:
        """
        Create and persist a new programed scan.

        Args:
            user_id:         Owner user primary key.
            scan_type:       Scan discriminator ("nmap", "nikto", "openvas").
            arguments:       Scan parameters (e.g. {"ports": "22,80"}).
            schedule_type:   "interval" or "cron".
            schedule_config: Schedule definition (e.g. {"every": 60, "unit": "minutes"}).
            next_run_at:     First planned execution time (computed by the caller
                             via Scheduler.calculate_next_run).

        Returns:
            The newly persisted ProgramedScan instance.
        """
        ps = ProgramedScan(
            user_id=user_id,
            scan_type=scan_type,
            arguments=arguments,
            schedule_type=schedule_type,
            schedule_config=schedule_config,
            next_run_at=next_run_at,
        )
        return self.save(ps)


class AuthorizedTargetRepository(BaseRepository[AuthorizedTarget]):
    """Repository for the AuthorizedTarget entity (roadmap §6 register)."""

    def __init__(self, uow: UnitOfWork | None = None, session: Session | None = None) -> None:
        super().__init__(AuthorizedTarget, uow=uow, session=session)

    def get_by_user(self, user_id: int) -> List[AuthorizedTarget]:
        """Return all authorized-target entries for a user, newest first."""
        return (
            self._session.query(AuthorizedTarget)
            .filter(AuthorizedTarget.user_id == user_id)
            .order_by(AuthorizedTarget.created_at.desc())
            .all()
        )

    def get_by_id_and_user(self, target_id: int, user_id: int) -> Optional[AuthorizedTarget]:
        """Return an entry only if it belongs to the given user."""
        return (
            self._session.query(AuthorizedTarget)
            .filter(AuthorizedTarget.id == target_id, AuthorizedTarget.user_id == user_id)
            .one_or_none()
        )

    def get_by_target_and_user(self, target: str, user_id: int) -> Optional[AuthorizedTarget]:
        """Return the entry matching the exact normalized target string, if any."""
        return (
            self._session.query(AuthorizedTarget)
            .filter(AuthorizedTarget.target == target, AuthorizedTarget.user_id == user_id)
            .one_or_none()
        )