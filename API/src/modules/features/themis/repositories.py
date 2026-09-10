"""
Repositories for the Themis security scanning module.

Provides typed data access for Scan, its polymorphic subtypes
(NmapScan, NiktoScan, LybraScan, NucleiScan), and ThemisDocument.

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
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from sqlalchemy import func, or_
from sqlalchemy import update as sa_update
from sqlalchemy.orm import joinedload
from src.modules.infrastructure import BaseRepository, DocumentRepository
from src.modules.shared import utcnow_naive
from .lybra.evidence import prepare_evidence

from .model import (
    AuthorizedTarget,
    CpeMatch,
    CpeProductAlias,
    CveEntry,
    DistroAdvisory,
    DistroPkgStatus,
    LybraScan,
    EpssScore,
    Finding,
    FindingEvidence,
    Host,
    HostService,
    KbSyncStatus,
    KevEntry,
    UnresolvedProduct,
    NiktoIncident,
    NiktoScan,
    NmapScan,
    NucleiScan,
    OpenPort,
    Port,
    ProgramedScan,
    Scan,
    ScanFolder,
    ScanFailureReason,
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
    returns instances of NmapScan, NiktoScan, LybraScan or NucleiScan
    depending on the `scan_type` discriminator column.

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
        ScanType.LYBRA: (
            LybraScan,
            lambda: [joinedload(LybraScan.findings)],
        ),
        ScanType.NUCLEI: (
            NucleiScan,
            lambda: [joinedload(NucleiScan.findings)],
        ),
    }


    _MODEL = Scan

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

    def get_latest_scan_by_asset(self, user_id: int, asset_ids: List[int]) -> List[LybraScan]:
        """El escaneo más reciente por activo Hygeia, en una sola query.

        ``ROW_NUMBER`` sobre ``started_at`` desc particionado por activo:
        así la rejilla de agentes de Themis (Fase I) recibe el contador de
        hallazgos de cada tarjeta sin un request por tarjeta, que es justo
        lo que ``GET /hygeia/assets`` ahorra con esto. La función de ventana
        es portable entre Postgres y el SQLite de los tests (≥ 3.25).

        Args:
            user_id:   Dueño de los escaneos.
            asset_ids: Activos cuyos últimos escaneos se quieren; vacío
                devuelve lista vacía sin tocar la base de datos.

        Returns:
            Lista con, a lo sumo, un :class:`LybraScan` por activo.
        """
        if not asset_ids:
            return []

        row_number = func.row_number().over(
            partition_by=LybraScan.asset_id,
            order_by=LybraScan.started_at.desc(),
        ).label("_rn")
        ranked = (
            self._session.query(LybraScan, row_number)
            .filter(
                LybraScan.user_id == user_id,
                LybraScan.asset_id.in_(asset_ids),
            )
            .subquery()
        )
        return (
            self._session.query(LybraScan)
            .join(ranked, LybraScan.id == ranked.c.id)
            .filter(ranked.c._rn == 1)
            .all()
        )

    def count_findings_by_scan(self, scan_ids: List[int]) -> Dict[int, int]:
        """Número de hallazgos por escaneo, en una sola query agrupada.

        Complementa a :meth:`get_latest_scan_by_asset`: el contador que
        pinta la tarjeta de un agente es el ``totalFindings`` de su último
        análisis, y calcularlo fila a fila serían N consultas en lugar de
        una.

        Args:
            scan_ids: Escaneos cuyo recuento de hallazgos se quiere.

        Returns:
            Dict ``{scan_id: count}``; los escaneos sin hallazgos pueden
            faltar, que es lo mismo que un cero.
        """
        if not scan_ids:
            return {}
        rows = (
            self._session.query(Finding.scan_id, func.count(Finding.id))
            .filter(Finding.scan_id.in_(scan_ids))
            .group_by(Finding.scan_id)
            .all()
        )
        return {scan_id: count for scan_id, count in rows}

    def get_stats(self, user_id: int) -> dict:
        """
        Return scan counts grouped by type for a user.

        Returns:
            Dict with keys ``total``, ``nmap``, ``nikto``, ``lybra``, ``nuclei``.
        """
        from sqlalchemy import func

        results = (
            self._session.query(Scan.scan_type, func.count(Scan.id))
            .filter(Scan.user_id == user_id)
            .group_by(Scan.scan_type)
            .all()
        )
        counts = {scan_type.value: 0 for scan_type in ScanType}
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

    def update_status(
        self,
        scan: Scan,
        status: ScanStatus,
        failure_reason: Optional[ScanFailureReason] = None,
    ) -> Scan:
        """Persiste el estado y, cuando es un fallo, por qué falló.

        El motivo sólo se escribe con ``status`` FAILED: en cualquier otra
        transición sería un dato que contradice al estado. Y se limpia al salir
        de FAILED —un escaneo relanzado no arrastra el motivo del intento
        anterior— porque la única lectura del campo es «por qué falló este
        escaneo», y un residuo la respondería con una mentira.
        """
        scan.status = status.value # type: ignore
        scan.failure_reason = (  # type: ignore
            failure_reason.value if status is ScanStatus.FAILED and failure_reason else None
        )

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
            .where(Scan.id == scan_id, Scan.status.in_([expected_status.value for expected_status in expected]))
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

    def get_or_create_nikto_incident(self, incident_data: dict) -> NiktoIncident:
        """Get or create a NiktoIncident row by its unique fields."""
        existing = self._session.query(NiktoIncident).filter(
            NiktoIncident.description == incident_data["description"],
            NiktoIncident.url         == incident_data["url"],
            NiktoIncident.method      == incident_data["method"],
        ).first()

        if existing:
            return existing

        incident = NiktoIncident(
            description = incident_data["description"],
            osvdb_id    = incident_data["osvdb_id"],
            method      = incident_data["method"],
            url         = incident_data["url"],
            severity    = incident_data["severity"],
        )
        self._session.add(incident)
        self._session.flush()
        return incident

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
        for incident_data in incidents_data:
            incident = self.get_or_create_nikto_incident(incident_data)
            if incident not in scan.incidents:
                scan.incidents.append(incident)

        scan.host = host

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

    def persist_findings(self, scan: Scan, findings_data: List[dict],
                         evidence_max_body: int = 8192) -> None:
        """Persist a batch of normalized Finding rows for a scan.

        Un finding puede traer una clave ``_evidence`` —la respuesta cruda que
        lo provocó, que el runtime de checks adjuntó (Fase E)—. No es una
        columna, así que se extrae antes de construir el ``Finding``, y se
        persiste como una fila ``FindingEvidence`` aparte, ya redactada y
        hasheada, una vez que el ``Finding`` tiene id.

        Args:
            scan: The scan that produced the findings (its id is used as scan_id).
            findings_data: List of dicts with Finding column values.
            evidence_max_body: Tope del cuerpo de la evidencia, en bytes.
        """
        for data in findings_data:
            evidence = data.pop("_evidence", None)
            # Las claves con guion bajo son de trabajo, no columnas: las etapas
            # de la tubería se pasan datos por ahí (la evidencia cruda, la
            # versión instalada que necesita la verificación de backports) y
            # ninguna sobrevive a la fila.
            data = {key: value for key, value in data.items() if not key.startswith("_")}
            finding = Finding(scan_id=scan.id, **data)
            self._session.add(finding)
            if evidence:
                self._session.flush()          # necesita el id del finding
                prepared = prepare_evidence(evidence["payload"], evidence_max_body)
                self._session.add(FindingEvidence(
                    finding_id=finding.id,
                    kind=evidence["kind"],
                    payload=prepared["payload"],
                    content_hash=prepared["content_hash"],
                    captured_at=utcnow_naive(),
                ))

    def get_findings_by_state(self, user_id: int, state: str) -> List[Finding]:
        """Los hallazgos de un usuario en un estado concreto, el más nuevo primero.

        Se une contra ``Scan`` porque la propiedad vive ahí: un ``Finding`` no
        tiene dueño propio, lo hereda del escaneo que lo produjo.
        """
        return (
            self._session.query(Finding)
            .join(Scan, Finding.scan_id == Scan.id)
            .filter(Scan.user_id == user_id, Finding.state == state)
            .order_by(Finding.state_set_at.desc().nullslast())
            .all()
        )

    def get_evidence_for_finding(self, finding_id: int) -> List[FindingEvidence]:
        """Return the evidence rows backing a finding, newest first."""
        return (
            self._session.query(FindingEvidence)
            .filter(FindingEvidence.finding_id == finding_id)
            .order_by(FindingEvidence.captured_at.desc())
            .all()
        )

    def delete_expired_evidence(self, retention_days: int) -> int:
        """Borra la evidencia más vieja que ``retention_days``.

        La evidencia crece rápido —hasta varios KiB por hallazgo confirmado, por
        escaneo, por activo— y necesita caducidad desde el primer día, no cuando
        la tabla ocupe gigas. Un valor 0 o negativo desactiva la purga (retención
        indefinida), para el caso de auditoría que exige conservarlo todo.

        Args:
            retention_days: Días que se conserva la evidencia.

        Returns:
            El número de filas borradas.
        """
        if retention_days <= 0:
            return 0
        cutoff = utcnow_naive() - timedelta(days=retention_days)
        deleted = (
            self._session.query(FindingEvidence)
            .filter(FindingEvidence.captured_at < cutoff)
            .delete(synchronize_session=False)
        )
        return deleted

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

    def get_previous_findings(
        self, user_id: int, target: str, scan_type: str, exclude_scan_id: int
    ) -> List[Finding]:
        """Return the findings of the user's previous finished scan of a given
        type against a target (for lifecycle comparison), or an empty list if
        there is none. Generic over ``scan_type`` — the version any scanner's
        manager (Lybra, Nuclei, ...) can share instead of each hand-rolling its
        own "find the previous scan" query.
        """
        prev = (
            self._session.query(Scan)
            .filter(
                Scan.user_id == user_id,
                Scan.target == target,
                Scan.scan_type == scan_type,
                Scan.status == ScanStatus.FINISHED.value,
                Scan.id != exclude_scan_id,
            )
            .order_by(Scan.started_at.desc())
            .first()
        )
        return self.get_findings_by_scan(prev.id) if prev else []

    def set_feed_version_for_scan(self, scan_id: int, feed_version: str) -> None:
        """Bulk-update every Finding's ``feed_version`` for a scan.

        Used by ``NucleiScanManager`` to correct the reproducibility marker
        after the fact: findings are persisted with a config-level fallback
        during ``_persist_scan_results`` (before the live ``templates_version``
        banner from the running binary is captured), then patched here once
        the outer ``_execute_scan`` override has it — the same
        persist-now/patch-post-hoc shape any scanner uses when a value is
        only known after the subprocess has already produced its output.
        """
        self._session.query(Finding).filter(Finding.scan_id == scan_id).update(
            {"feed_version": feed_version}
        )

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


class ThemisReportRepository(DocumentRepository[ThemisDocument]):
    """
    Repository for the ThemisDocument entity (PDF reports).

    Las tres consultas de documentos (``get_latest_document``,
    ``get_documents_by_user``, ``get_documents_by_parent``) las aporta
    ``DocumentRepository`` (A9).

    Example:
    >>> with UnitOfWork() as uow:
    ...     repo = ThemisReportRepository(uow)
    ...     doc  = repo.get_by_id(1)
    ...     repo.delete(doc)
    """

    _MODEL = ThemisDocument
    _PARENT_FK = "scan_id"


class ScanFolderRepository(BaseRepository[ScanFolder]):
    """
    Repository for the ScanFolder entity.

    Manages user-created folders that group security scans. A scan can belong
    to at most one folder; deleting a folder leaves its scans unassigned.

    Attributes:
        _model:  ScanFolder (inherited from BaseRepository).
        _uow:    Active Unit of Work (inherited from BaseRepository).
    """

    _MODEL = ScanFolder

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

    _MODEL = Traceroute

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

    _MODEL = CveEntry

    # =========================================================================
    # MATCHER QUERY
    # =========================================================================

    def cves_for_cpe(self, vendor: str, product: str, version: str) -> List[CveEntry]:
        """Return the CVEs affecting ``vendor:product`` at ``version``.

        Filters candidate applicability rows by (vendor, product) in SQL, then
        applies the version-range logic in Python (see ``lybra.kb``). Results
        are de-duplicated by CVE — a CVE can have several ``CpeMatch`` rows for
        the same product (different ranges, some OS-gated and some not); when
        that happens the *least* restrictive rule wins, since an unconditional
        applicability rule proves the CVE genuinely applies here regardless of
        any other, narrower rule that also happens to match.

        Each returned ``CveEntry`` carries a transient ``required_os``
        attribute (not a mapped column — set on this query's result objects
        only) telling the caller which platform, if any, every contributing
        match required. ``None`` means unconditional.
        """
        from .lybra import version_in_range

        candidates = (
            self._session.query(CpeMatch)
            .filter(CpeMatch.vendor == vendor, CpeMatch.product == product)
            .options(joinedload(CpeMatch.cve))
            .all()
        )
        order: List[int] = []
        entries: Dict[int, CveEntry] = {}
        required_os: Dict[int, Optional[str]] = {}
        for match in candidates:
            if not version_in_range(version, match):
                continue
            cve_id = match.cve_id
            if cve_id not in entries:
                order.append(cve_id)
                entries[cve_id] = match.cve
                required_os[cve_id] = match.required_os
            elif required_os[cve_id] and not match.required_os:
                required_os[cve_id] = None
        result: List[CveEntry] = []
        for cve_id in order:
            entry = entries[cve_id]
            entry.required_os = required_os[cve_id]  # type: ignore[attr-defined]
            result.append(entry)
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

    def kev_ids_in(self, cve_ids: List[str]) -> set:
        """Which of ``cve_ids`` are in CISA's Known Exploited Vulnerabilities.

        Batch counterpart to :meth:`get_kev`, which costs one query per CVE —
        fine for the matcher (a handful of findings per host), wasteful for a
        discovery query that starts from dozens of CVEs at once.
        """
        if not cve_ids:
            return set()
        rows = (
            self._session.query(KevEntry.cve_id)
            .filter(KevEntry.cve_id.in_(cve_ids))
            .all()
        )
        return {row[0] for row in rows}

    def epss_scores_for(self, cve_ids: List[str]) -> dict:
        """EPSS exploitation-probability scores for ``cve_ids``, keyed by id.

        Batch counterpart to :meth:`get_epss` — see :meth:`kev_ids_in`.
        """
        if not cve_ids:
            return {}
        rows = (
            self._session.query(EpssScore.cve_id, EpssScore.score)
            .filter(EpssScore.cve_id.in_(cve_ids))
            .all()
        )
        return {cve_id: score for cve_id, score in rows}

    # =========================================================================
    # DISCOVERY QUERIES
    # =========================================================================
    #
    # Distintas de ``cves_for_cpe`` a propósito, y no una generalización suya.
    #
    # El matcher responde "¿ESTE host, con ESTA versión, es vulnerable?", y por
    # eso exige versión y descarta las reglas de aplicabilidad sin límites (ver
    # ``lybra.kb.version_in_range``: honrarlas producía 695 CVEs para un Edge al
    # día). Las consultas de aquí abajo responden otra pregunta —"¿qué ha sido
    # notable en este producto últimamente?"— para alimentar contenido de
    # concienciación, no un hallazgo contra un activo concreto. Ahí no hay
    # versión que comprobar y una regla sin límites es información válida, así
    # que mezclar ambos caminos rompería uno de los dos.

    def recent_cves_for_products(
        self,
        products: List[Tuple[str, str]],
        since: datetime,
        min_cvss: Optional[float] = None,
        limit_per_product: int = 5,
    ) -> List[Tuple[str, str, CveEntry]]:
        """Recent CVEs published against any of ``products``.

        Args:
            products: ``(vendor, product)`` CPE coordinates to look up.
            since: Only CVEs published at or after this instant.
            min_cvss: Optional CVSS floor; rows with no score are kept, since
                a missing score means "not yet analysed", not "harmless".
            limit_per_product: Newest N per product, so one noisy product
                cannot crowd out the rest.

        Returns:
            ``(vendor, product, cve)`` triples, newest first per product.
        """
        if not products:
            return []

        results: List[Tuple[str, str, CveEntry]] = []
        for vendor, product in products:
            query = (
                self._session.query(CveEntry)
                .join(CpeMatch, CpeMatch.cve_id == CveEntry.id)
                .filter(CpeMatch.vendor == vendor, CpeMatch.product == product)
                .filter(CveEntry.published.isnot(None), CveEntry.published >= since)
            )
            if min_cvss is not None:
                query = query.filter(
                    or_(CveEntry.cvss_score.is_(None), CveEntry.cvss_score >= min_cvss)
                )
            rows = (
                query.order_by(CveEntry.published.desc())
                .distinct()
                .limit(limit_per_product)
                .all()
            )
            results.extend((vendor, product, cve) for cve in rows)
        return results

    def search_products(self, term: str, limit: int = 20) -> List[Tuple[str, str, str]]:
        """Search the CPE product index for a human-facing picker.

        Runs over ``CpeProductAlias`` rather than ``CpeMatch``: it is already
        the small, indexed, nightly-rebuilt set of products that have at least
        one CVE, which is exactly what deserves to be offered. Prefix match so
        the unique index on ``normalized_name`` can serve it.

        Note this index drops names that map to more than one ``(vendor,
        product)`` pair — necessary when the machine resolves a name on its
        own (see :meth:`rebuild_cpe_product_index`), and harmless here because
        the vendor-qualified key ("microsoft edge") survives even when the bare
        one ("edge") does not.

        Returns:
            ``(vendor, product, display_name)`` triples, alphabetically.
        """
        term = (term or "").strip().lower()
        if not term:
            return []
        rows = (
            self._session.query(
                CpeProductAlias.vendor,
                CpeProductAlias.product,
                CpeProductAlias.normalized_name,
            )
            .filter(CpeProductAlias.normalized_name.like(f"{term}%"))
            .order_by(CpeProductAlias.normalized_name)
            .limit(limit)
            .all()
        )
        return [(vendor, product, name) for vendor, product, name in rows]

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

    def knowledge_state(self) -> dict:
        """The newest date each KB source carries, as the mirror stands right now.

        This is what makes a finding reproducible: two scans of the same target
        can disagree because the target changed **or** because the knowledge
        base learned something in between, and without this there is no way to
        tell those two apart after the fact.

        Read from the data itself rather than from a sync log, because there is
        no sync log. These dates are the closest honest proxy: not "when did we last
        ask NVD", but "how recent is the newest thing we know". A source with
        no rows, or whose rows carry no date, reports ``None``, which is
        information too and must not be dressed up as a date.

        Returns:
            ``{"nvd": datetime | None, "kev": ..., "epss": ...}``.
        """
        return {
            "nvd":  self._session.query(func.max(CveEntry.last_modified)).scalar(),
            "kev":  self._session.query(func.max(KevEntry.date_added)).scalar(),
            "epss": self._session.query(func.max(EpssScore.scored_at)).scalar(),
        }

    def record_sync(self, source: str, rows_upserted: Optional[int] = None,
                    error: Optional[str] = None) -> None:
        """Anotar el desenlace de un intento de sincronización de una fuente.

        Se llama **siempre**, salga bien o mal: el caso que importa es el malo,
        porque una sincronización rota no deja ningún otro rastro consultable y
        los escaneos siguen saliendo en verde contra un catálogo congelado.

        ``last_success_at`` se conserva cuando el intento falla — la distancia
        entre él y ``last_attempt_at`` es exactamente "cuánto lleva roto", y
        pisarlo destruiría el único dato que responde a esa pregunta. Al revés,
        ``error`` sí se limpia al tener éxito: la tabla dice si está bien
        *ahora*, no lo que pasó alguna vez.

        Args:
            source: ``"nvd"``, ``"kev"`` o ``"epss"``.
            rows_upserted: Filas escritas, en un intento con éxito.
            error: El mensaje del fallo. Su presencia es lo que distingue un
                intento fallido de uno correcto.
        """
        now = utcnow_naive()
        row = self._session.query(KbSyncStatus).filter_by(source=source).one_or_none()
        if row is None:
            row = KbSyncStatus(source=source)
            self._session.add(row)
        row.last_attempt_at = now
        if error is None:
            row.last_success_at = now
            row.rows_upserted = rows_upserted
            row.error = None
        else:
            # El mensaje se acota: un traceback entero o el cuerpo de una
            # respuesta HTTP no aportan más que su primera línea en una tabla
            # de estado, y el detalle completo ya está en el log.
            row.error = error[:500]

    def sync_status(self) -> List[KbSyncStatus]:
        """El estado de sincronización de todas las fuentes registradas."""
        return self._session.query(KbSyncStatus).order_by(KbSyncStatus.source).all()

    def upsert_distro_pkg_status(self, row: dict) -> None:
        """Guardar lo que un proveedor dice de un paquete frente a una CVE."""
        if not row.get("package") or not row.get("cve_id"):
            return
        existing = (self._session.query(DistroPkgStatus).filter_by(
            vendor=row["vendor"], release=row.get("release"),
            package=row["package"], cve_id=row["cve_id"]).one_or_none())
        if existing is None:
            self._session.add(DistroPkgStatus(**row))
            return
        existing.fixed_in = row.get("fixed_in")
        existing.status = row.get("status", "unknown")

    def upsert_distro_advisory(self, row: dict) -> None:
        """Guardar la cabecera de un aviso de distribución (DSA, USN, RHSA…)."""
        existing = (self._session.query(DistroAdvisory)
                    .filter_by(advisory_id=row["advisory_id"]).one_or_none())
        if existing is None:
            self._session.add(DistroAdvisory(**row))
            return
        for field_name, value in row.items():
            setattr(existing, field_name, value)

    def distro_package_status(self, vendor: str, release: Optional[str],
                              package: str, cve_id: str) -> Optional[tuple]:
        """Qué dice el proveedor sobre este paquete y esta CVE.

        Un aviso sin ``release`` aplica a todas las versiones de la
        distribución, así que sirve también cuando se pregunta por una
        concreta; el que sí la nombra manda sobre él. De ahí el orden: primero
        se busca la respuesta específica y sólo después la genérica.

        Returns:
            ``(status, fixed_in)``, o ``None`` si el proveedor no se ha
            pronunciado — que no es lo mismo que decir que está a salvo, y por
            eso el llamante no toca el hallazgo en ese caso.
        """
        query = (self._session.query(DistroPkgStatus)
                 .filter(DistroPkgStatus.vendor == vendor,
                         DistroPkgStatus.package == package,
                         DistroPkgStatus.cve_id == cve_id))
        rows = query.all()
        if not rows:
            return None
        specific = [row for row in rows if release and row.release == release]
        generic = [row for row in rows if row.release is None]
        chosen = (specific or generic or None)
        if not chosen:
            return None
        return chosen[0].status, chosen[0].fixed_in

    def exploit_evidence(self, cve_id: str) -> Optional[str]:
        """Qué madurez de explotación consta para una CVE, sin contar KEV (L34).

        Hoy sólo puede decir ``"poc"``: la señal disponible es la referencia
        que la propia NVD etiqueta como exploit, y esa etiqueta afirma que
        alguien publicó algo que demuestra el fallo, no cuán usable es. Subirla
        a ``functional`` sería inventar precisión que el dato no tiene.

        KEV no se mira aquí a propósito: el motor ya lo consulta por su cuenta
        y es la evidencia más fuerte, así que la combinación de ambas vive en
        :func:`~lybra.correlation.exploit_maturity` y no repartida entre dos
        capas.
        """
        entry = (self._session.query(CveEntry)
                 .filter(CveEntry.cve_id == cve_id).one_or_none())
        return "poc" if entry is not None and entry.has_exploit_reference else None

    def record_resolution(self, normalized_name: str, origin: str, was_resolved: bool) -> None:
        """Llevar la cuenta de un nombre de producto que no resuelve a un CPE.

        Cuando falla, suma uno a su contador; **cuando resuelve, borra la fila**.
        Esa segunda mitad es la que cierra el bucle que pedía L37: al escribir
        el alias que faltaba, el nombre desaparece del ranking en el siguiente
        escaneo. Sin ella el ranking mediría el trabajo que hubo, no el que
        queda, y no habría forma de saber si el feed está mejorando.
        """
        row = (self._session.query(UnresolvedProduct)
               .filter_by(normalized_name=normalized_name, origin=origin)
               .one_or_none())
        if was_resolved:
            if row is not None:
                self._session.delete(row)
            return

        now = utcnow_naive()
        if row is None:
            self._session.add(UnresolvedProduct(
                normalized_name=normalized_name, origin=origin,
                occurrences=1, first_seen_at=now, last_seen_at=now,
            ))
        else:
            row.occurrences = (row.occurrences or 0) + 1
            row.last_seen_at = now

    def top_unresolved_products(self, limit: int = 50,
                                origin: Optional[str] = None) -> List[UnresolvedProduct]:
        """Los nombres que más veces han quedado sin resolver, el peor primero."""
        query = self._session.query(UnresolvedProduct)
        if origin:
            query = query.filter(UnresolvedProduct.origin == origin)
        return (query.order_by(UnresolvedProduct.occurrences.desc(),
                               UnresolvedProduct.normalized_name.asc())
                .limit(limit).all())

    def counts(self) -> dict:
        """Row counts per KB table (for the sync summary / health checks)."""
        return {
            "cves": self._session.query(CveEntry).count(),
            "cpeMatches": self._session.query(CpeMatch).count(),
            "kev": self._session.query(KevEntry).count(),
            "epss": self._session.query(EpssScore).count(),
            "distroPkgStatus": self._session.query(DistroPkgStatus).count(),
        }

    def has_content(self) -> dict:
        """Si cada fuente de la KB tiene algo dentro, por nombre de fuente.

        Responde a una pregunta distinta de :meth:`knowledge_state` y de
        :meth:`sync_status`, y las tres hacen falta para no confundir tres
        situaciones que se parecen: *cuán reciente es lo que sabemos*, *cuándo
        lo preguntamos y funcionó*, y *si sabemos algo en absoluto*.

        La tercera es la que evita el falso positivo del día del despliegue:
        ``KbSyncStatus`` nace vacía en cada instalación, así que "nunca
        sincronizada" es cierto para todas las fuentes aunque el espejo tenga
        350.000 CVEs dentro. Sin este recuento, el aviso de frescura le grita a
        todo el mundo la primera semana — y un aviso que sale mal el primer día
        enseña a ignorar los avisos.

        Las claves son las de ``features.themis.kb.sources``, no las de las
        tablas, porque quien pregunta razona en fuentes.
        """
        totals = self.counts()
        return {
            "nvd": totals["cves"] > 0,
            "kev": totals["kev"] > 0,
            "epss": totals["epss"] > 0,
            "oval": totals["distroPkgStatus"] > 0,
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

    _MODEL = ProgramedScan

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
            scan_type:  Scan type discriminator ("nmap", "nikto", "lybra", "nuclei").

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
        programed_scan: ProgramedScan,
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
        programed_scan.last_run_at = last_run  # type: ignore
        programed_scan.next_run_at = next_run  # type: ignore
        return self.update(programed_scan)

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
            scan_type:       Scan discriminator ("nmap", "nikto", "lybra", "nuclei").
            arguments:       Scan parameters (e.g. {"ports": "22,80"}).
            schedule_type:   "interval" or "cron".
            schedule_config: Schedule definition (e.g. {"every": 60, "unit": "minutes"}).
            next_run_at:     First planned execution time (computed by the caller
                             via Scheduler.calculate_next_run).

        Returns:
            The newly persisted ProgramedScan instance.
        """
        programed_scan = ProgramedScan(
            user_id=user_id,
            scan_type=scan_type,
            arguments=arguments,
            schedule_type=schedule_type,
            schedule_config=schedule_config,
            next_run_at=next_run_at,
        )
        return self.save(programed_scan)


class AuthorizedTargetRepository(BaseRepository[AuthorizedTarget]):
    """Repository for the AuthorizedTarget entity (roadmap §6 register)."""

    _MODEL = AuthorizedTarget

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