"""
Database models for Themis security scanning module.

This module contains SQLAlchemy models for vulnerability scanning including:
- Network hosts and port management
- Scan base class with polymorphic inheritance
- Nmap and Nikto scan implementations
- Vulnerability and result tracking
- Scan document generation

Classes:
    Host: Network host entity for scan targets.
    Scan: Base class for all scan types (polymorphic).
    Port: Network port definition.
    NmapScan: Nmap network scanning results.
    OpenPort: Open port discovered during Nmap scan.
    NiktoScan: Nikto web vulnerability scan results.
    NiktoIncident: Individual Nikto finding.
    ThemisDocument: Generated PDF report from scan.

Example:
    >>> from src.modules.features.themis.model import Scan, NmapScan
    >>> scan = NmapScan(target="192.168.1.1", user_id=1)
    >>> print(scan)
    NmapScan(id=None, target='192.168.1.1', puertos_abiertos=0, inicio=N/A)
"""

from enum import Enum

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Table,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship

from src.modules.shared import Base, Document, utcnow_naive


# =========================================================================
# ASSOCIATION TABLES
# =========================================================================

TargetPort = Table(
    "TargetPort",
    Base.metadata,
    Column("port_id",      Integer, ForeignKey("Port.id"),    primary_key=True),
    Column("nmap_scan_id", Integer, ForeignKey("NmapScan.id"), primary_key=True),
)

ScanIncident = Table(
    "ScanIncident",
    Base.metadata,
    Column("nikto_scan_id",     Integer, ForeignKey("NiktoScan.id"),     primary_key=True),
    Column("nikto_incident_id", Integer, ForeignKey("NiktoIncident.id"), primary_key=True),
)

# =========================================================================
# ENUMS
# =========================================================================

class ScanStatus(Enum):
    """
    Enumeration of possible scan execution states.

    Attributes:
        PENDING: Scan created but not yet started.
        RUNNING: Scan is currently executing.
        FINISHED: Scan completed successfully.
        FAILED: Scan encountered an error.
        CANCELLED: Scan was cancelled by user.
    """
    PENDING   = "pending"
    RUNNING   = "running"
    FINISHED  = "finished"
    FAILED    = "failed"
    CANCELLED = "cancelled"

class ScanType(str, Enum):
    """
    Enumeration of supported scan tool types.

    Inherits from str so that ScanType.NMAP == "nmap" is True,
    making it directly compatible with SQLAlchemy's polymorphic_identity
    and with any existing string comparisons.

    Attributes:
        NMAP:    Nmap network and port scanner.
        NIKTO:   Nikto web server vulnerability scanner.
        LYBRA: Lybra's own vulnerability engine (native detection).
        NUCLEI: Nuclei template-based vulnerability scanner (Fase U1).

    OpenVAS was removed (roadmap §7/§6.3, Ronda 2 — E1): it was a whole
    platform we could never add anything on top of, not a tool whose output
    we parsed like the others (see the roadmap's §1). Historical ``Finding``
    rows with ``source="openvas"`` are kept as provenance; nothing produces
    new ones.
    """
    NMAP    = "nmap"
    NIKTO   = "nikto"
    LYBRA = "lybra"
    NUCLEI = "nuclei"


# =========================================================================
# HOST MODEL
# =========================================================================

class Host(Base):
    """
    Network host entity representing a target for security scans.

    Stores host identification information including hostname, IP address,
    MAC address, and vendor information from ARP/Network scans.

    Attributes:
        id: Primary key, auto-incrementing integer.
        hostname: Unique hostname (max 64 characters).
        ip_address: IPv4/IPv6 address (max 15 characters).
        mac_address: MAC address (max 17 characters).
        vendor: Device vendor from MAC OUI lookup (max 64 characters).

    Relationships:
        scans: List of Scan objects targeting this host.
    """
    __tablename__ = "Host"

    id          = Column(Integer,    primary_key=True, autoincrement=True)
    hostname    = Column(String(64), unique=True, nullable=False)
    ip_address  = Column(String(15), nullable=False)
    mac_address = Column(String(17), nullable=False)
    vendor      = Column(String(64))

    scans = relationship("Scan", back_populates="host", cascade="all, delete-orphan")


# =========================================================================
# HOST SERVICE (Lybra Fase 5 — the asset's attack surface, tracked over time)
# =========================================================================

class HostService(Base):
    """A service Lybra has observed open on a host, tracked across scans.

    Roadmap Fase 5's "cambio de sujeto": a ``Scan`` is one observation of a
    host's attack surface at a point in time, not the surface itself. This
    table is that surface — one row per ``(host, port, protocol)`` — so a new
    scan can be diffed against it to notice a port opening for the first time
    or a service's version changing, independently of whether that change
    happens to also match a known CVE. Findings answer "is this vulnerable?";
    this table answers "did the surface itself change?".

    Populated by every Lybra scan of a target, whether its services came from
    self-discovery or from a prior Nmap scan's already-collected ports — both
    paths resolve the same ``Service`` shape before this table sees it. Only
    Lybra writes here today; it is not yet a fusion of every scanner's view.

    Attributes:
        id: Primary key.
        host_id: The asset this service belongs to.
        port: The port number, or ``None`` for a portless, ``origin="inventory"``
            service (Fase 0.9) — an installed package has nothing listening.
        protocol: ``"tcp"`` or ``"udp"``.
        name: The service's conventional name (``"http"``, ``"ssh"``...).
        product: The identified product, or ``None`` if never resolved.
        version: The identified version, or ``None``.
        cpe: The CPE last resolved for this service, or ``None``.
        first_seen_at: When this port was first observed open.
        last_seen_at: When this port was last observed open (bumped every scan
            that still finds it open — a stale row implies the port closed).
    """
    __tablename__ = "HostService"
    __table_args__ = (
        UniqueConstraint("host_id", "port", "protocol", name="uq_host_service_host_port_protocol"),
    )

    id            = Column(Integer, primary_key=True, autoincrement=True)
    host_id       = Column(Integer, ForeignKey("Host.id", ondelete="CASCADE"), nullable=False, index=True)
    port          = Column(Integer, nullable=True)
    protocol      = Column(String(8), nullable=False, default="tcp")
    name          = Column(String(64), nullable=True)
    product       = Column(String(128), nullable=True)
    version       = Column(String(64), nullable=True)
    cpe           = Column(String(255), nullable=True)
    first_seen_at = Column(DateTime, nullable=False, default=utcnow_naive)
    last_seen_at  = Column(DateTime, nullable=False, default=utcnow_naive)


# =========================================================================
# TRACEROUTE
# =========================================================================

class Traceroute(Base):
    """
    Cached network path (traceroute) from the Ellysia server to a scan target.

    The hops are a property of the *route to the destination*, not of any
    individual scan, and change slowly over time. We therefore cache one row
    per (user, target) and reuse it across all scan types instead of
    re-running the traceroute on every scan. ``created_at`` drives cache
    invalidation (see ``TracerouteManager``).

    Attributes:
        id: Primary key, auto-incrementing integer.
        user_id: Owner user foreign key (scopes the cache per user).
        target: The scan target string (IP or domain), the cache key.
        hops: Ordered list of hops as JSONB. Each hop is a dict:
            ``{"ttl": int, "ip": str|None, "hostname": str|None, "rtt_ms": float|None}``.
            A hop with ``ip == None`` represents a non-responding (timed-out) hop.
        hop_count: Number of hops stored (denormalized for convenience).
        created_at: Timestamp the traceroute was computed (cache TTL anchor).
        updated_at: Last refresh timestamp (automatic).

    Table Constraints:
        Unique constraint on (user_id, target) so each target has a single
        cached path per user (upserted on refresh).
    """

    __tablename__ = "Traceroute"

    id         = Column(Integer,     primary_key=True, autoincrement=True)
    user_id    = Column(Integer,     ForeignKey("User.id"), nullable=False, index=True)
    target     = Column(String(255), nullable=False, index=True)
    hops       = Column(JSONB,       nullable=False)
    hop_count  = Column(Integer,     nullable=False, default=0)
    created_at = Column(DateTime,    nullable=False, default=utcnow_naive)
    updated_at = Column(DateTime,    nullable=False, default=utcnow_naive, onupdate=utcnow_naive)

    __table_args__ = (
        UniqueConstraint("user_id", "target", name="unique_user_target_trace"),
    )

    def __repr__(self) -> str:
        return f"<Traceroute(id={self.id}, target='{self.target}', hops={self.hop_count})>"


# =========================================================================
# SCAN FOLDER
# =========================================================================

class ScanFolder(Base):
    """
    Logical grouping of scans created by a user.

    A scan may belong to zero or one folder. Deleting a folder leaves its
    scans orphaned (folder_id becomes NULL) so they appear in the default
    virtual folder.

    Attributes:
        id: Primary key, auto-incrementing integer.
        user_id: Owner user foreign key.
        name: Folder name (max 255 characters).
        created_at: Creation timestamp (automatic).
        updated_at: Last update timestamp (automatic).

    Relationships:
        scans: Scan objects contained in this folder.
    """

    __tablename__ = "ScanFolder"

    id         = Column(Integer,    primary_key=True, autoincrement=True)
    user_id    = Column(Integer,    ForeignKey("User.id"), nullable=False)
    name       = Column(String(255), nullable=False)
    created_at = Column(DateTime,   nullable=False, default=utcnow_naive)
    updated_at = Column(DateTime,   nullable=False, default=utcnow_naive, onupdate=utcnow_naive)

    scans = relationship("Scan", back_populates="folder")

    def __repr__(self) -> str:
        return f"<ScanFolder(id={self.id}, name='{self.name}', user_id={self.user_id})>"


# =========================================================================
# SCAN BASE
# =========================================================================

class Scan(Base):
    """
    Base class for all security scan types.

    Uses polymorphic inheritance to support different scan implementations
    (Nmap, Nikto, Lybra, Nuclei) while maintaining a common interface.

    Attributes:
        id: Primary key, auto-incrementing integer.
        target: Scan target (IP or domain, max 255 characters).
        started_at: Scan start timestamp (automatic).
        status: Current scan status (pending/running/finished/failed/cancelled).
        user_id: Foreign key to User.id (scan owner).
        scan_type: Polymorphic discriminator (nmap/nikto/lybra/nuclei). May
            still read "openvas" on a historical row — that scan type no
            longer runs, but old rows are not rewritten.
        frequent: Whether this is a scheduled/repeated scan.
        host_id: Optional foreign key to Host.
        finished_at: Scan completion timestamp (nullable).

    Relationships:
        user: User who initiated the scan.
        host: Target host if resolved.
        themis_document: Generated PDF report (one-to-one).

    Columnas:
        id (int): Identificador único del escaneo.
        target (str): Objetivo del escaneo (IP o dominio, máx. 255 caracteres).
        started_at (datetime): Fecha y hora de inicio del escaneo.
        user_id (int): ID del usuario que ejecuta el escaneo (clave foránea).
        scan_type (str): Tipo de escaneo (para discriminador polimórfico).
    """

    __tablename__ = "Scan"

    id          = Column(Integer,    primary_key=True, autoincrement=True)
    target      = Column(String(255), nullable=False)
    started_at  = Column(DateTime,   nullable=False, default=utcnow_naive)
    status      = Column(String(20), nullable=False, default=ScanStatus.PENDING.value)
    user_id     = Column(Integer,    ForeignKey("User.id"), nullable=False)
    scan_type   = Column(String(50))
    # Q13: "frecuent" era un typo de "frequent" — el atributo Python se
    # renombra sin migración (la columna real en BD sigue llamándose
    # "frecuent"; renombrar la columna es un cambio de esquema que no
    # compensa para un campo interno sin consumidores activos).
    frequent    = Column("frecuent", Boolean, nullable=False, default=True)
    host_id     = Column(Integer,    ForeignKey("Host.id"))
    finished_at = Column(DateTime,   nullable=True)

    user = relationship("User", back_populates="scans")
    host = relationship("Host", back_populates="scans")

    programed_scan_id = Column(Integer, ForeignKey("ProgramedScan.id"), nullable=True)
    programed_scan = relationship("ProgramedScan", back_populates="scans")

    folder_id = Column(Integer, ForeignKey("ScanFolder.id"), nullable=True)
    folder = relationship("ScanFolder", back_populates="scans")

    themis_document = relationship(
        "ThemisDocument",
        back_populates="scan",
        uselist=False,
    )

    # viewonly: Finding rows are written via ScanRepository.persist_findings
    # (plain inserts keyed by scan_id), never through this relationship. Read
    # side only, e.g. LybraMetricExtractor (history.py) counting a scan's
    # findings without a tool-specific query.
    findings = relationship("Finding", viewonly=True)

    __mapper_args__ = {
        "polymorphic_identity": "scan",
        "polymorphic_on":       scan_type,
    }

    def __str__(self):
        """
        Return a string representation of the Scan instance.

        Returns:
            String with id, type, target, and start time.
        """
        started = self.started_at.strftime("%Y-%m-%d %H:%M:%S") if self.started_at else "N/A" # type: ignore
        return f"Scan(id={self.id}, tipo='{self.scan_type}',\
            target='{self.target}', inicio={started})"

    def __repr__(self):
        """
        Return a debug representation of the Scan instance.

        Returns:
            String with id, type, and target.
        """
        return f"<Scan(id={self.id}, type='{self.scan_type}', target='{self.target}')>"


# =========================================================================
# PROGRAMED SCAN
# =========================================================================

class ProgramedScan(Base):
    __tablename__ = "ProgramedScan"

    id              = Column(Integer, primary_key=True)
    user_id         = Column(Integer, ForeignKey("User.id"), nullable=False)
    scan_type       = Column(String(20), nullable=False)  # "nmap" | "nikto" | "lybra" | "nuclei" (or historical "openvas")
    arguments       = Column(JSONB, nullable=False)       # {"ports": "22,80", "timeout": 300}

    # Schedule
    schedule_type    = Column(String(10), nullable=False)   # "interval" | "cron"
    schedule_config  = Column(JSONB, nullable=False)        # {"every": 60, "unit": "minutes"}
                                                             # o {"cron": "0 2 * * *"}
    # Estado
    is_active       = Column(Boolean, default=True)
    last_run_at     = Column(DateTime, nullable=True)
    next_run_at     = Column(DateTime, nullable=True)
    created_at      = Column(DateTime, default=utcnow_naive)

    # Relación
    scans = relationship("Scan", back_populates="programed_scan")
    user  = relationship("User")


# =========================================================================
# PORT MODELS
# =========================================================================

class Port(Base):
    """
    Network port definition for tracking scanned ports.

    Stores port protocol information and relationships to Nmap scans
    and discovered open ports.

    Attributes:
        id: Primary key, auto-incrementing integer.
        protocol: Port protocol (e.g., "tcp", "udp", max 255 characters).

    Relationships:
        nmap_target_scans: NmapScan objects targeting this port.
        open_port_entries: OpenPort entries where this port was found open.
    """
    __tablename__ = "Port"

    id       = Column(Integer,     primary_key=True, autoincrement=True)
    protocol = Column(String(255), unique=True, nullable=False)

    nmap_target_scans = relationship(
        "NmapScan",
        secondary=TargetPort,
        back_populates="target_ports",
        overlaps="target_ports",
    )
    open_port_entries = relationship(
        "OpenPort", back_populates="port", cascade="all, delete-orphan"
    )

    def __str__(self):
        """
        Return a string representation of the Port instance.

        Returns:
            String with id and protocol.
        """
        return f"Port(id={self.id}, protocol='{self.protocol}')"

    def __repr__(self):
        """
        Return a debug representation of the Port instance.

        Returns:
            String with id and protocol.
        """
        return f"<Port(id={self.id}, {self.protocol})>"


# =========================================================================
# NMAP MODELS
# =========================================================================

class NmapScan(Scan):
    """
    Nmap network scan results.

    Inherits from Scan and stores specific Nmap data including
    target ports and discovered open ports with service information.

    Attributes:
        id: Primary key (foreign key to Scan.id).
        target_ports: List of Port objects being scanned.
        open_ports_relation: List of OpenPort entries with scan results.

    Example:
        >>> scan = NmapScan(target="10.0.0.1", user_id=1)
        >>> print(scan)
        NmapScan(id=None, target='10.0.0.1', puertos_abiertos=0, inicio=N/A)
    """

    __tablename__ = "NmapScan"

    id = Column(Integer, ForeignKey("Scan.id"), primary_key=True)

    target_ports = relationship(
        "Port",
        secondary=TargetPort,
        back_populates="nmap_target_scans",
        overlaps="target_ports",
    )
    open_ports_relation = relationship(
        "OpenPort", back_populates="nmap_scan", cascade="all, delete-orphan"
    )

    __mapper_args__ = {"polymorphic_identity": ScanType.NMAP}

    def __str__(self):
        """
        Return a string representation of the NmapScan instance.

        Returns:
            String with id, target, open port count, and start time.
        """
        started   = self.started_at.strftime("%Y-%m-%d %H:%M:%S") if self.started_at else "N/A" # type: ignore
        num_ports = len(self.open_ports_relation) if self.open_ports_relation else 0
        return f"NmapScan(id={self.id}, target='{self.target}', puertos_abiertos={num_ports}, inicio={started})"

    def __repr__(self):
        """
        Return a debug representation of the NmapScan instance.

        Returns:
            String with id and target.
        """
        return f"<NmapScan(id={self.id}, target='{self.target}')>"


class OpenPort(Base):
    """
    Open port discovered during an Nmap scan.

    Stores the relationship between a port, an Nmap scan, and
    discovered service information.

    Attributes:
        port_id: Foreign key to Port.id (part of primary key).
        nmap_scan_id: Foreign key to NmapScan.id (part of primary key).
        reason: Reason port was determined to be open.
        product: Detected service product name.
        version: Detected service version.
        given_use: Nmap service detection result.
        cpe: Common Platform Enumeration string Nmap emits with ``-sV`` when it
            recognises the service (2.2 URI form, e.g.
            ``cpe:/a:apache:http_server:2.4.49``). Nullable: many services do
            not yield a CPE. It is the entry point the Lybra engine reads to
            correlate versions to CVEs (see the vuln-engine roadmap).

    Relationships:
        port: Port entity.
        nmap_scan: NmapScan that discovered this open port.
    """
    __tablename__ = "OpenPort"

    port_id      = Column(Integer, ForeignKey("Port.id"),    primary_key=True)
    nmap_scan_id = Column(Integer, ForeignKey("NmapScan.id"), primary_key=True)
    reason       = Column(String(255), nullable=False)
    product      = Column(String(255))
    version      = Column(String(64))
    given_use    = Column(String(255))
    cpe          = Column(String(255), nullable=True)

    port     = relationship("Port",     back_populates="open_port_entries")
    nmap_scan = relationship("NmapScan", back_populates="open_ports_relation")

    def __repr__(self):
        """
        Return a debug representation of the OpenPort instance.

        Returns:
            String with port_id and scan_id.
        """
        return f"<OpenPort(port_id={self.port_id}, scan_id={self.nmap_scan_id})>"


# =========================================================================
# NIKTO MODELS
# =========================================================================

class NiktoScan(Scan):
    """
    Nikto web vulnerability scan results.

    Inherits from Scan and stores Nikto-specific data including
    discovered web vulnerabilities/incidents.

    Attributes:
        id: Primary key (foreign key to Scan.id).
        incidents: List of NiktoIncident objects with findings.
    """
    __tablename__ = "NiktoScan"

    id = Column(Integer, ForeignKey("Scan.id"), primary_key=True)

    incidents = relationship(
        "NiktoIncident", secondary=ScanIncident, back_populates="nikto_scans"
    )

    __mapper_args__ = {"polymorphic_identity": ScanType.NIKTO}

    def __repr__(self):
        """
        Return a debug representation of the NiktoScan instance.

        Returns:
            String with id and target.
        """
        return f"<NiktoScan(id={self.id}, target='{self.target}')>"


class NiktoIncident(Base):
    """
    Individual vulnerability finding from a Nikto scan.

    Stores a single web vulnerability discovered during scanning,
    including OSVDB reference, affected URL, and severity.

    Attributes:
        id: Primary key, auto-incrementing integer.
        osvdb_id: OSVDB reference identifier.
        method: HTTP method used to discover (GET, POST, etc.).
        url: Affected URL path.
        description: Vulnerability description.
        severity: Severity level (INFO, LOW, MEDIUM, HIGH, CRITICAL).
        port: Target port number.
        references: Additional reference URLs.
        discovered_at: Discovery timestamp (automatic).

    Relationships:
        nikto_scans: NiktoScan objects containing this incident.
    """
    __tablename__ = "NiktoIncident"

    id           = Column(Integer,    primary_key=True, autoincrement=True)
    osvdb_id     = Column(String(20), nullable=True)
    method       = Column(String(10), nullable=True)
    url          = Column(String(512), nullable=False)
    description  = Column(Text,       nullable=False)
    severity     = Column(String(20), nullable=True)
    port         = Column(Integer,    nullable=True)
    references   = Column(Text,       nullable=True)
    discovered_at = Column(DateTime,  nullable=False, default=utcnow_naive)

    nikto_scans = relationship(
        "NiktoScan", secondary=ScanIncident, back_populates="incidents"
    )

    def __repr__(self):
        """
        Return a debug representation of the NiktoIncident instance.

        Returns:
            String with id, OSVDB id, and severity.
        """
        return f"<NiktoIncident(id={self.id}, osvdb='{self.osvdb_id}', severity='{self.severity}')>"


# OpenVAS's three native tables (OpenVASScan, OpenVASVulnerability,
# OpenVASScanResult) were removed here (roadmap §7/§6.3, Ronda 2 — E2+E3).
# The development database had zero rows in any of the three (verified by
# query before removing), so there was nothing to archive first — the
# backfill-then-drop the roadmap originally described was unnecessary.
# Finding rows with source="openvas" are unaffected: they live in the
# source-agnostic Finding table, not in these.


# =========================================================================
# LYBRA ENGINE MODELS
# =========================================================================

class LybraScan(Scan):
    """Scan produced by Lybra's own vulnerability engine.

    In the current phase (Fase 0) Lybra has no network transport of its own,
    so a scan takes its services from a previous Nmap scan of the same target
    (``source_scan_id``) and produces normalized :class:`Finding` rows. When the
    engine gains its own transport (Fase T) ``source_scan_id`` becomes optional.

    Attributes:
        id: Primary key (foreign key to Scan.id).
        source_scan_id: The Nmap Scan whose discovered services were analysed.
            Nullable so a future self-discovering scan can leave it empty.
        deep_scan_ids: Fase 6 "análisis profundo" — ids of the Nmap/Nikto/Nuclei
            corroborator scans launched alongside this one. Fire-and-forget:
            each is an ordinary, independently-tracked Scan; their Finding rows
            are merged in only at read time (see LybraEngineManager.format_scan),
            never copied into this scan's own Finding rows.
        asset_id: Fase I — the Hygeia MonitoredAsset whose software inventory
            originated this scan, or None when it was launched from the Themis
            panel. Deliberately a plain Integer with no ForeignKey: it is a
            soft reference that keeps Themis's *schema* independent of
            Hygeia's (no module under features/ depends on another today, and
            this column must not be what changes that). Cleanup when an asset
            is deleted is therefore explicit, in HygeiaAssetManager.delete_asset.
            Non-null also means "keep this out of the ordinary Lybra feed" —
            these scans are browsed per-agent instead.
    """
    __tablename__ = "LybraScan"

    id             = Column(Integer, ForeignKey("Scan.id"), primary_key=True)
    source_scan_id = Column(Integer, ForeignKey("Scan.id"), nullable=True)
    deep_scan_ids  = Column(JSONB, nullable=True)
    asset_id       = Column(Integer, nullable=True, index=True)

    __mapper_args__ = {
        "polymorphic_identity": ScanType.LYBRA,
        "inherit_condition":    id == Scan.id,
    }

    def __repr__(self):
        return f"<LybraScan(id={self.id}, target='{self.target}', source={self.source_scan_id})>"


class NucleiScan(Scan):
    """Scan launched via the Nuclei template-based scanner (roadmap Fase U1).

    Follows the same design ``LybraScan`` already established rather than the
    Nmap/Nikto one: no result table of its own. Nuclei's JSONL output
    maps almost 1:1 onto ``Finding`` (``cve_ids``, ``cvss_score``, ``check_id``
    all come straight from the tool), so building a parallel ``NucleiFinding``
    table would only recreate the scaffolding the roadmap's §7 dismantled
    for OpenVAS — not something to add fresh in a brand new scan type. Unlike
    ``LybraScan`` there is no second identifying column (no ``source_scan_id``
    equivalent), so no ``inherit_condition`` override is needed: SQLAlchemy
    resolves the join against ``Scan.id`` on its own.

    Attributes:
        id: Primary key (foreign key to Scan.id).
    """
    __tablename__ = "NucleiScan"

    id = Column(Integer, ForeignKey("Scan.id"), primary_key=True)

    __mapper_args__ = {"polymorphic_identity": ScanType.NUCLEI}

    def __repr__(self):
        return f"<NucleiScan(id={self.id}, target='{self.target}')>"


class AuthorizedTarget(Base):
    """A target (IP or CIDR) a user has declared authorized for Lybra's
    network-touching operations (roadmap §6): self-discovery (Fase T), own
    fingerprinting (Fase F) and the active check runtime (Fase R). Analysing
    services already known from a prior Nmap scan (Fase 1) does not need an
    entry here, since it sends no new packets to the target.

    Attributes:
        id: Primary key.
        user_id: Owner of this register entry.
        target: Canonical IP or CIDR string, e.g. "10.0.0.5/32" or "10.0.0.0/24".
        label: Optional free-text note (client name, authorization scope...).
        created_at: When the entry was added.
    """
    __tablename__ = "AuthorizedTarget"

    id         = Column(Integer, primary_key=True, autoincrement=True)
    user_id    = Column(Integer, ForeignKey("User.id"), nullable=False, index=True)
    target     = Column(String(64), nullable=False)
    label      = Column(String(255), nullable=True)
    created_at = Column(DateTime, nullable=False, default=utcnow_naive)

    __table_args__ = (
        UniqueConstraint("user_id", "target", name="uq_authorizedtarget_user_target"),
    )

    def __repr__(self):
        return f"<AuthorizedTarget(id={self.id}, target='{self.target}', user_id={self.user_id})>"


class Finding(Base):
    """Normalized security finding, independent of the scanner that produced it.

    The unified finding model that lets Lybra, Nikto, Nuclei and (historically)
    OpenVAS results live in one table and be correlated (dedup by
    ``dedup_key``). See the vuln-engine roadmap (§3.3) for the full design.
    In Fase 0 only informational
    "open port" findings are written (``category="open_port"``, ``qod=30``); the
    detection columns (``cve_ids``, ``cvss_score``…) stay empty until later
    phases fill them.

    Attributes:
        id: Primary key.
        scan_id: The Scan that produced this finding (any scan type).
        host_id: Host the finding refers to (nullable).
        title: Human-readable one-line description.
        category: Finding family ("open_port" | "outdated_software" | "tls" ...).
        port / service / cpe: The affected service.
        protocol: Transport of the affected service ("tcp" | "udp"). Nullable —
            every finding before Fase N's UDP probe (roadmap §6.3, Ronda 1) is
            TCP and is never backfilled. Exists so ``compute_dedup_key`` can
            tell a service open on 161/tcp apart from the same port on
            161/udp; see its docstring for why the merge would otherwise
            collide the two.
        cve_ids / cvss_score / cvss_vector / epss_score / in_kev /
            exploit_maturity: Vulnerability correlation (filled from Fase 1 on).
        required_os: CPE platform token (e.g. "windows_10") this finding's CVE
            match is gated behind, or None if unconditional. Set from
            ``CpeMatch.required_os`` at correlation time; used by
            ``score_finding`` to avoid treating an unverifiable platform
            precondition as a confirmed risk.
        source: Which scanner produced it ("lybra" | "nikto" | "nuclei" | "nmap",
            or historically "openvas" — that scanner no longer runs).
        check_id: Which own check produced it ("lybra:git-config-exposure@3").
        feed_version: KB/checks version used (reproducibility).
        dedup_key: hash(host, port, cpe|check_id, cve) for multi-source merge.
        qod: Quality of Detection 0-100.
        confirmed: Actively confirmed vs version-only deduction.
        cpe_resolved: Whether Lybra's matcher could resolve this service to a
            CPE at all (Fase I-b observability). ``None`` for finding sources
            that never attempt CPE resolution (Nikto, OpenVAS); ``True``/
            ``False`` for Lybra findings — distinguishes "checked, no CVEs"
            from "could not even identify the package" in the same data that
            otherwise reads identically as an ``installed_package`` row.
        first_seen_at / last_seen_at / state: Lifecycle (open|fixed|regressed|accepted).
    """
    __tablename__ = "Finding"

    id       = Column(Integer, primary_key=True, autoincrement=True)
    scan_id  = Column(Integer, ForeignKey("Scan.id", ondelete="CASCADE"), nullable=False, index=True)
    host_id  = Column(Integer, ForeignKey("Host.id"), nullable=True, index=True)

    # What was found
    title    = Column(Text, nullable=False)
    category = Column(String(64))
    port     = Column(Integer)
    service  = Column(String(128))
    cpe      = Column(String(255), index=True)
    protocol = Column(String(8), nullable=True)

    # Vulnerability correlation (filled from Fase 1 onwards)
    cve_ids          = Column(JSONB)
    cvss_score       = Column(Float)
    cvss_vector      = Column(String(255))
    epss_score       = Column(Float)
    in_kev           = Column(Boolean, default=False)
    exploit_maturity = Column(String(16))   # none|poc|functional|weaponized|in_the_wild
    required_os      = Column(String(64))   # Platform this finding's CVE match is gated behind (see CpeMatch.required_os), or None

    # Quality / provenance
    source       = Column(String(32), index=True)
    check_id     = Column(String(128))
    feed_version = Column(String(32))
    dedup_key    = Column(String(64), index=True)
    qod          = Column(Integer)
    confirmed    = Column(Boolean, default=False)
    cpe_resolved = Column(Boolean, nullable=True)

    # Lifecycle
    first_seen_at = Column(DateTime, default=utcnow_naive)
    last_seen_at  = Column(DateTime, default=utcnow_naive)
    state         = Column(String(20), default="open")
    
    @property
    def snapshot(self) -> dict:
        return {
            "host_id": self.host_id, 
            "title": self.title, 
            "category": self.category,
            "port": self.port,
            "service": self.service,
            "cpe": self.cpe,
            "protocol": self.protocol,
            "cve_ids": self.cve_ids,
            "cvss_score": self.cvss_score, 
            "cvss_vector": self.cvss_vector,
            "epss_score": self.epss_score,
            "in_kev": self.in_kev,
            "exploit_maturity": self.exploit_maturity,
            "required_os": self.required_os,
            "source": self.source,
            "check_id": self.check_id, 
            "feed_version": self.feed_version,
            "dedup_key": self.dedup_key,
            "qod": self.qod,
            "confirmed": self.confirmed,
            "cpe_resolved": self.cpe_resolved,
        }

    def __repr__(self):
        return f"<Finding(id={self.id}, scan_id={self.scan_id}, category='{self.category}', title='{self.title[:40]}')>"


# =========================================================================
# KNOWLEDGE BASE (the "Lybra Feed": local mirror of NVD/KEV/EPSS)
# =========================================================================

class CveEntry(Base):
    """A single CVE mirrored from NVD, the core of the local knowledge base.

    Stored so version→CVE correlation (Fase 1) runs against the local DB instead
    of hitting cve.circl.lu per target. ``cpe_matches`` holds the applicability
    rows (which products/version ranges the CVE affects).
    """
    __tablename__ = "CveEntry"

    id            = Column(Integer, primary_key=True, autoincrement=True)
    cve_id        = Column(String(32), unique=True, nullable=False, index=True)
    published     = Column(DateTime)
    last_modified = Column(DateTime)
    cvss_score    = Column(Float)
    cvss_vector   = Column(String(255))
    severity      = Column(String(16))   # CRITICAL | HIGH | MEDIUM | LOW | NONE
    description   = Column(Text)
    cwe_ids       = Column(JSONB)
    source        = Column(String(16), default="nvd")

    cpe_matches = relationship("CpeMatch", back_populates="cve", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<CveEntry(cve_id='{self.cve_id}', cvss={self.cvss_score})>"


class CpeMatch(Base):
    """One applicability rule of a CVE: a vendor/product and a version range.

    NVD expresses "which versions are affected" with up to four bounds
    (``versionStartIncluding`` etc.); a CPE that pins one version uses
    ``exact_version`` instead. The matcher filters by (vendor, product) and then
    applies ``version_in_range`` (see lybra/kb.py).
    """
    __tablename__ = "CpeMatch"

    id      = Column(Integer, primary_key=True, autoincrement=True)
    cve_id  = Column(Integer, ForeignKey("CveEntry.id", ondelete="CASCADE"), nullable=False, index=True)
    vendor  = Column(String(128), nullable=False)
    product = Column(String(128), nullable=False)

    version_start_including = Column(String(64))
    version_start_excluding = Column(String(64))
    version_end_including   = Column(String(64))
    version_end_excluding   = Column(String(64))
    exact_version           = Column(String(64))  # set when the CPE pins a single version
    required_os             = Column(String(64))  # AND-linked platform gate (lybra/kb.py::_node_required_os), or None

    cve = relationship("CveEntry", back_populates="cpe_matches")

    __table_args__ = (
        Index("ix_CpeMatch_vendor_product", "vendor", "product"),
    )

    def __repr__(self):
        return f"<CpeMatch(cve_id={self.cve_id}, {self.vendor}:{self.product})>"


class CpeProductAlias(Base):
    """A normalized product name -> (vendor, product) index, derived from
    ``CpeMatch`` (Fase I-b, paso 2 del roadmap de Lybra).

    This is deliberately *not* a mirror of NVD's full CPE Dictionary (~1.4M
    entries, expensive to keep in sync): it only indexes products that
    already have at least one CVE in ``CpeMatch``, because a product with
    none could never produce a detection anyway — resolving it would be
    pointless. Rebuilt wholesale after every ``KbSyncManager.sync_nvd`` (see
    ``KbRepository.rebuild_cpe_product_index``), never written to
    incrementally: a full rebuild is what lets a ``(vendor, product)`` pair
    that stops being unique (a name that used to be unambiguous, until a
    same-named product with a different vendor showed up in a later sync)
    correctly disappear from the index instead of silently going stale.

    ``normalized_name`` is unique by construction: the rebuild discards any
    name that maps to more than one distinct ``(vendor, product)`` pair
    rather than picking one — guessing here risks a false-positive CVE
    match, worse than staying unresolved (see
    ``lybra.kb.normalize_product_name``'s docstring for why).
    """
    __tablename__ = "CpeProductAlias"

    id              = Column(Integer, primary_key=True, autoincrement=True)
    normalized_name = Column(String(256), nullable=False, unique=True, index=True)
    vendor          = Column(String(128), nullable=False)
    product         = Column(String(128), nullable=False)

    def __repr__(self):
        return f"<CpeProductAlias({self.normalized_name!r} -> {self.vendor}:{self.product})>"


class KevEntry(Base):
    """A CVE present in CISA's Known Exploited Vulnerabilities catalogue.

    Presence here is a strong "actively exploited in the wild" signal that
    drives contextual prioritization (Fase 5).
    """
    __tablename__ = "KevEntry"

    id               = Column(Integer, primary_key=True, autoincrement=True)
    cve_id           = Column(String(32), unique=True, nullable=False, index=True)
    date_added       = Column(DateTime)
    due_date         = Column(DateTime)
    known_ransomware = Column(Boolean, default=False)

    def __repr__(self):
        return f"<KevEntry(cve_id='{self.cve_id}')>"


class EpssScore(Base):
    """FIRST/EPSS probability that a CVE will be exploited in the next 30 days."""
    __tablename__ = "EpssScore"

    id         = Column(Integer, primary_key=True, autoincrement=True)
    cve_id     = Column(String(32), unique=True, nullable=False, index=True)
    score      = Column(Float)
    percentile = Column(Float)
    scored_at  = Column(DateTime)

    def __repr__(self):
        return f"<EpssScore(cve_id='{self.cve_id}', score={self.score})>"


# =========================================================================
# DOCUMENT MODEL
# =========================================================================

class ThemisDocument(Document):
    """
    PDF report generated from a Themis security scan.

    Inherits from Document (shared model) and adds scan-specific fields.
    Stores the generated PDF path, scan type, and cached AI enrichment.

    Inherits from Document:
        id, document_type, filename, format, status,
        created_at, generated_at, user_id, user

    Attributes:
        id: Primary key (foreign key to Document.id).
        scan_id: Foreign key to Scan.id (cascade delete).
        scan_type: Scan type ('nmap', 'nikto', 'lybra', 'nuclei') for filtering without join.
        enrichment_json: Cached AI analysis result (JSONB, nullable).
        scan: Relationship to the source Scan.

    enrichment_json Structure by scan_type:
        nmap:
        {
          "summary": "...",
          "risk_table": [
            {"port": 80, "service": "http", "risk": "...", "recommendation": "..."}
          ],
          "global_recommendations": ["...", "..."]
        }

        nikto:
        [
          {"item_id": <int>, "recommendation": "..."},
          ...
        ]

    Notes:
        - enrichment_json is nullable: PDFs without AI also use this model.
        - Written once by worker; never overwritten in 'done' state.
        - scan_type field allows filtering without joining Scan table.
    """

    __tablename__ = "ThemisDocument"

    id        = Column(Integer, ForeignKey("Document.id"), primary_key=True)
    scan_id   = Column(Integer, ForeignKey("Scan.id", ondelete="CASCADE"), nullable=False)
    scan_type = Column(String(20),  nullable=False)

    enrichment_json = Column(JSONB, nullable=True)

    scan = relationship("Scan", back_populates="themis_document")

    __mapper_args__ = {
        "polymorphic_identity": "themis",
    }

    @property
    def is_enriched(self) -> bool:
        """
        Check if AI enrichment is available.

        Returns:
            True if enrichment_json is not None.
        """
        return self.enrichment_json is not None

    def __repr__(self) -> str:
        """
        Return a debug representation of the ThemisDocument instance.

        Returns:
            String with id, scan_id, scan_type, and status.
        """
        return (
            f"<ThemisDocument(id={self.id}, scan_id={self.scan_id}, "
            f"scan_type='{self.scan_type}', status='{self.status}')>"
        )