"""
Database models for Sentinel security scanning module.

This module contains SQLAlchemy models for vulnerability scanning including:
- Network hosts and port management
- Scan base class with polymorphic inheritance
- Nmap, Nikto, and OpenVAS scan implementations
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
    OpenVASScan: OpenVAS vulnerability scan results.
    OpenVASVulnerability: Stored vulnerability definition.
    OpenVASScanResult: Scan result linking scan to vulnerability.
    SentinelDocument: Generated PDF report from scan.

Example:
    >>> from src.modules.sentinel.model import Scan, NmapScan
    >>> scan = NmapScan(target="192.168.1.1", user_id=1)
    >>> print(scan)
    NmapScan(id=None, target='192.168.1.1', puertos_abiertos=0, inicio=N/A)
"""

from datetime import datetime
from enum import Enum

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Table,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship

from src.modules.shared import Base, Document


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
        OPENVAS: OpenVAS comprehensive vulnerability manager.
        ELLYSIA: Ellysia's own vulnerability engine (native detection).
    """
    NMAP    = "nmap"
    NIKTO   = "nikto"
    OPENVAS = "openvas"
    ELLYSIA = "ellysia"


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
# TRACEROUTE
# =========================================================================

class Traceroute(Base):
    """
    Cached network path (traceroute) from the Ellysia server to a scan target.

    The hops are a property of the *route to the destination*, not of any
    individual scan, and change slowly over time. We therefore cache one row
    per (user, target) and reuse it across all scan types (Nmap, Nikto,
    OpenVAS) instead of re-running the traceroute on every scan. ``created_at``
    drives cache invalidation (see ``TracerouteManager``).

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
    created_at = Column(DateTime,    nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime,    nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

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
    created_at = Column(DateTime,   nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime,   nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

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
    (Nmap, Nikto, OpenVAS) while maintaining a common interface.

    Attributes:
        id: Primary key, auto-incrementing integer.
        target: Scan target (IP or domain, max 255 characters).
        started_at: Scan start timestamp (automatic).
        status: Current scan status (pending/running/finished/failed/cancelled).
        user_id: Foreign key to User.id (scan owner).
        scan_type: Polymorphic discriminator (nmap/nikto/openvas).
        frecuent: Whether this is a scheduled/repeated scan.
        host_id: Optional foreign key to Host.
        finished_at: Scan completion timestamp (nullable).

    Relationships:
        user: User who initiated the scan.
        host: Target host if resolved.
        sentinel_document: Generated PDF report (one-to-one).

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
    started_at  = Column(DateTime,   nullable=False, default=datetime.utcnow)
    status      = Column(String(20), nullable=False, default=ScanStatus.PENDING.value)
    user_id     = Column(Integer,    ForeignKey("User.id"), nullable=False)
    scan_type   = Column(String(50))
    frecuent    = Column(Boolean,    nullable=False, default=True)
    host_id     = Column(Integer,    ForeignKey("Host.id"))
    finished_at = Column(DateTime,   nullable=True)

    user = relationship("User", back_populates="scans")
    host = relationship("Host", back_populates="scans")

    programed_scan_id = Column(Integer, ForeignKey("ProgramedScan.id"), nullable=True)
    programed_scan = relationship("ProgramedScan", back_populates="scans")

    folder_id = Column(Integer, ForeignKey("ScanFolder.id"), nullable=True)
    folder = relationship("ScanFolder", back_populates="scans")

    sentinel_document = relationship(
        "SentinelDocument",
        back_populates="scan",
        uselist=False,
    )

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
    scan_type       = Column(String(20), nullable=False)  # "nmap" | "nikto" | "openvas"
    arguments       = Column(JSONB, nullable=False)       # {"ports": "22,80", "timeout": 300}

    # Schedule
    schedule_type    = Column(String(10), nullable=False)   # "interval" | "cron"
    schedule_config  = Column(JSONB, nullable=False)        # {"every": 60, "unit": "minutes"}
                                                             # o {"cron": "0 2 * * *"}
    # Estado
    is_active       = Column(Boolean, default=True)
    last_run_at     = Column(DateTime, nullable=True)
    next_run_at     = Column(DateTime, nullable=True)
    created_at      = Column(DateTime, default=datetime.utcnow)

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
            not yield a CPE. It is the entry point the Ellysia engine reads to
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
    discovered_at = Column(DateTime,  nullable=False, default=datetime.utcnow)

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


# =========================================================================
# OPENVAS MODELS
# =========================================================================

class OpenVASScan(Scan):
    """
    OpenVAS vulnerability scan results.

    Inherits from Scan and stores OpenVAS-specific data including
    task and report identifiers, and detected vulnerabilities.

    Attributes:
        id: Primary key (foreign key to Scan.id).
        task_id: OpenVAS task identifier.
        report_id: OpenVAS report identifier.
        scan_config_name: OpenVAS scan configuration used.
        scanner_name: OpenVAS scanner name.
        results: List of OpenVASScanResult objects with findings.

    Table Constraints:
        Unique constraint on (task_id, report_id) to prevent duplicates.
    """
    __tablename__ = "OpenVASScan"

    id               = Column(Integer,     ForeignKey("Scan.id"), primary_key=True)
    task_id          = Column(String(255), nullable=False)
    report_id        = Column(String(255), nullable=False)
    scan_config_name = Column(String(255))
    scanner_name     = Column(String(255))

    results = relationship(
        "OpenVASScanResult", back_populates="openvas_scan", cascade="all, delete-orphan"
    )

    __mapper_args__ = {"polymorphic_identity": ScanType.OPENVAS}

    __table_args__ = (
        UniqueConstraint("task_id", "report_id", name="unique_task_report"),
    )


class OpenVASVulnerability(Base):
    """
    Stored vulnerability definition from OpenVAS NVT feed.

    Represents a unique vulnerability with CVSS scoring, CVE references,
    and remediation information.

    Attributes:
        id: Primary key, auto-incrementing integer.
        nvt_oid: OpenVAS NVT OID (unique, indexed).
        name: Vulnerability name/title.
        severity_score: Numeric severity score.
        severity_class: Severity category (Critical/High/Medium/Low/Log).
        cvss_base_score: CVSS v2 base score.
        cvss_vector: CVSS vector string.
        cve_ids: Comma-separated CVE identifiers.
        cert_refs: CERT-Bund references.
        bugtraq_ids: BugTraq IDs.
        other_refs: Other reference identifiers.
        summary: Brief summary.
        description: Full description.
        impact: Impact description.
        insight: Insight into the vulnerability.
        affected_software: Affected software list.
        solution_type: Type of solution (VendorFix, Workaround, etc.).
        solution: Solution description.
        qod_value: Quality of Detection value.
        qod_type: Quality of Detection type.
        family: NVT family.
        category: NVT category.
        created_at: Creation timestamp (automatic).
        updated_at: Last update timestamp (automatic).

    Relationships:
        scan_results: OpenVASScanResult objects linking to this vulnerability.
    """
    __tablename__ = "OpenVASVulnerability"

    id                = Column(Integer,     primary_key=True, autoincrement=True)
    nvt_oid           = Column(String(255), unique=True, nullable=False, index=True)
    name              = Column(Text,        nullable=False)
    severity_score    = Column(Float(3))
    severity_class    = Column(String(20),  index=True)
    cvss_base_score   = Column(Float(3))
    cvss_vector       = Column(String(255))
    cve_ids           = Column(Text)
    cert_refs         = Column(Text)
    bugtraq_ids       = Column(Text)
    other_refs        = Column(Text)
    summary           = Column(Text)
    description       = Column(Text)
    impact            = Column(Text)
    insight           = Column(Text)
    affected_software = Column(Text)
    solution_type     = Column(String(50))
    solution          = Column(Text)
    qod_value         = Column(Integer)
    qod_type          = Column(String(100))
    family            = Column(String(255))
    category          = Column(String(255))
    created_at        = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at        = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    scan_results = relationship("OpenVASScanResult", back_populates="vulnerability")

    def __repr__(self):
        """
        Return a debug representation of the OpenVASVulnerability instance.

        Returns:
            String with NVT OID.
        """
        return f"<OpenVASVulnerability(nvt_oid='{self.nvt_oid}')>"


class OpenVASScanResult(Base):
    """
    Result linking an OpenVAS scan to a detected vulnerability.

    Represents a single vulnerability finding in a specific scan,
    including host where it was detected.

    Attributes:
        id: Primary key, auto-incrementing integer.
        openvas_scan_id: Foreign key to OpenVASScan.id (indexed, cascading delete).
        vulnerability_id: Foreign key to OpenVASVulnerability.id (indexed).
        host_id: Foreign key to Host.id where vulnerability was found.
        detected_at: Detection timestamp (automatic).

    Relationships:
        openvas_scan: OpenVASScan containing this result.
        vulnerability: OpenVASVulnerability detected.
        host: Host where vulnerability was detected.
    """
    __tablename__ = "OpenVASScanResult"

    id              = Column(Integer, primary_key=True, autoincrement=True)
    openvas_scan_id = Column(Integer, ForeignKey("OpenVASScan.id", ondelete="CASCADE"), nullable=False, index=True)
    vulnerability_id = Column(Integer, ForeignKey("OpenVASVulnerability.id"), nullable=False, index=True)
    host_id         = Column(Integer, ForeignKey("Host.id"), nullable=False, index=True)
    detected_at     = Column(DateTime, nullable=False, default=datetime.utcnow)

    openvas_scan  = relationship("OpenVASScan",          back_populates="results")
    vulnerability = relationship("OpenVASVulnerability",  back_populates="scan_results")
    host          = relationship("Host")


# =========================================================================
# ELLYSIA ENGINE MODELS
# =========================================================================

class EllysiaScan(Scan):
    """Scan produced by Ellysia's own vulnerability engine.

    In the current phase (Fase 0) Ellysia has no network transport of its own,
    so a scan takes its services from a previous Nmap scan of the same target
    (``source_scan_id``) and produces normalized :class:`Finding` rows. When the
    engine gains its own transport (Fase T) ``source_scan_id`` becomes optional.

    Attributes:
        id: Primary key (foreign key to Scan.id).
        source_scan_id: The Nmap Scan whose discovered services were analysed.
            Nullable so a future self-discovering scan can leave it empty.
    """
    __tablename__ = "EllysiaScan"

    id             = Column(Integer, ForeignKey("Scan.id"), primary_key=True)
    source_scan_id = Column(Integer, ForeignKey("Scan.id"), nullable=True)

    __mapper_args__ = {
        "polymorphic_identity": ScanType.ELLYSIA,
        "inherit_condition":    id == Scan.id,
    }

    def __repr__(self):
        return f"<EllysiaScan(id={self.id}, target='{self.target}', source={self.source_scan_id})>"


class Finding(Base):
    """Normalized security finding, independent of the scanner that produced it.

    The unified finding model that lets Ellysia, Nikto and OpenVAS results live
    in one table and be correlated (dedup by ``dedup_key``). See the vuln-engine
    roadmap (§3.3) for the full design. In Fase 0 only informational
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
        cve_ids / cvss_score / cvss_vector / epss_score / in_kev /
            exploit_maturity: Vulnerability correlation (filled from Fase 1 on).
        source: Which scanner produced it ("ellysia" | "nikto" | "openvas" | "nmap").
        check_id: Which own check produced it ("ellysia:git-config-exposure@3").
        feed_version: KB/checks version used (reproducibility).
        dedup_key: hash(host, port, cpe|check_id, cve) for multi-source merge.
        qod: Quality of Detection 0-100.
        confirmed: Actively confirmed vs version-only deduction.
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

    # Vulnerability correlation (filled from Fase 1 onwards)
    cve_ids          = Column(JSONB)
    cvss_score       = Column(Float)
    cvss_vector      = Column(String(255))
    epss_score       = Column(Float)
    in_kev           = Column(Boolean, default=False)
    exploit_maturity = Column(String(16))   # none|poc|functional|weaponized|in_the_wild

    # Quality / provenance
    source       = Column(String(32), index=True)
    check_id     = Column(String(128))
    feed_version = Column(String(32))
    dedup_key    = Column(String(64), index=True)
    qod          = Column(Integer)
    confirmed    = Column(Boolean, default=False)

    # Lifecycle
    first_seen_at = Column(DateTime, default=datetime.utcnow)
    last_seen_at  = Column(DateTime, default=datetime.utcnow)
    state         = Column(String(20), default="open")

    def __repr__(self):
        return f"<Finding(id={self.id}, scan_id={self.scan_id}, category='{self.category}', title='{self.title[:40]}')>"


# =========================================================================
# DOCUMENT MODEL
# =========================================================================

class SentinelDocument(Document):
    """
    PDF report generated from a Sentinel security scan.

    Inherits from Document (shared model) and adds scan-specific fields.
    Stores the generated PDF path, scan type, and cached AI enrichment.

    Inherits from Document:
        id, document_type, filename, format, status,
        created_at, generated_at, user_id, user

    Attributes:
        id: Primary key (foreign key to Document.id).
        scan_id: Foreign key to Scan.id (cascade delete).
        scan_type: Scan type ('nmap', 'nikto', 'openvas') for filtering without join.
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

        nikto / openvas:
        [
          {"item_id": <int>, "recommendation": "..."},
          ...
        ]

    Notes:
        - enrichment_json is nullable: PDFs without AI also use this model.
        - Written once by worker; never overwritten in 'done' state.
        - scan_type field allows filtering without joining Scan table.
    """

    __tablename__ = "SentinelDocument"

    id        = Column(Integer, ForeignKey("Document.id"), primary_key=True)
    scan_id   = Column(Integer, ForeignKey("Scan.id", ondelete="CASCADE"), nullable=False)
    scan_type = Column(String(20),  nullable=False)

    enrichment_json = Column(JSONB, nullable=True)

    scan = relationship("Scan", back_populates="sentinel_document")

    __mapper_args__ = {
        "polymorphic_identity": "sentinel",
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
        Return a debug representation of the SentinelDocument instance.

        Returns:
            String with id, scan_id, scan_type, and status.
        """
        return (
            f"<SentinelDocument(id={self.id}, scan_id={self.scan_id}, "
            f"scan_type='{self.scan_type}', status='{self.status}')>"
        )