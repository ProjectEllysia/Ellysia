"""
src.modules.features.themis - Módulo de escaneos de seguridad

Exponente:
    - NmapScanManager: Escaneo de puertos
    - NiktoScanManager: Escaneo web
    - OpenVASScanManager: Escaneo de vulnerabilidades
    - Modelos: Scan, Host, Port, etc.
    - Endpoints: themis_bp
"""

from src.modules.system.taskqueue import QueueRegistry

from .model import (
    Host,
    NiktoIncident,
    NiktoScan,
    NmapScan,
    OpenPort,
    OpenVASScan,
    OpenVASScanResult,
    OpenVASVulnerability,
    Port,
    ProgramedScan,
    Scan,
    ScanFolder,
    ScanIncident,
    ScanStatus,
    ThemisDocument,
    TargetPort,
)

from .managers import (
    NmapScanManager,
    NiktoScanManager,
    OpenVASScanManager,
    ProgramedScanManager,
    ScanManager,
    ScanFolderManager,
)

from .repositories import (
    ProgramedScanRepository,
    ScanRepository,
    ThemisReportRepository,
)

from .services import (
    NmapPrintingStrategy,
    NiktoPrintingStrategy,
    OpenVASPrintingStrategy,
    PDFCreator,
    ThemisScheduler,
)

from .endpoints import themis_blp

# Registro de las categorías de cola de este módulo (OCP).
QueueRegistry.register("themis.scan", "themis.report", "themis.traceroute")

__all__ = [
    "Host", "NiktoIncident", "NiktoScan", "NmapScan", "OpenPort",
    "OpenVASScan", "OpenVASScanResult", "OpenVASVulnerability", "Port",
    "ProgramedScan", "Scan", "ScanFolder", "ScanIncident", "ScanStatus",
    "ThemisDocument", "TargetPort",
    "NmapScanManager", "NiktoScanManager", "OpenVASScanManager",
    "ProgramedScanManager", "ScanManager", "ScanFolderManager",
    "ProgramedScanRepository", "ScanRepository", "ScanFolderRepository",
    "ThemisReportRepository",
    "themis_blp",
    "PDFCreator", "NmapPrintingStrategy", "NiktoPrintingStrategy",
    "OpenVASPrintingStrategy",
    "ThemisScheduler",
]