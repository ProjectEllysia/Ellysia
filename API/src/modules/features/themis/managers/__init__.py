"""
Managers for security scan orchestration and result persistence.

This package provides manager classes for coordinating security scans:
- NmapScanManager: Network exploration and security scanning.
- NiktoScanManager: Web server vulnerability scanning.
- NucleiScanManager: Template-based vulnerability scanning (roadmap Fase U1).
- LybraEngineManager: self-built detection engine (Lybra).

Each manager handles the complete lifecycle of a scan:
- Creating scan records via ScanRepository.
- Executing scans in background threads.
- Processing and saving results.
- Generating PDF reports asynchronously.

Database access is performed exclusively through UnitOfWork + ScanRepository.
ScanManager no longer inherits from BaseManager.

Fase 3 del refactor de estructura: este paquete sustituye al antiguo fichero
monolítico ``managers.py`` (~2700 líneas). Cada clase vive en su propio
módulo; este ``__init__.py`` reexporta los nombres públicos para que
``from src.modules.features.themis.managers import X`` (y el registro de entry
points de la TaskQueue, que referencia estos símbolos por atributo de
módulo) sigan funcionando sin cambios.

Usage:
    manager = NmapScanManager(user)
    scan_id = manager.run_scan(target_host="192.168.1.1", target_ports="1-1000")
    scan = manager.get_scan_by_id(scan_id)
"""

from src.modules.system.taskqueue import TaskQueue

from .scan import ScanManager
from .programed import ProgramedScanManager
from .scan_folder import ScanFolderManager
from .scan_history import ScanHistoryManager
from .traceroute import TracerouteManager
from .thirdparty_scans_managers import NmapScanManager, NiktoScanManager, NucleiScanManager
from .authorized_target import AuthorizedTargetManager
from .lybra_engine import LybraEngineManager
from .kb import KbSyncManager
from .reports import ThemisReportManager

__all__ = [
    "TaskQueue",
    "ScanManager",
    "ProgramedScanManager",
    "ScanFolderManager",
    "ScanHistoryManager",
    "TracerouteManager",
    "NmapScanManager",
    "NiktoScanManager",
    "NucleiScanManager",
    "LybraEngineManager",
    "KbSyncManager",
    "AuthorizedTargetManager",
    "ThemisReportManager",
]
