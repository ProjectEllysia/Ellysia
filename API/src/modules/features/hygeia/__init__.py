"""
src.modules.features.hygeia - Monitorización de activos (agente Hygeia)

Exponente:
    - HygeiaAssetManager: alta, consulta y credenciales de activos monitorizados.
    - HygeiaTagManager: catálogo de etiquetas y su asignación a los activos.
    - HygeiaReportManager: informe PDF del inventario de activos.
    - Modelos: MonitoredAsset, AssetSnapshot, Anomaly, HygeiaTag (SystemTag, UserTag).
    - Endpoints: hygeia_blp.
"""

from src.modules.system.taskqueue import QueueRegistry

from .model import Anomaly, AssetSnapshot, AssetTag, HygeiaTag, MonitoredAsset, SystemTag, UserTag
from .managers import HygeiaAssetManager, HygeiaReportManager, HygeiaTagManager
from .endpoints import hygeia_blp

# Registro de las categorías de cola de este módulo (OCP). Los jobs de
# presencia/retención corren directo en el hilo del scheduler
# propio de Hygeia, sin pasar por RQ — igual que KbSyncManager.execute_kb_sync
# en Themis, son mantenimiento periódico, no trabajo de usuario. Solo
# "notify" (correo de anomalía crítica) necesita cola propia.
QueueRegistry.register("hygeia.notify")

__all__ = [
    "MonitoredAsset",
    "AssetSnapshot",
    "Anomaly",
    "AssetTag",
    "HygeiaTag",
    "SystemTag",
    "UserTag",
    "HygeiaAssetManager",
    "HygeiaReportManager",
    "HygeiaTagManager",
    "hygeia_blp",
]
