"""
src.modules.features.hygeia - Monitorización de activos (agente Hygeia)

Exponente:
    - HygeiaAssetManager: alta, consulta y credenciales de activos monitorizados.
    - Modelos: MonitoredAsset, AssetSnapshot, Anomaly.
    - Endpoints: hygeia_blp.
"""

from src.modules.system.taskqueue import QueueRegistry

from .model import Anomaly, AssetSnapshot, MonitoredAsset
from .managers import HygeiaAssetManager
from .endpoints import hygeia_blp

# Registro de las categorías de cola de este módulo (OCP). Los jobs de
# presencia/retención (Fase 3) corren directo en el hilo del scheduler
# propio de Hygeia, sin pasar por RQ — igual que KbSyncManager.execute_kb_sync
# en Themis, son mantenimiento periódico, no trabajo de usuario. Solo
# "notify" (Fase 4, correo de anomalía crítica) necesita cola propia.
QueueRegistry.register("hygeia.notify")

__all__ = [
    "MonitoredAsset",
    "AssetSnapshot",
    "Anomaly",
    "HygeiaAssetManager",
    "hygeia_blp",
]
