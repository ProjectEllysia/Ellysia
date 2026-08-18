from src.modules.system.taskqueue import QueueRegistry

from .model import IrisAnalysis, IrisMailboxConnection, IrisRuleResult, IrisDocument
from .managers import IrisManager, IrisReportManager, IrisMailboxManager
from .managers import IrisMailboxManager
from .managers.notifications import IrisPhishingNotifyManager
from .endpoints import iris_blp

# Registro de las categorías de cola de este módulo (OCP).
QueueRegistry.register("iris.analyze")
QueueRegistry.register("iris.report")
QueueRegistry.register("iris.ingest")
QueueRegistry.register("iris.notify")

__all__ = [
    "IrisAnalysis",
    "IrisMailboxConnection",
    "IrisRuleResult",
    "IrisDocument",
    "IrisManager",
    "IrisReportManager",
    "IrisMailboxManager",
    "IrisPhishingNotifyManager",
    "iris_blp",
]
