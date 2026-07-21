from src.modules.system.taskqueue import QueueRegistry

from .model import IrisAnalysis, IrisRuleResult, IrisDocument
from .managers import IrisManager, IrisReportManager
from .endpoints import iris_blp

# Registro de las categorías de cola de este módulo (OCP).
QueueRegistry.register("iris.analyze")
QueueRegistry.register("iris.report")

__all__ = [
    "IrisAnalysis",
    "IrisRuleResult",
    "IrisDocument",
    "IrisManager",
    "IrisReportManager",
    "iris_blp",
]
