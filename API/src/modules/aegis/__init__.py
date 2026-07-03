"""
src.modules.aegis - Módulo de concienciación en ciberseguridad

Exponente:
    - AegisManager: Generación de píldoras
    - Modelos: AegisDocument, AegisTip, Topic
    - Endpoints: aegis_bp
"""

from src.modules.system.taskqueue import QueueRegistry

from .model import (
    AegisDocument,
    AegisDocumentAlert,
    AegisQuizQuestion,
    AegisTip,
    Campaign,
    CampaignAnswer,
    CampaignRecipient,
    DistributionList,
    Recipient,
    Topic,
)
from .managers import AegisManager, CampaignManager
from .endpoints import aegis_blp

# Registro de las categorías de cola de este módulo (OCP).
QueueRegistry.register("aegis.generate", "aegis.campaign")

__all__ = [
    "AegisDocument",
    "AegisDocumentAlert",
    "AegisQuizQuestion",
    "AegisTip",
    "Campaign",
    "CampaignAnswer",
    "CampaignRecipient",
    "DistributionList",
    "Recipient",
    "Topic",
    "AegisManager",
    "CampaignManager",
    "aegis_blp",
]