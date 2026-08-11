"""
Helpers internos del módulo Hygeia.

La mayoría son funciones puras sin conocimiento de Flask ni de
repositorios. Las excepciones son los decoradores de autenticación/guarda
de request (``require_agent_key``, ``enforce_ingest_limits``), que sí
necesitan tocar ``flask.request`` — mismo precedente que
``users/services/permissions.py`` con ``require_oauth_token``.
"""

from .aggregation import denormalize
from .detection import AnomalyChange, DetectionOutcome, evaluate
from .enrollment import agent_key_id_from_request, generate_agent_key, require_agent_key
from .ingest_guard import (
    check_clock_skew,
    decompress_gzip_capped,
    enforce_body_size,
    enforce_ingest_limits,
)
from .inventory_adapter import services_from_inventory

__all__ = [
    "services_from_inventory",
    "agent_key_id_from_request",
    "generate_agent_key",
    "require_agent_key",
    "check_clock_skew",
    "decompress_gzip_capped",
    "enforce_body_size",
    "enforce_ingest_limits",
    "evaluate",
    "AnomalyChange",
    "DetectionOutcome",
    "denormalize",
]
