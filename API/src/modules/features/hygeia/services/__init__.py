"""
Helpers internos del módulo Hygeia.

La mayoría son funciones puras sin conocimiento de Flask ni de
repositorios. Las excepciones son los decoradores de autenticación/guarda
de request (``require_agent_key``, ``enforce_ingest_limits``), que sí
necesitan tocar ``flask.request`` — mismo precedente que
``users/services/permissions.py`` con ``require_oauth_token``.
"""

from .aggregation import denormalize
from .agent_freshness import is_agent_outdated
from .detection import AnomalyChange, DetectionOutcome, evaluate
from .enrollment import agent_key_id_from_request, generate_agent_key, require_agent_key
from .ingest_guard import (
    check_clock_skew,
    decompress_gzip_capped,
    enforce_body_size,
    enforce_ingest_limits,
)
from .inventory_adapter import services_from_inventory
from .reports import build_inventory_report
from .stats import (
    EnergyCost,
    PeriodClassification,
    PowerAverage,
    classify_period,
    energy_and_cost,
    project_month,
    summarize_power_period,
    weighted_average_with_observed_time,
)

__all__ = [
    "services_from_inventory",
    "build_inventory_report",
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
    "is_agent_outdated",
    "PowerAverage",
    "EnergyCost",
    "PeriodClassification",
    "weighted_average_with_observed_time",
    "energy_and_cost",
    "classify_period",
    "summarize_power_period",
    "project_month",
]
