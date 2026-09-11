"""Ingesta de plantillas externas al runtime propio.

Tres piezas, en el orden en que actúan: el **clasificador** decide qué
plantillas entiende el runtime (y es el mismo criterio que usa el censo de
cobertura del feed para medir qué fracción es ingerible), el **traductor** las
convierte en ``Check`` con su procedencia sellada, y el **selector** reduce el
resultado a lo que vale la pena lanzar contra un objetivo concreto.
"""

from .classifier import (
    Bucket,
    TemplateProfile,
    classify_template,
    is_ingestible,
    summarize,
)
from .translator import translate_all, translate_template
from .selector import (
    DEFAULT_MAX_CHECKS,
    DEFAULT_MIN_SEVERITY,
    is_relevant,
    select_for_services,
)

__all__ = [
    "Bucket",
    "TemplateProfile",
    "classify_template",
    "is_ingestible",
    "summarize",
    "translate_template",
    "translate_all",
    "select_for_services",
    "is_relevant",
    "DEFAULT_MIN_SEVERITY",
    "DEFAULT_MAX_CHECKS",
]
