"""Ingesta de plantillas externas al runtime propio (roadmap Fases U4 y R).

De momento solo contiene el clasificador, que es lo que la Fase U4 necesita
para medir. El traductor plantilla→``Check`` es la Fase R, y está condicionado
a lo que esa medición diga.
"""

from .classifier import (
    Bucket,
    TemplateProfile,
    classify_template,
    is_ingestible,
    summarize,
)

__all__ = [
    "Bucket",
    "TemplateProfile",
    "classify_template",
    "is_ingestible",
    "summarize",
]
