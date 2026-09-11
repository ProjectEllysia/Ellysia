"""
Etiquetas del analista: la misma regla para las de un análisis y las de un caso.

Módulo puro: sin base de datos ni red.
"""

from __future__ import annotations

from typing import Iterable, List

#: Etiquetas por análisis o por caso.
MAX_TAGS = 10

#: Longitud máxima de una etiqueta; coincide con ``IrisAnalysisTag.name``.
MAX_TAG_LENGTH = 40


def normalize_tags(tags: Iterable[str]) -> List[str]:
    """Limpia una lista de etiquetas antes de guardarla.

    Args:
        tags: Etiquetas tal como las escribió el usuario.

    Returns:
        List[str]: En minúsculas, con los espacios interiores colapsados, sin
            vacías ni duplicadas, en el orden en que llegaron.

    Raises:
        ValueError: Si alguna supera ``MAX_TAG_LENGTH`` o si son más de
            ``MAX_TAGS``. El mensaje es apto para el usuario.
    """
    normalized: List[str] = []
    for tag in tags:
        cleaned = " ".join((tag or "").split()).lower()
        if not cleaned or cleaned in normalized:
            continue
        if len(cleaned) > MAX_TAG_LENGTH:
            raise ValueError(f"Una etiqueta no puede pasar de {MAX_TAG_LENGTH} caracteres.")
        normalized.append(cleaned)
    if len(normalized) > MAX_TAGS:
        raise ValueError(f"Como mucho {MAX_TAGS} etiquetas.")
    return normalized
