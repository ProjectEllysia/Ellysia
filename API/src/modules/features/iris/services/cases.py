"""
Ciclo de vida de un caso de analista de Iris.

Un análisis es el resultado inmutable de lo que decidió Iris; un caso es la
decisión humana encima: se abre, se investiga, se contiene y se cierra con una
razón. Este módulo fija qué transiciones de estado son válidas y qué exige
cada una. Es puro: sin base de datos ni red.

Estados (``CaseStatus`` en ``model.py``):

- ``new``: recién abierto, nadie lo ha mirado.
- ``triage``: alguien lo está investigando.
- ``contained``: la amenaza está controlada (enlace bloqueado, buzón limpio)
  pero el caso sigue abierto.
- ``resolved``: cerrado; era un incidente real y se trató.
- ``false_positive``: cerrado; no era una amenaza.

Cerrar exige una razón. Reabrir un caso cerrado lo devuelve a ``triage``.
"""

from __future__ import annotations

from typing import Optional

#: Estados que cierran un caso.
CLOSED_STATUSES = frozenset({"resolved", "false_positive"})

#: A qué estados se puede pasar desde cada uno. Un caso cerrado solo se
#: reabre a ``triage``: volver a ``new`` borraría la señal de que ya se
#: investigó una vez.
ALLOWED_TRANSITIONS = {
    "new": frozenset({"triage", "contained", "resolved", "false_positive"}),
    "triage": frozenset({"contained", "resolved", "false_positive"}),
    "contained": frozenset({"triage", "resolved", "false_positive"}),
    "resolved": frozenset({"triage"}),
    "false_positive": frozenset({"triage"}),
}

#: Longitud máxima de la razón de cierre y de una nota.
MAX_CASE_TEXT_LENGTH = 4000


def validate_transition(current: str, target: str, reason: Optional[str]) -> Optional[str]:
    """Comprueba que un caso puede pasar de un estado a otro.

    Args:
        current: Estado actual del caso.
        target: Estado al que se quiere pasar.
        reason: Razón que da el analista. Obligatoria si ``target`` cierra el
            caso (``CLOSED_STATUSES``); se ignora si no.

    Returns:
        Optional[str]: La razón limpia (sin espacios alrededor y recortada a
            ``MAX_CASE_TEXT_LENGTH``) cuando se cierra; ``None`` en cualquier
            otra transición.

    Raises:
        ValueError: Si la transición no está en ``ALLOWED_TRANSITIONS`` o si
            falta la razón de cierre. El mensaje es apto para el usuario.
    """
    if target not in ALLOWED_TRANSITIONS.get(current, frozenset()):
        raise ValueError(f"Un caso en estado «{current}» no puede pasar a «{target}».")
    if target not in CLOSED_STATUSES:
        return None
    cleaned = (reason or "").strip()[:MAX_CASE_TEXT_LENGTH]
    if not cleaned:
        raise ValueError("Cerrar un caso exige explicar por qué.")
    return cleaned
