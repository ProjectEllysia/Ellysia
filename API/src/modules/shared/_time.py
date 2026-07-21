"""Helper de tiempo compartido: "ahora" en UTC, naive."""

from datetime import datetime, timezone
from typing import Optional


def utcnow_naive() -> datetime:
    """Ahora, en UTC, como ``datetime`` *naive* (sin ``tzinfo``).

    Equivalente a ``datetime.utcnow()`` (deprecado en Python 3.12+), pero
    explícito sobre que la ausencia de tzinfo es intencional: las columnas
    ``DateTime`` del esquema no llevan zona horaria y el código asume
    naive-UTC de forma consistente en todo el proyecto.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)


def isoformat_utc(dt: Optional[datetime]) -> Optional[str]:
    """Serializa un ``datetime`` naive-UTC a ISO 8601 marcado explícitamente como UTC.

    ``datetime.isoformat()`` sobre un naive-UTC (como el que produce
    ``utcnow_naive()``, usado en todas las columnas ``DateTime`` del esquema)
    no añade sufijo de zona horaria. El frontend hace ``new Date(iso)`` sobre
    esa cadena, y JavaScript interpreta un ISO 8601 *sin* zona horaria como
    hora **local** del navegador, no UTC — así una hora guardada como
    "09:34 UTC" se mostraba como si fueran las "09:34" en la zona del usuario,
    desfasada por su offset respecto a UTC (2 h en Madrid en verano). Usar
    esta función en cualquier campo de fecha que vaya a una respuesta JSON
    deja la cadena sin ambigüedad (p. ej. ``"...T09:34:05Z"``) y el navegador
    la convierte a hora local correctamente él solo.

    Args:
        dt: El datetime a serializar (se asume naive-UTC), o ``None``.

    Returns:
        La cadena ISO 8601 con sufijo ``Z``, o ``None`` si ``dt`` es ``None``.
    """
    if dt is None:
        return None
    return dt.isoformat() + "Z"
