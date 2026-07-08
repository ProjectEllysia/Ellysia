"""Helper de tiempo compartido: "ahora" en UTC, naive."""

from datetime import datetime, timezone


def utcnow_naive() -> datetime:
    """Ahora, en UTC, como ``datetime`` *naive* (sin ``tzinfo``).

    Equivalente a ``datetime.utcnow()`` (deprecado en Python 3.12+), pero
    explícito sobre que la ausencia de tzinfo es intencional: las columnas
    ``DateTime`` del esquema no llevan zona horaria y el código asume
    naive-UTC de forma consistente en todo el proyecto.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)
