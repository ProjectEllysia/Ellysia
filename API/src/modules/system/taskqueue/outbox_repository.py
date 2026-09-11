"""
Data-access layer for TaskDispatch (B08 outbox). Ver ``outbox.py`` para el
porqué de esta tabla y cómo se usa.
"""

from __future__ import annotations

from typing import List

from src.modules.infrastructure import BaseRepository

from .outbox import TaskDispatch


class TaskDispatchRepository(BaseRepository[TaskDispatch]):
    """Data-access layer for TaskDispatch records."""

    _MODEL = TaskDispatch

    def get_pending(self, limit: int = 100) -> List[TaskDispatch]:
        """Filas sin publicar, en orden de creación -- el orden en que se
        crearon es el orden en que sus jobs deberían empezar a intentarse.

        Args:
            limit: Máximo de filas a devolver. Por defecto ``100``.

        Returns:
            List[TaskDispatch]: Filas con ``status="pending"``, ordenadas
                por ``id`` ascendente (más antigua primero). Vacía si no
                queda ninguna por publicar.
        """
        return (
            self._session.query(TaskDispatch)
            .filter(TaskDispatch.status == "pending")
            .order_by(TaskDispatch.id.asc())
            .limit(limit)
            .all()
        )
