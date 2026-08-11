"""
Repositorio base para las entidades ``Document`` (A9 en
plans/deuda-tecnica-y-calidad.md).

Los tres repositorios de documentos del proyecto —Themis (informes PDF de
escaneo), Iris (informes PDF de análisis) y Aegis (píldoras de
concienciación)— repetían las mismas tres consultas: "el último documento de
este padre", "todos los documentos de este usuario" y "todos los documentos
de este padre". Misma forma, distinta columna de orden y distinto nombre de
la clave ajena.

Esta base las concentra parametrizadas por dos atributos de clase:

    _PARENT_FK:    nombre de la columna FK al padre (``scan_id`` /
                   ``analysis_id`` / ``topic_id``).
    _ORDER_COLUMN: columna de ordenación descendente. Por defecto
                   ``created_at`` (nunca nula, la que usan Themis e Iris);
                   Aegis usa ``generated_at`` a propósito, que es lo que su
                   listado muestra.

Es el complemento en la capa de datos de ``shared/_documents.py::DocumentManager``
(A3), que hace lo propio en la capa de negocio.
"""

from __future__ import annotations

from typing import List, Optional, TypeVar

from .base_repository import BaseRepository

T = TypeVar("T")


class DocumentRepository(BaseRepository[T]):
    """Consultas compartidas por todo repositorio de documentos."""

    #: Columna FK que apunta a la entidad padre del documento.
    _PARENT_FK: str = ""

    #: Columna por la que se ordena (descendente) en todas las consultas.
    _ORDER_COLUMN: str = "created_at"

    def _ordered(self, *filters):
        """Query de ``self._model`` con los filtros dados, ordenada desc."""
        order_column = getattr(self._model, self._ORDER_COLUMN)
        return (
            self._session.query(self._model)
            .filter(*filters)
            .order_by(order_column.desc())
        )

    def _parent_column(self):
        assert self._PARENT_FK, f"{type(self).__name__} no define _PARENT_FK"
        return getattr(self._model, self._PARENT_FK)

    def get_latest_document(self, parent_id) -> Optional[T]:
        """El documento más reciente de la entidad padre dada, o ``None``."""
        return self._ordered(self._parent_column() == parent_id).first()

    def get_documents_by_user(self, user_id: int, limit: Optional[int] = None) -> List[T]:
        """Todos los documentos de un usuario, más recientes primero."""
        query = self._ordered(self._model.user_id == user_id)
        if limit is not None:
            query = query.limit(limit)
        return query.all()

    def get_documents_by_parent(self, parent_id, limit: Optional[int] = None) -> List[T]:
        """Todos los documentos de la entidad padre dada, más recientes primero."""
        query = self._ordered(self._parent_column() == parent_id)
        if limit is not None:
            query = query.limit(limit)
        return query.all()
