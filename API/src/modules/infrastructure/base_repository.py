"""
Generic repository base class for SQLAlchemy models.

Provides type-safe CRUD and query operations through Python Generics,
eliminating boilerplate in concrete repositories.

Classes:
    BaseRepository: Generic repository parameterised on a SQLAlchemy model type.

Usage:
    class ScanRepository(BaseRepository[Scan]):
        _MODEL = Scan

        def get_by_target(self, target: str) -> list[Scan]:
            return self.get_all_by_field("target", target)

A subclass needs its own ``__init__`` only if it does something beyond
declaring ``_MODEL`` (A8) — the base's ``__init__`` reads it, so the
``super().__init__(Model, uow, session)`` one-liner that used to be repeated
in every repository is gone.
"""

from __future__ import annotations

import logging
from typing import Any, ClassVar, Generic, List, Optional, Type, TypeVar

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from .unit_of_work import UnitOfWork

logger = logging.getLogger(__name__)


T = TypeVar("T")


class BaseRepository(Generic[T]):
    """
    Generic repository providing type-safe CRUD operations.

    Concrete repositories inherit from this class, specifying the model
    type via the Generic parameter *and* the ``_MODEL`` class attribute
    (A8) — the former is for static type-checking, the latter is what
    ``__init__`` actually reads at runtime.

    Class Attributes:
        _MODEL: SQLAlchemy model class this repository manages. Must be set
            by every concrete subclass.

    Attributes:
        _model:  The SQLAlchemy model class this repository manages (copied
            from ``_MODEL`` in ``__init__``).
        _uow:    The Unit of Work providing the active session.

    Type Parameters:
        T: SQLAlchemy declarative model class.

    Example:
    >>> class UserRepository(BaseRepository[User]):
    ...     _MODEL = User
    ...
    >>> with UnitOfWork() as uow:
    ...     repo = UserRepository(uow)
    ...     user = repo.get_by_id(42)
    """

    _MODEL: ClassVar[Optional[Type]] = None

    def __init__(self, uow: Optional[UnitOfWork] = None, session: Optional[Session] = None) -> None:
        """
        Initialize the repository.

        Accepts either a UnitOfWork (for explicit transaction control) or a
        plain Session (for request-scoped access where the session is managed
        by Flask middleware).

        Args:
            uow:      Active Unit of Work providing the session (write path).
            session:  Direct SQLAlchemy Session (read path, request-scoped).
        """
        assert self._MODEL is not None, f"{type(self).__name__} no define _MODEL"
        self._model = self._MODEL
        if session is not None:
            self.__session = session
            self._uow = None
        elif uow is not None:
            self._uow = uow
        else:
            raise ValueError("Debe proporcionar uow o session")

    # =========================================================================
    # INTERNAL HELPERS
    # =========================================================================

    @property
    def _session(self):
        """Return the current session, whether from UnitOfWork or direct."""
        if self._uow is not None:
            if self._uow.session is None:
                raise RuntimeError(
                    f"{self.__class__.__name__}: No active session in UnitOfWork."
                )
            return self._uow.session
        return self.__session

    # =========================================================================
    # QUERY METHODS
    # =========================================================================

    def get_by_id(self, pk: Any) -> Optional[T]:
        """
        Retrieve a single record by primary key.

        Args:
            pk: Primary key value.

        Returns:
            Model instance, or None if not found.
        """
        return self._session.get(self._model, pk)

    def get_by_field(self, field: str, value: Any) -> Optional[T]:
        """
        Retrieve the first record matching a field/value pair.

        Args:
            field:  Attribute name on the model.
            value:  Value to match.

        Returns:
            Model instance, or None if not found.

        Raises:
            AttributeError: If the field does not exist on the model.
        """
        return (
            self._session.query(self._model)
            .filter(getattr(self._model, field) == value)
            .one_or_none()
        )

    def get_all_by_field(self, field: str, value: Any) -> List[T]:
        """
        Retrieve all records matching a field/value pair.

        Args:
            field:  Attribute name on the model.
            value:  Value to match.

        Returns:
            List of matching model instances (may be empty).
        """
        return (
            self._session.query(self._model)
            .filter(getattr(self._model, field) == value)
            .all()
        )

    def get_all(self) -> List[T]:
        """
        Retrieve all records for this model.

        Returns:
            List of all model instances (may be empty).
        """
        return self._session.query(self._model).all()

    def exists(self, field: str, value: Any) -> bool:
        """
        Check whether any record matches a field/value pair.

        Args:
            field:  Attribute name on the model.
            value:  Value to match.

        Returns:
            True if at least one matching record exists.
        """
        # ``first()`` aplica LIMIT 1 y para en la primera fila; ``count()``
        # recorrería todas las coincidencias solo para compararlas con 0.
        return (
            self._session.query(self._model)
            .filter(getattr(self._model, field) == value)
            .first()
        ) is not None

    def get_children(self, foreign_key: str, parent_id: Any) -> List[T]:
        """
        Retrieve all child records linked to a parent via a foreign key.

        Args:
            foreign_key:    Foreign key attribute name on this model.
            parent_id:      Parent's primary key value.

        Returns:
            List of matching child model instances.
        """
        return (
            self._session.query(self._model)
            .filter(getattr(self._model, foreign_key) == parent_id)
            .all()
        )

    # =========================================================================
    # PAGINATION
    # =========================================================================

    def paginate(self, page=1, per_page=20, filters=None, order_by=None):
        """
        Retrieve a page of records with a count of total matching rows.

        Args:
            page:     1‑based page number (clamped to >= 1).
            per_page: Items per page (clamped to >= 1).
            filters:  Optional dict of field=value pairs appended as WHERE.
            order_by: Optional SQLAlchemy ORDER BY expression.

        Returns:
            Tuple of (items: List[T], total_count: int).
        """
        page = max(page, 1)
        per_page = max(per_page, 1)

        query = self._session.query(self._model)
        if filters:
            for field, value in filters.items():
                attr = getattr(self._model, field)
                if isinstance(value, (list, tuple)):
                    query = query.filter(attr.in_(value))
                else:
                    query = query.filter(attr == value)

        total_count = query.count()

        if order_by is not None:
            query = query.order_by(order_by)

        offset = (page - 1) * per_page
        items = query.limit(per_page).offset(offset).all()

        return items, total_count

    # =========================================================================
    # CRUD METHODS
    # =========================================================================

    def save(self, obj: T) -> T:
        """
        Persist a new object and refresh it to populate generated fields.

        Flush is used instead of commit so that transaction control remains
        with the Unit of Work / caller.

        Args:
            obj: Model instance to persist.

        Returns:
            The same instance, refreshed with any server-generated values.

        Raises:
            SQLAlchemyError: If the flush fails.
        """
        try:
            self._session.add(obj)
            self._session.flush()
            self._session.refresh(obj)
            return obj
        except SQLAlchemyError as e:
            logger.error("Error saving %s", self._model.__name__, exc_info=True)
            raise SQLAlchemyError(f"Error saving {self._model.__name__}: {e}") from e

    def delete(self, obj: T) -> None:
        """
        Remove an object from the database.

        Flush is used instead of commit so that transaction control remains
        with the Unit of Work / caller.

        Args:
            obj: Model instance to delete.

        Raises:
            SQLAlchemyError: If the flush fails.
        """
        try:
            self._session.delete(obj)
            self._session.flush()
        except SQLAlchemyError as e:
            logger.error("Error deleting %s", self._model.__name__, exc_info=True)
            raise SQLAlchemyError(f"Error deleting {self._model.__name__}: {e}") from e

    def update(self, obj: T) -> T:
        """
        Flush pending changes to an existing object.

        Transaction control (commit/rollback) remains with the caller.

        Args:
            obj: Modified model instance.

        Returns:
            The same instance after flush.

        Raises:
            SQLAlchemyError: If the flush fails.
        """
        try:
            self._session.flush()
            return obj
        except SQLAlchemyError as e:
            logger.error("Error updating %s", self._model.__name__, exc_info=True)
            raise SQLAlchemyError(f"Error updating {self._model.__name__}: {e}") from e
