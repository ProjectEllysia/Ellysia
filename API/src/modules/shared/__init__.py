"""src.modules.shared - Paquete de utilidades compartidas.

Contiene las base classes y utilities que otros módulos necesitan:
    - Base (SQLAlchemy)
    - Document
    - OAuth decorators y helpers

La generación con IA vive ahora en el módulo `scribe`, no aquí.
La inicialización del engine/sesión vive en `infrastructure.unit_of_work`.

Este paquete no contiene endpoints, models específicos de módulos,
ni managers concretos. Esas responsabilidades viven en sus módulos respectivos.
"""

from ._model        import Base, Document
from ._exceptions   import handle_exceptions, ExceptionHandler
from ._endpoints    import (
    current_actor,
    normalize_target,
    require_json,
    require_str,
    require_arg,
    limiter
)
from ._ownership import assert_owned
from ._time import utcnow_naive
from .schemas import ErrorSchema, SuccessMessageSchema, PaginationQuerySchema

__all__ = [
    "Base",
    "Document",
    "handle_exceptions",
    "ExceptionHandler",
    "current_actor",
    "normalize_target",
    "require_json",
    "require_str",
    "require_arg",
    "limiter",
    "assert_owned",
    "utcnow_naive",
    "ErrorSchema",
    "SuccessMessageSchema",
    "PaginationQuerySchema"
]