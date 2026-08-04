"""
Helper genérico para el patrón "assert ownership" repetido en varios módulos
(acheron, iris, aegis, themis): obtener una entidad por ID y verificar que
pertenece al usuario, lanzando la MISMA excepción tanto si no existe como si
pertenece a otro usuario. Esto evita enumerar IDs ajenos por diferencia de
respuesta (404 "no encontrado" vs 403 "no es tuyo").
"""

from typing import Callable, Optional, Type, TypeVar

from src.modules.infrastructure.session import build_repository
from src.modules.infrastructure.unit_of_work import UnitOfWork

T = TypeVar("T")


def assert_owned(
    repo_cls: Type,
    entity_id: int,
    user_id: int,
    not_found_error: Callable[[int], Exception],
    *,
    uow: Optional[UnitOfWork] = None,
) -> T:
    """
    Obtiene la entidad ``entity_id`` vía ``repo_cls`` (``get_by_id``) y
    verifica que ``entity.user_id == user_id``.

    Args:
        repo_cls: Clase de repositorio (debe implementar ``get_by_id``).
        entity_id: PK de la entidad a verificar.
        user_id: ID del usuario que debería ser propietario.
        not_found_error: Callable que recibe ``entity_id`` y devuelve la
            excepción a lanzar, p. ej. ``ScanNotFoundError`` o
            ``lambda eid: DocumentError(f"Documento {eid} no encontrado")``.
        uow: ``UnitOfWork`` activo (E5). Si se pasa, la entidad se busca con
            ``repo_cls(uow)`` en vez de ``build_repository`` — necesario para
            comprobar propiedad *dentro* de una transacción de escritura ya
            abierta, sin disparar una segunda sesión de solo lectura. Si se
            omite (caso por defecto, camino de lectura), se comporta como
            antes.

    Returns:
        La entidad, si pertenece al usuario.

    Raises:
        La excepción devuelta por ``not_found_error`` si la entidad no
        existe o pertenece a otro usuario (misma excepción en ambos casos).
    """
    repository = repo_cls(uow) if uow is not None else build_repository(repo_cls)
    entity = repository.get_by_id(entity_id)
    if entity is None or entity.user_id != user_id:
        raise not_found_error(entity_id)
    return entity
