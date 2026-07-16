"""
Helper genérico para el patrón "assert ownership" repetido en varios módulos
(acheron, iris, aegis, themis): obtener una entidad por ID y verificar que
pertenece al usuario, lanzando la MISMA excepción tanto si no existe como si
pertenece a otro usuario. Esto evita enumerar IDs ajenos por diferencia de
respuesta (404 "no encontrado" vs 403 "no es tuyo").
"""

from typing import Callable, Type, TypeVar

from src.modules.infrastructure.session import build_repository

T = TypeVar("T")


def assert_owned(
    repo_cls: Type,
    entity_id: int,
    user_id: int,
    not_found_error: Callable[[int], Exception],
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

    Returns:
        La entidad, si pertenece al usuario.

    Raises:
        La excepción devuelta por ``not_found_error`` si la entidad no
        existe o pertenece a otro usuario (misma excepción en ambos casos).
    """
    entity = build_repository(repo_cls).get_by_id(entity_id)
    if entity is None or entity.user_id != user_id:
        raise not_found_error(entity_id)
    return entity
