"""
Excepciones específicas del módulo Acheron (vault cifrado).

Este módulo define las excepciones utilizadas en el flujo de gestión
de vaults y storables (accounts, credit cards).

Excepciones de Vault:
    - VaultError: Excepción base para errores del vault.
    - VaultNotFoundError: Cuando un vault no existe.
    - StorableNotFoundError: Cuando un storable no existe.
    - StorableConflictError: Cuando ya existe un storable con el mismo internalId.
    - VaultRevisionMismatchError: Cuando el cliente escribe sobre una revisión
      obsoleta del vault (concurrencia optimista).

Ejemplo de uso:
    >>> raise VaultNotFoundError(vault_id=42)
    >>> raise StorableConflictError(internal_id="abc123")
    >>> raise VaultRevisionMismatchError(current=7, provided=3)
"""

from typing import Optional

from src.modules.shared._exceptions import (
    ErrorCode,
    ErrorSeverity,
    DatabaseError,
)


class VaultError(DatabaseError):
    """
    Excepción base para errores relacionados con vaults.

    Por defecto retorna código 500 (Error interno del servidor) con
    severidad ALTA.
    """
    default_code = ErrorCode.VAULT_ERROR
    default_status_code = 500
    default_severity = ErrorSeverity.HIGH


class VaultNotFoundError(VaultError):
    """
    Cuando un vault no existe en la base de datos.
    """
    default_code = ErrorCode.ENTITY_NOT_FOUND
    default_status_code = 404
    default_severity = ErrorSeverity.LOW

    def __init__(self, vault_id: int = None, **kwargs):
        msg = f"Vault con ID {vault_id} no encontrado" if vault_id is not None else "Vault no encontrado"
        super().__init__(
            message=kwargs.pop("message", msg),
            details={"vault_id": vault_id},
            user_message="Vault no encontrado.",
            **kwargs,
        )


class StorableNotFoundError(VaultError):
    """
    Cuando un storable no existe en el vault.
    """
    default_code = ErrorCode.ENTITY_NOT_FOUND
    default_status_code = 404
    default_severity = ErrorSeverity.LOW

    def __init__(self, internal_id: str = None, storable_id: int = None):
        identifier = internal_id or str(storable_id)
        super().__init__(
            message=f"Storable '{identifier}' no encontrado",
            details={"internal_id": internal_id, "storable_id": storable_id},
            user_message="Storable no encontrado."
        )


class VaultRevisionMismatchError(VaultError):
    """
    Cuando la revisión que el cliente dice tener no es la del servidor.

    Es el mecanismo que impide que un cliente con un snapshot obsoleto pise
    cambios hechos desde otro dispositivo. ``provided=None`` significa que el
    cliente no mandó ``If-Match`` donde es obligatorio (upsert completo).
    """
    default_code = ErrorCode.VAULT_REVISION_MISMATCH
    default_status_code = 409
    default_severity = ErrorSeverity.LOW

    def __init__(self, current: int, provided: Optional[int] = None):
        self.current_revision = current
        self.provided_revision = provided
        if provided is None:
            msg = (
                f"Falta la cabecera If-Match; la revisión actual del vault "
                f"es {current}"
            )
            user_msg = (
                "Esta operación exige indicar la revisión del vault "
                "(cabecera If-Match)."
            )
        else:
            msg = (
                f"Revisión de vault obsoleta: el cliente envió {provided} "
                f"y la actual es {current}"
            )
            user_msg = (
                "El vault cambió desde otro dispositivo. Recarga y vuelve a "
                "intentarlo."
            )
        super().__init__(
            message=msg,
            details={"currentRevision": current, "yourRevision": provided},
            user_message=user_msg,
        )


class StorableConflictError(VaultError):
    """
    Cuando ya existe un storable con el mismo internalId.
    """
    default_code = ErrorCode.ENTITY_ALREADY_EXISTS
    default_status_code = 409
    default_severity = ErrorSeverity.LOW

    def __init__(self, internal_id: str):
        super().__init__(
            message=f"Storable con internalId '{internal_id}' ya existe",
            details={"internal_id": internal_id},
            user_message="Ya existe un storable con ese identificador."
        )