"""
Excepciones del módulo accounts.

``AccountsError`` es la base; las de "no encontrado" heredan además de
``EntityNotFoundError`` (herencia doble deliberada, igual que en el resto de
módulos) para que un ``except AccountsError`` las siga capturando.
"""

from src.modules.shared._exceptions import (
    EllysiaException,
    EntityNotFoundError,
    ErrorCode,
)


class AccountsError(EllysiaException):
    """Fallo genérico de la capa de planes, suscripciones u organizaciones."""

    default_code = ErrorCode.UNKNOWN_ERROR
    default_status_code = 500


class PlanNotFoundError(EntityNotFoundError, AccountsError):
    """No existe un plan con ese código o id."""

    entity_label = "Plan"
    id_field = "plan_id"


class DefaultPlanMissingError(AccountsError):
    """No hay ningún plan marcado como ``is_default``.

    No es un error del usuario: significa que el catálogo no se ha sembrado, es
    decir, que falta aplicar la migración. Se responde 500 a propósito — un 404
    invitaría a buscar el fallo en la petición y no en el despliegue.
    """

    default_code = ErrorCode.MISSING_CONFIG
    default_status_code = 500

    def __init__(self) -> None:
        super().__init__(
            message="No hay ningun plan marcado como is_default en el catalogo",
            user_message=(
                "La plataforma no tiene configurado un plan por defecto. "
                "Avisa a un administrador."
            ),
        )
