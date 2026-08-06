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


class PlanLimitError(AccountsError):
    """Base de los cortes por plan. Se responden con **402 Payment Required**.

    Un 402 y un 403 significan cosas distintas y el cliente los redacta
    distinto: el 403 del ABAC es "tu administrador no te ha concedido esto" y
    este 402 es "tu plan no da para esto". Con la regla de que el plan nunca
    escribe atributos, cada uno tiene una sola causa posible.

    ``details`` viaja al cliente (``expose_details``) porque es el contrato:
    sin el tope, el consumo y la fecha de reinicio no se puede escribir un
    mensaje útil.
    """

    default_code = ErrorCode.PLAN_ERROR
    default_status_code = 402
    expose_details = True


class PlanFeatureDisabledError(PlanLimitError):
    """El plan no incluye la característica en absoluto (tope a 0)."""

    default_code = ErrorCode.PLAN_FEATURE_NOT_INCLUDED

    def __init__(self, limit_key: str, plan_code: str) -> None:
        super().__init__(
            message=f"El plan '{plan_code}' no incluye '{limit_key}'",
            details={"limitKey": limit_key, "value": 0, "planCode": plan_code},
            user_message="Tu plan no incluye esta funcionalidad.",
        )


class QuotaExceededError(PlanLimitError):
    """La característica está incluida, pero se ha agotado el cupo."""

    default_code = ErrorCode.PLAN_LIMIT_REACHED

    def __init__(
        self,
        limit_key: str,
        value: int,
        used: int,
        period: str,
        plan_code: str,
        resets_at=None,
    ) -> None:
        super().__init__(
            message=f"Cuota agotada para '{limit_key}': {used}/{value} ({period})",
            details={
                "limitKey": limit_key,
                "value":    value,
                "used":     used,
                "period":   period,
                "planCode": plan_code,
                "resetsAt": resets_at.isoformat() if resets_at else None,
            },
            user_message=(
                "Has alcanzado el limite de tu plan para esta accion."
                if resets_at is None
                else "Has alcanzado el limite de tu plan. Se renueva al empezar el proximo periodo."
            ),
        )


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
