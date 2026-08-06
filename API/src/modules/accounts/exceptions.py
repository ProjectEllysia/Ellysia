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


class OrganizationNotFoundError(EntityNotFoundError, AccountsError):
    """No existe la organización, o no es tuya.

    El mismo error en los dos casos, con el criterio de ``assert_owned``: si
    "no existe" y "no es tuya" dieran respuestas distintas, se podrían enumerar
    organizaciones ajenas probando ids.
    """

    entity_label = "Organizacion"
    id_field = "organization_id"
    entity_is_feminine = True


class OrganizationNotAllowedError(AccountsError):
    """El plan del usuario no incluye el toggle de organización.

    402 y no 403: esto se arregla pagando, que es justo la diferencia que el
    cliente necesita para saber qué ofrecer.
    """

    default_code = ErrorCode.PLAN_FEATURE_NOT_INCLUDED
    default_status_code = 402
    expose_details = True

    def __init__(self) -> None:
        super().__init__(
            message="La suscripcion no tiene habilitada la gestion de organizaciones",
            details={"limitKey": "organization.members", "requiresOrganizationAddon": True},
            user_message=(
                "Tu plan no incluye la gestion de una organizacion. "
                "Puedes anyadirla desde la pagina de planes."
            ),
        )


class OrganizationAlreadyExistsError(AccountsError):
    """Un usuario es dueño de una organización como mucho."""

    default_code = ErrorCode.ENTITY_ALREADY_EXISTS
    default_status_code = 409

    def __init__(self) -> None:
        super().__init__(
            message="El usuario ya es duenyo de una organizacion",
            user_message="Ya tienes una organizacion. Solo se puede tener una.",
        )


class AlreadyInOrganizationError(AccountsError):
    """El usuario ya pertenece a una organización.

    Un usuario pertenece a lo sumo a una, y lo impone un ``UNIQUE`` de la base
    de datos; esto es solo el mensaje legible.
    """

    default_code = ErrorCode.CONSTRAINT_VIOLATION
    default_status_code = 409

    def __init__(self) -> None:
        super().__init__(
            message="El usuario ya pertenece a una organizacion",
            user_message=(
                "Esta cuenta ya forma parte de una organizacion. "
                "Tiene que salirse de ella antes de unirse a otra."
            ),
        )


class NotInOrganizationError(AccountsError):
    """La acción exige pertenecer a una organización y el usuario no está en ninguna."""

    default_code = ErrorCode.ENTITY_NOT_FOUND
    default_status_code = 404

    def __init__(self) -> None:
        super().__init__(
            message="El usuario no pertenece a ninguna organizacion",
            user_message="No formas parte de ninguna organizacion.",
        )


class InvitationInvalidError(AccountsError):
    """Invitación inexistente, ya respondida, revocada o caducada.

    Los cuatro casos dan el mismo error a propósito, con el mismo criterio que
    la verificación de correo: distinguirlos permitiría averiguar qué
    invitaciones existieron y a qué organizaciones.
    """

    default_code = ErrorCode.ENTITY_NOT_FOUND
    default_status_code = 400

    def __init__(self) -> None:
        super().__init__(
            message="Invitacion invalida, ya respondida o caducada",
            user_message=(
                "Esta invitacion no es valida o ha caducado. "
                "Pide a quien te invito que te mande otra."
            ),
        )


class CannotRemoveOwnerError(AccountsError):
    """No se puede expulsar al dueño de su propia organización.

    Ni él mismo puede salirse: la organización quedaría sin titular y sin nadie
    que pague. Primero se disuelve o se traspasa.
    """

    default_code = ErrorCode.CONSTRAINT_VIOLATION
    default_status_code = 409

    def __init__(self) -> None:
        super().__init__(
            message="El duenyo no puede salir de su propia organizacion",
            user_message=(
                "Eres el duenyo de esta organizacion. Para dejarla, "
                "tendrias que disolverla o traspasarla antes."
            ),
        )


class EmailNotVerifiedError(AccountsError):
    """La cuenta no ha confirmado su correo y la acción cuesta dinero.

    Es un **403**, no un 402: no se arregla pagando, se arregla pulsando el
    enlace del correo. Vive aquí y no en ``users`` porque quien la lanza es el
    motor de cuotas — importar ``users.exceptions`` desde aquí cerraría un
    ciclo de imports.
    """

    default_code = ErrorCode.EMAIL_NOT_VERIFIED
    default_status_code = 403

    def __init__(self) -> None:
        super().__init__(
            message="La cuenta no ha verificado su correo",
            user_message=(
                "Confirma tu correo electronico para poder usar esta funcion. "
                "Puedes pedir un enlace nuevo desde tu perfil."
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
