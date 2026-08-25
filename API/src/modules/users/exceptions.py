from typing import Optional

from src.modules.shared._exceptions import (
    EllysiaException,
    EntityNotFoundError,
    ErrorCode,
    ErrorSeverity,
    DatabaseError,  # noqa: F401  — re-exportada: users/managers.py la importa desde aquí
)


class AuthenticationError(EllysiaException):
    default_code = ErrorCode.AUTHENTICATION_ERROR
    default_status_code = 401
    default_severity = ErrorSeverity.MEDIUM

    def __init__(self, message: str = "Error de autenticación", **kwargs):
        if "user_message" not in kwargs:
            kwargs["user_message"] = "No se pudo verificar su identidad."
        super().__init__(message=message, **kwargs)


class AuthorizationError(EllysiaException):
    default_code = ErrorCode.AUTHORIZATION_ERROR
    default_status_code = 403
    default_severity = ErrorSeverity.MEDIUM

    def __init__(self, message: str = "Error de autorización", **kwargs):
        if "user_message" not in kwargs:
            kwargs["user_message"] = "No tiene permisos para realizar esta acción."
        super().__init__(message=message, **kwargs)


class PermissionsError(AuthorizationError):
    default_code = ErrorCode.AUTHORIZATION_ERROR

    def __init__(self, message: str = "Permisos insuficientes", **kwargs):
        if "user_message" not in kwargs:
            kwargs["user_message"] = message
        super().__init__(message=message, **kwargs)


class InvalidCredentialsError(AuthenticationError):
    default_code = ErrorCode.INVALID_CREDENTIALS

    def __init__(self):
        super().__init__(
            message="Credenciales inválidas",
            user_message="Usuario o contraseña incorrectos."
        )


class PasswordChangedError(AuthenticationError):
    """La sesión/token quedó obsoleto porque la contraseña de acceso cambió.

    Se distingue de ``InvalidCredentialsError`` para que el cliente pueda mostrar
    una pantalla dedicada ("tu contraseña ha cambiado; inicia sesión de nuevo")
    en lugar de un error genérico. Se identifica por ``code == 1609``.
    """
    default_code = ErrorCode.PASSWORD_CHANGED

    def __init__(self):
        super().__init__(
            message="La contraseña fue cambiada; el token/sesión ya no es válido",
            user_message="Tu contraseña ha cambiado. Inicia sesión de nuevo.",
        )


class UserNotFoundError(EntityNotFoundError, AuthenticationError):
    default_code = ErrorCode.USER_NOT_FOUND
    # 401, no el 404 de EntityNotFoundError: se hereda de AuthenticationError
    # y se re-declara para que la mezcla no lo cambie. "Usuario no
    # encontrado" aquí es un fallo de autenticación, no un recurso ausente.
    default_status_code = 401
    default_severity = ErrorSeverity.MEDIUM

    entity_label = "Usuario"
    id_field = "id_usuario"


class UserBindingError(AuthenticationError):
    default_code = ErrorCode.UNBINDABLE_USER

    def __init__(self, username: str):
        super().__init__(
            message=f"No se pudo vincular el usuario '{username}' con una persona existente",
            details={"username": username},
            user_message=f"Error al crear el usuario debido a datos incompletos"
        )


class DuplicatedUserCredentials(AuthenticationError):
    default_code = ErrorCode.DUPLICATED_CREDENTIALS

    def __init__(self, credentials: str):
        super().__init__(
            message=f"Se ha detectado una credencial duplicada para un usuario",
            user_message=f"Se ha detectado duplicidad de datos para el siguiente valor: {credentials}"
        )


class ExistingUserError(AuthenticationError):
    default_code = ErrorCode.USER_ALREADY_EXISTS
    # 409, no el 401 que hereda de AuthenticationError: que un nombre de usuario
    # esté cogido no es un fallo de autenticación. Los dos endpoints que la
    # lanzan (sign-up de admin y alta pública) ya documentaban 409 en su
    # alt_response, así que hasta ahora contradecían su propio contrato — y un
    # cliente que trate el 401 como "sesión caducada" echaría al administrador
    # al intentar crear un usuario repetido.
    default_status_code = 409

    def __init__(self, username: str, email: str):
        super().__init__(
            message="Se ha intentado crear un usuario con un email o nombre de usuario existentes",
            details={"username": username, "email": email},
            user_message=f"""Ya existe un usuario con los siguientes parámetros: {f"email: {email}" if email is not None else "" } {"|" if username is not None and email is not None else ""} {f"username: {username}" if username is not None else "" }"""
        )


class ProfileUpdateError(AuthenticationError):
    default_code = ErrorCode.PROFILE_UPDATE_ERROR

    def __init__(self, message: str = "Error al actualizar el perfil"):
        super().__init__(
            message=message,
            user_message="No se pudo actualizar el perfil. Intente de nuevo."
        )


class MfaAlreadyEnabledError(AuthenticationError):
    """El usuario ya tiene un método TOTP confirmado; no se puede re-inscribir
    sin desactivarlo antes."""
    default_code = ErrorCode.MFA_ALREADY_ENABLED
    default_status_code = 409

    def __init__(self):
        super().__init__(
            message="El usuario ya tiene MFA (TOTP) activado y confirmado",
            user_message="Ya tienes la verificación en dos pasos activada.",
        )


class MfaNotEnabledError(AuthenticationError):
    """No existe una inscripción TOTP (confirmada o pendiente) para el usuario."""
    default_code = ErrorCode.MFA_NOT_ENABLED
    default_status_code = 400

    def __init__(self):
        super().__init__(
            message="El usuario no tiene MFA (TOTP) activado",
            user_message="No tienes la verificación en dos pasos activada.",
        )


class InvalidMfaCodeError(AuthenticationError):
    """El código TOTP o de recuperación no coincide."""
    default_code = ErrorCode.INVALID_MFA_CODE

    def __init__(self):
        super().__init__(
            message="Código MFA o de recuperación inválido",
            user_message="El código introducido no es válido.",
        )


class MfaChallengeInvalidError(AuthenticationError):
    """El challenge de MFA no existe, expiró o agotó sus intentos.

    ``user_message`` es pisable porque los dos flujos que lo usan siguen
    caminos distintos: el de login debe decir "inicia sesión de nuevo" y el de
    recuperación de contraseña "vuelve a solicitarlo".
    """
    default_code = ErrorCode.MFA_CHALLENGE_INVALID

    def __init__(self, user_message: Optional[str] = None):
        super().__init__(
            message="El challenge de MFA es inválido, expiró o agotó sus intentos",
            user_message=user_message or "La verificación ha expirado. Inicia sesión de nuevo.",
        )

# =========================================================================
# ALTA PÚBLICA Y VERIFICACIÓN DE CORREO
# =========================================================================

class RegistrationClosedError(AuthorizationError):
    """Esta instalación no acepta altas públicas.

    Es una decisión del despliegue (``general.registration.enabled``), no del
    usuario: un Ellysia interno de una empresa quiere el grifo cerrado y da de
    alta a su gente desde el panel.
    """

    default_code = ErrorCode.REGISTRATION_CLOSED

    def __init__(self) -> None:
        super().__init__(
            message="El registro publico esta deshabilitado en esta instalacion",
            user_message=(
                "Esta instalacion de Ellysia no acepta registros. "
                "Pide a un administrador que te cree la cuenta."
            ),
        )


class InvalidVerificationTokenError(AuthenticationError):
    """Enlace de verificación inexistente, ya usado o caducado.

    Los tres casos dan el mismo error a propósito: distinguirlos permitiría
    averiguar qué tokens existieron.
    """

    default_code = ErrorCode.INVALID_VERIFICATION_TOKEN
    default_status_code = 400

    def __init__(self) -> None:
        super().__init__(
            message="Token de verificacion invalido o caducado",
            user_message=(
                "Este enlace de confirmacion no es valido o ha caducado. "
                "Puedes pedir uno nuevo desde tu perfil."
            ),
        )


class EmailAlreadyVerifiedError(EllysiaException):
    """Se pidió reenviar la confirmación de un correo ya confirmado."""

    default_code = ErrorCode.VALIDATION_ERROR
    default_status_code = 409

    def __init__(self) -> None:
        super().__init__(
            message="El correo ya esta verificado",
            user_message="Tu correo ya esta confirmado.",
        )


# =========================================================================
# RECUPERACIÓN DE CONTRASEÑA
# =========================================================================


class PasswordResetTokenInvalidError(AuthenticationError):
    """Enlace de recuperación inexistente, ya usado o caducado.

    Los tres casos dan el mismo error a propósito: distinguirlos permitiría
    averiguar qué enlaces existieron.
    """

    default_code = ErrorCode.PASSWORD_RESET_TOKEN_INVALID
    default_status_code = 400

    def __init__(self) -> None:
        super().__init__(
            message="Token de recuperacion invalido o caducado",
            user_message=(
                "Este enlace de recuperación no es válido o ha caducado. "
                "Puedes pedir uno nuevo desde la pantalla de acceso."
            ),
        )
