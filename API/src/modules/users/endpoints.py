import logging
from typing import Any

from flask import request
from flask_smorest import Blueprint as SmorestBlueprint

from src.modules.shared._endpoints import limiter
from src.modules.shared._exceptions import (
    handle_exceptions,
    DatabaseError,
    IllegalStateError,
    EllysiaException,
)
from src.modules.shared.schemas import ErrorSchema, SuccessMessageSchema
from src.modules.shared import utcnow_naive

from .services import Role, require_oauth_token, require_role
from .managers import UserManager, OAuthTokenManager, MFAManager
import src.modules.system.config_reading as CR
from .exceptions import (
    InvalidCredentialsError,
    PasswordChangedError,
    MfaChallengeInvalidError,
    InvalidMfaCodeError,
    RegistrationClosedError,
)
from .model import User
from .schemas import (
    TokenRequestSchema,
    TokenResponseSchema,
    SignUpRequestSchema,
    SignUpResponseSchema,
    CheckCredentialsRequestSchema,
    CheckCredentialsResponseSchema,
    ChangePasswordRequestSchema,
    ChangePasswordResponseSchema,
    UpdateProfileRequestSchema,
    UserProfileSchema,
    UserListItemSchema,
    AttributesRequestSchema,
    UserAttributesResponseSchema,
    AttributeOperationResponseSchema,
    RevokeResponseSchema,
    MfaVerifyRequestSchema,
    MfaTotpSetupResponseSchema,
    MfaTotpConfirmRequestSchema,
    MfaTotpConfirmResponseSchema,
    MfaDisableRequestSchema,
    MfaStatusResponseSchema,
    RegisterRequestSchema,
    RegisterResponseSchema,
    VerifyEmailRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetRequestResponseSchema,
    PasswordResetMfaSchema,
    PasswordResetCheckRequestSchema,
    PasswordResetCheckResponseSchema,
    PasswordResetCompleteRequestSchema,
    DeletionPreviewSchema,
    DeleteAccountRequestSchema,
)


oauth_blp = SmorestBlueprint("oauth", __name__, description="Autenticacion OAuth 2.0")
users_blp = SmorestBlueprint("users", __name__, description="Gestion de usuarios")
logger = logging.getLogger(__name__)


USER_MANAGER = UserManager()
OAUTH_MANAGER = OAuthTokenManager()
MFA_MANAGER = MFAManager()


def get_current_user() -> "User":
    if not hasattr(request, "current_user"):
        user_id = request.current_user_id  # type: ignore
        user = UserManager().get_user_by_id(user_id)
        if user is None:
            raise IllegalStateError("'user' detectado como None")
        request.current_user = user  # type: ignore
    return request.current_user  # type: ignore


def _serialize_user_profile(user: "User", *, include_attributes: bool = False) -> dict[str, Any]:
    """Construye el dict de perfil de usuario compartido por los endpoints.

    Args:
        user: instancia ORM de ``User``.
        include_attributes: si True, añade la lista de nombres de atributos ABAC.
    """
    profile: dict[str, Any] = {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "role": user.role,
        "created_at": user.created_at,
        "password_changed_at": user.password_changed_at,
        # Sin esto el cliente no puede saber que la cuenta está pendiente de
        # confirmar, y el usuario se come un 403 al primer intento de hacer
        # cualquier cosa sin entender por qué ni cómo salir de ahí.
        "emailVerified": user.email_verified_at is not None,
        "mustChangePassword": bool(user.must_change_password),
    }
    if include_attributes:
        profile["attributes"] = [attribute.attribute_name for attribute in user.attributes]
    return profile


# =========================================================================
# OAUTH ENDPOINTS
# =========================================================================


@oauth_blp.post("/token")
@oauth_blp.arguments(TokenRequestSchema)
@oauth_blp.response(200, TokenResponseSchema, description="Token issued")
@oauth_blp.alt_response(400, schema=ErrorSchema, description="Invalid parameters")
@oauth_blp.alt_response(401, schema=ErrorSchema, description="Invalid credentials")
@limiter.limit("20 per hour; 100 per day")
def oauth_token(data: dict[str, Any]):
    """Emitir tokens OAuth 2.0 (password o refresh_token)"""
    grant_type = data["grantType"]

    if grant_type == "password":
        username = data["username"]
        password = data["password"]

        is_valid, user_id = UserManager().verify_credentials(username, password)
        if not is_valid or user_id is None:
            logger.warning(f"Login fallido para: {username}")
            raise InvalidCredentialsError()

        user = USER_MANAGER.get_user_by_id(user_id)

        # Un login con la contraseña correcta anula el enlace de recuperación
        # pendiente: la recuperación ya no hace falta y el enlace no debe
        # quedar vivo en el buzón por si alguien más lo tiene.
        USER_MANAGER.clear_pending_password_reset(user_id)

        # MFA activado: en vez de tokens reales, se emite un challenge de corta
        # duración que el cliente debe canjear en POST /oauth/mfa/verify tras
        # aportar el segundo factor. Cuentas sin MFA no ven ningún cambio.
        if MFA_MANAGER.is_enabled(user_id):
            challenge_token = OAUTH_MANAGER.create_mfa_challenge(user_id)
            logger.info(f"MFA requerido para: {username}")
            return {
                "mfaRequired": True,
                "challengeToken": challenge_token,
                "methods": ["totp"],
            }

        access_token = OAUTH_MANAGER.create_access_token(
            user_id=user_id, username=username,
            role=user.role if user else "role_user",
            password_changed_at=user.password_changed_at if user else None,
        )
        refresh_token = OAUTH_MANAGER.create_refresh_token(user_id)
        user_attrs = USER_MANAGER.get_user_attributes(user_id)

        logger.info(f"Tokens emitidos para: {username}")
        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": CR.jwt_config().access_token_expiry_minutes * 60,
            "refresh_token": refresh_token,
            "role": user.role if user else "role_user",
            "attributes": user_attrs,
        }

    if grant_type == "refresh_token":
        refresh_token_str = data["refresh_token"]
        user_id = OAUTH_MANAGER.verify_refresh_token(refresh_token_str)
        if not user_id:
            # Si el refresh falló porque la contraseña cambió, devolver un motivo
            # específico para que el cliente muestre la pantalla dedicada.
            if OAUTH_MANAGER.is_refresh_stale_by_password(refresh_token_str):
                raise PasswordChangedError()
            raise InvalidCredentialsError()

        user = USER_MANAGER.get_user_by_id(user_id)
        if not user:
            raise InvalidCredentialsError()

        access_token = OAUTH_MANAGER.create_access_token(
            user_id, user.username, user.role,  # type: ignore
            password_changed_at=user.password_changed_at,
        )
        user_attrs = USER_MANAGER.get_user_attributes(user_id)

        logger.info(f"Access token renovado para usuario ID: {user_id}")
        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": CR.jwt_config().access_token_expiry_minutes * 60,
            "role": user.role,
            "attributes": user_attrs,
        }

    raise InvalidCredentialsError()


@oauth_blp.post("/revoke")
@oauth_blp.response(200, RevokeResponseSchema, description="Token revoked")
@oauth_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@require_oauth_token
def oauth_revoke():
    """Revocar el token Bearer actual"""
    token = request.headers["Authorization"].split()[1]
    OAUTH_MANAGER.revoke_access_token(token)
    logger.info(f"Token revocado para: {get_current_user().username}")
    return {"message": "Token revoked successfully"}


@oauth_blp.post("/revoke-all")
@oauth_blp.response(200, RevokeResponseSchema, description="All tokens revoked")
@oauth_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@require_oauth_token
def oauth_revoke_all():
    """Revocar todos los tokens del usuario autenticado"""
    user = get_current_user()
    OAUTH_MANAGER.revoke_all_user_tokens(user.id)
    return {"message": "All tokens revoked successfully"}


@oauth_blp.post("/mfa/verify")
@oauth_blp.arguments(MfaVerifyRequestSchema)
@oauth_blp.response(200, TokenResponseSchema, description="MFA verified, tokens issued")
@oauth_blp.alt_response(400, schema=ErrorSchema, description="Invalid parameters")
@oauth_blp.alt_response(401, schema=ErrorSchema, description="Invalid code or challenge")
@limiter.limit("10 per minute; 30 per hour")
def oauth_mfa_verify(data: dict[str, Any]):
    """Verificar el segundo factor (TOTP o codigo de recuperacion) y emitir tokens"""
    challenge_token = data["challengeToken"]

    # Solo challenges de propósito "login": uno emitido para la recuperación de
    # contraseña no debe canjearse aquí por tokens reales.
    user_id = OAUTH_MANAGER.verify_mfa_challenge(challenge_token, purpose="login")
    if user_id is None:
        raise MfaChallengeInvalidError()

    user = USER_MANAGER.get_user_by_id(user_id)
    if user is None:
        raise MfaChallengeInvalidError()

    verified = MFA_MANAGER.verify_totp_or_recovery(
        user_id, code=data.get("code"), recovery_code=data.get("recoveryCode"),
    )
    if not verified:
        OAUTH_MANAGER.register_mfa_challenge_failure(challenge_token)
        logger.warning(f"Codigo MFA invalido para: {user.username}")
        raise InvalidMfaCodeError()

    OAUTH_MANAGER.consume_mfa_challenge(challenge_token)

    access_token = OAUTH_MANAGER.create_access_token(
        user_id=user_id, username=user.username, role=user.role,
        password_changed_at=user.password_changed_at,
        mfa_at=utcnow_naive(),
    )
    refresh_token = OAUTH_MANAGER.create_refresh_token(user_id)
    user_attrs = USER_MANAGER.get_user_attributes(user_id)

    logger.info(f"MFA verificado, tokens emitidos para: {user.username}")
    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": CR.jwt_config().access_token_expiry_minutes * 60,
        "refresh_token": refresh_token,
        "role": user.role,
        "attributes": user_attrs,
    }


# =========================================================================
# SELF-APPLIED ENDPOINTS
# =========================================================================


@users_blp.post("/check-credentials")
@users_blp.arguments(CheckCredentialsRequestSchema)
@users_blp.response(200, CheckCredentialsResponseSchema, description="Valid credentials")
@users_blp.alt_response(401, schema=ErrorSchema, description="Invalid credentials")
@limiter.limit("10 per minute; 30 per hour")
@handle_exceptions(default_exception=InvalidCredentialsError, logger=logger)
def check_credentials(data: dict[str, Any]):
    """Validar credenciales de usuario (endpoint legacy)"""
    username = data["username"]
    password = data["password"]

    is_valid, user_id = USER_MANAGER.verify_credentials(username, password)
    if not is_valid:
        raise InvalidCredentialsError()

    logger.info(f"Credenciales validas para: {username} (ID: {user_id})")
    return {"message": "Credenciales validas", "isValid": True, "userId": user_id, "username": username}


@users_blp.put("/change-password")
@users_blp.arguments(ChangePasswordRequestSchema)
@users_blp.response(200, ChangePasswordResponseSchema, description="Password changed")
@users_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@require_oauth_token
@limiter.limit("5 per hour; 10 per day")
@handle_exceptions(default_exception=DatabaseError, logger=logger)
def change_password(data: dict[str, Any]):
    """Cambiar la contrasena del usuario autenticado. Invalida todos sus tokens."""
    current_password = data["currentPassword"]
    new_password = data["newPassword"]

    user = get_current_user()
    user_id = user.id
    username = user.username

    # S11: antes solo se comparaba en cliente (ProfileView.vue); una operación
    # sensible autorizada solo por JWT es insuficiente — se re-verifica aquí.
    is_valid, _ = USER_MANAGER.verify_credentials(username, current_password)
    if not is_valid:
        raise InvalidCredentialsError()

    USER_MANAGER.update_user_password(user_id, new_password)
    OAUTH_MANAGER.revoke_all_user_tokens(user_id)

    logger.info(f"Contrasena cambiada para: {username} (ID: {user_id})")
    return {
        "message": "Contrasena cambiada exitosamente. Por favor, inicia sesion de nuevo.",
        "userId": user_id,
        "username": username,
    }


@users_blp.get("/me")
@users_blp.response(200, UserProfileSchema, description="Current user profile")
@users_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@require_oauth_token
@limiter.limit("30 per hour; 100 per day")
@handle_exceptions(default_exception=DatabaseError, logger=logger)
def get_current_profile():
    """Obtener el perfil del usuario autenticado"""
    user = get_current_user()
    return _serialize_user_profile(user)


@users_blp.put("/me")
@users_blp.arguments(UpdateProfileRequestSchema)
@users_blp.response(200, UserProfileSchema, description="Updated profile")
@users_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@require_oauth_token
@limiter.limit("10 per hour; 20 per day")
@handle_exceptions(default_exception=DatabaseError, logger=logger)
def update_current_profile(data: dict[str, Any]):
    """Actualizar nombre y apellidos del perfil propio"""
    first_name = data["first_name"]
    last_name = data["last_name"]

    user = get_current_user()
    user = USER_MANAGER.update_user_profile(user.id, first_name, last_name)

    return _serialize_user_profile(user)


@users_blp.post("/sign-up")
@users_blp.arguments(SignUpRequestSchema)
@users_blp.response(201, SignUpResponseSchema, description="User created")
@users_blp.alt_response(400, schema=ErrorSchema, description="Validation error")
@users_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@users_blp.alt_response(403, schema=ErrorSchema, description="Insufficient role")
@users_blp.alt_response(409, schema=ErrorSchema, description="Already exists")
@limiter.limit("10 per hour; 20 per day")
@require_oauth_token
@require_role(Role.ADMIN)
@handle_exceptions(default_exception=DatabaseError, logger=logger)
def sign_up_user(data: dict[str, Any]):
    """Registrar un nuevo usuario (requiere role_admin o role_root)"""
    username = data["username"]
    email = data["email"]
    first_name = data["first_name"]
    last_name = data["last_name"]
    password = data["password"]
    requested_role = data.get("role") or "role_user"
    current_user_id = get_current_user().id

    user = USER_MANAGER.sign_in_user(
        username=username,
        email=email,
        first_name=first_name,
        last_name=last_name,
        password=password,
        role=requested_role,
        actor_id=current_user_id,
    )
    logger.info(f"Usuario registrado: {username} con rol {requested_role} (ID: {user.id})")
    return {
        "message": "Usuario registrado exitosamente",
        "userId": user.id,
        "username": user.username,
        "email": email,
        "role": requested_role,
    }


# =========================================================================
# BAJA DE LA CUENTA
# =========================================================================


@users_blp.get("/me/deletion-preview")
@users_blp.response(200, DeletionPreviewSchema, description="What deleting the account destroys")
@users_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@limiter.limit("30 per hour")
@require_oauth_token
@handle_exceptions(default_exception=DatabaseError, logger=logger)
def preview_account_deletion():
    """Que se destruye si esta cuenta se borra. No borra nada.

    Alimenta el aviso de confirmacion. Lo importante que devuelve es la
    consecuencia sobre terceros: si el usuario es duenyo de una organizacion,
    esta DESAPARECE con su cuenta y sus miembros se quedan sin ella.
    """
    return USER_MANAGER.preview_deletion(get_current_user().id)


@users_blp.delete("/me")
@users_blp.arguments(DeleteAccountRequestSchema)
@users_blp.response(200, SuccessMessageSchema, description="Account deleted")
@users_blp.alt_response(401, schema=ErrorSchema, description="Wrong password or not authenticated")
@limiter.limit("5 per hour")
@require_oauth_token
@handle_exceptions(default_exception=DatabaseError, logger=logger)
def delete_own_account(data: dict[str, Any]):
    """Borrar la cuenta y todo lo que cuelga de ella.

    Si el usuario es duenyo de una organizacion, esta se disuelve: sus miembros
    conservan cuenta, datos y plan personal, pero pierden lo que heredaban.
    Se re-verifica la contrasenya porque un token robado no debe bastar para la
    operacion mas destructiva del producto.
    """
    user = get_current_user()
    username = user.username
    USER_MANAGER.delete_own_account(user.id, data["password"])
    logger.info(f"Cuenta eliminada a peticion del propio usuario: {username}")
    return {"message": "Tu cuenta y todos tus datos se han eliminado."}


# =========================================================================
# ALTA PUBLICA Y VERIFICACION DE CORREO
# =========================================================================


@users_blp.post("/register")
@users_blp.arguments(RegisterRequestSchema)
@users_blp.response(201, RegisterResponseSchema, description="Account created, verification email sent")
@users_blp.alt_response(400, schema=ErrorSchema, description="Validation error")
@users_blp.alt_response(403, schema=ErrorSchema, description="Public registration disabled")
@users_blp.alt_response(409, schema=ErrorSchema, description="Username or email already taken")
@limiter.limit("5 per hour; 20 per day")
@handle_exceptions(default_exception=DatabaseError, logger=logger)
def register_user(data: dict[str, Any]):
    """Crear una cuenta desde la web, sin intervencion de un administrador"""
    if not CR.registration_config().enabled:
        raise RegistrationClosedError()

    # Rol forzado a role_user y correo sin verificar: son las dos diferencias
    # con el alta de un administrador, y las dos son deliberadas. Los atributos
    # ABAC por defecto los pone sign_in_user, iguales para todo el mundo.
    user = USER_MANAGER.sign_in_user(
        username=data["username"],
        email=data["email"],
        first_name=data["first_name"],
        last_name=data["last_name"],
        password=data["password"],
        email_verified=False,
    )

    # No se crea fila en Subscription: su ausencia ya significa "plan por
    # defecto" (ver accounts/services/entitlements.py).
    USER_MANAGER.issue_email_verification(user.id)

    logger.info(f"Alta publica: {user.username} (ID: {user.id})")
    return {
        "message": "Cuenta creada. Te hemos enviado un correo para confirmarla.",
        "userId": user.id,
        "username": user.username,
        "email": user.email,
        "emailVerified": False,
    }


@users_blp.post("/verify-email")
@users_blp.arguments(VerifyEmailRequestSchema)
@users_blp.response(200, SuccessMessageSchema, description="Email verified")
@users_blp.alt_response(400, schema=ErrorSchema, description="Invalid or expired token")
@limiter.limit("20 per hour")
@handle_exceptions(default_exception=DatabaseError, logger=logger)
def verify_email(data: dict[str, Any]):
    """Confirmar una direccion de correo con el token del enlace

    Publico a proposito: el token es la unica identidad, igual que en el quiz
    de Aegis. Quien pulsa el enlace no tiene por que tener la sesion abierta,
    ni siquiera en el mismo dispositivo.
    """
    user = USER_MANAGER.verify_email(data["token"])
    return {"message": f"Correo confirmado. Ya puedes usar Ellysia, {user.first_name}."}


@users_blp.post("/verify-email/resend")
@users_blp.response(200, SuccessMessageSchema, description="Verification email sent again")
@users_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@users_blp.alt_response(409, schema=ErrorSchema, description="Email already verified")
@limiter.limit("3 per hour")
@require_oauth_token
@handle_exceptions(default_exception=DatabaseError, logger=logger)
def resend_email_verification():
    """Pedir un nuevo enlace de confirmacion. Invalida el anterior."""
    user = get_current_user()
    USER_MANAGER.issue_email_verification(user.id)
    return {"message": "Te hemos enviado un correo de confirmacion."}


# =========================================================================
# RECUPERACIÓN DE CONTRASEÑA
# =========================================================================


@users_blp.post("/password-reset/request")
@users_blp.arguments(PasswordResetRequestSchema)
@users_blp.response(200, PasswordResetRequestResponseSchema, description="Reset requested")
@limiter.limit("3 per hour; 10 per day")
@handle_exceptions(default_exception=DatabaseError, logger=logger)
def password_reset_request(data: dict[str, Any]):
    """Solicitar la recuperacion de contrasenya (fase 1)

    La respuesta es generica — ``sent`` tanto si la cuenta existe como si no,
    para que el endpoint no sirva de oraculo de usuarios. Si la cuenta tiene
    MFA, en su lugar devuelve un challenge para POST /password-reset/mfa: el
    enlace no sale hasta que el segundo factor verifica.
    """
    return USER_MANAGER.request_password_reset(data["identifier"])


@users_blp.post("/password-reset/mfa")
@users_blp.arguments(PasswordResetMfaSchema)
@users_blp.response(200, PasswordResetRequestResponseSchema, description="MFA verified, reset link sent")
@users_blp.alt_response(401, schema=ErrorSchema, description="Invalid MFA code or challenge")
@limiter.limit("10 per minute; 30 per hour")
@handle_exceptions(default_exception=DatabaseError, logger=logger)
def password_reset_mfa(data: dict[str, Any]):
    """Verificar el segundo factor de la recuperacion (fase 2)

    Endpoint aparte de la fase 1 para poder darle el rate limit del resto de
    verificaciones MFA (reintentos permitidos): compartir el 3/hora de la
    solicitud bloquearia a un usuario legitimo que errase un par de codigos.
    Solo tras el factor correcto se minta el enlace y se envia al correo
    registrado de la cuenta.
    """
    return USER_MANAGER.confirm_password_reset_mfa(
        data["challengeToken"],
        code=data.get("code"),
        recovery_code=data.get("recoveryCode"),
    )


@users_blp.post("/password-reset/check")
@users_blp.arguments(PasswordResetCheckRequestSchema)
@users_blp.response(200, PasswordResetCheckResponseSchema, description="Token validity")
@limiter.limit("10 per minute; 60 per hour")
@handle_exceptions(default_exception=DatabaseError, logger=logger)
def password_reset_check(data: dict[str, Any]):
    """Comprobar si un enlace de recuperacion sigue vivo.

    Publico a proposito: quien pulsa el enlace no tiene por que tener la sesion
    abierta. No consume el token ni revela a que cuenta pertenece.
    """
    return {"valid": USER_MANAGER.check_password_reset_token(data["token"])}


@users_blp.post("/password-reset/reset")
@users_blp.arguments(PasswordResetCompleteRequestSchema)
@users_blp.response(200, SuccessMessageSchema, description="Password updated")
@users_blp.alt_response(400, schema=ErrorSchema, description="Invalid or expired token")
@limiter.limit("5 per hour; 10 per day")
@handle_exceptions(default_exception=DatabaseError, logger=logger)
def password_reset_complete(data: dict[str, Any]):
    """Cambiar la contrasenya con el enlace de recuperacion. Invalida todos los tokens."""
    user_id = USER_MANAGER.complete_password_reset(data["token"], data["newPassword"])
    OAUTH_MANAGER.revoke_all_user_tokens(user_id)
    return {"message": "Contrasenya actualizada. Ya puedes entrar con tu nueva clave."}


@users_blp.get("")
@users_blp.response(200, UserListItemSchema(many=True), description="List of all users")
@users_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@users_blp.alt_response(403, schema=ErrorSchema, description="Insufficient role")
@require_oauth_token
@require_role(Role.ADMIN)
@handle_exceptions(default_exception=DatabaseError, logger=logger)
def list_all_users():
    """Listar todos los usuarios del sistema con sus atributos"""
    users = USER_MANAGER.get_all_users()
    return [_serialize_user_profile(user, include_attributes=True) for user in users]


@users_blp.get("/<int:target_user_id>/attributes")
@users_blp.response(200, UserAttributesResponseSchema, description="User attributes")
@users_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@users_blp.alt_response(403, schema=ErrorSchema, description="Insufficient role")
@require_oauth_token
@handle_exceptions(default_exception=DatabaseError, logger=logger)
def list_user_attributes(target_user_id: int):
    """Listar los atributos de un usuario especifico"""
    current_user = get_current_user()
    user_id = current_user.id

    if not USER_MANAGER.can_manage_user(user_id, target_user_id):
        logger.warning(f"Usuario {user_id} intento ver atributos de {target_user_id} sin permiso")
        raise EllysiaException(
            "No tienes permiso para ver atributos de este usuario",
            status_code=403,
        )

    target_user = USER_MANAGER.get_user_by_id(target_user_id)
    return {
        "user_id": target_user_id,
        "attributes": [attribute.attribute_name for attribute in target_user.attributes],
        "role": target_user.role if target_user else "role_user",
    }


@users_blp.put("/<int:target_user_id>/attributes")
@users_blp.arguments(AttributesRequestSchema)
@users_blp.response(200, AttributeOperationResponseSchema, description="Attributes added")
@users_blp.alt_response(400, schema=ErrorSchema, description="Validation error")
@users_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@users_blp.alt_response(403, schema=ErrorSchema, description="Insufficient role")
@require_oauth_token
@handle_exceptions(default_exception=DatabaseError, logger=logger)
def add_user_attribute(data: dict[str, Any], target_user_id: int):
    """Anadir atributos a un usuario"""
    current_user_id = get_current_user().id

    if not USER_MANAGER.can_administer_user(current_user_id, target_user_id):
        logger.warning(f"Usuario {current_user_id} intento anadir atributos a {target_user_id} sin permiso")
        raise EllysiaException(
            "No tienes permiso para gestionar atributos de este usuario",
            status_code=403,
        )

    attrs_to_add = data["attributes"]
    added_attrs = USER_MANAGER.add_user_attributes(
        user_id=target_user_id, attribute_names=attrs_to_add,
    )

    logger.info(f"Atributos {added_attrs} anadidos al usuario {target_user_id}")
    return {"message": "Attributes added", "attributes": added_attrs}


@users_blp.delete("/<int:target_user_id>/attributes")
@users_blp.arguments(AttributesRequestSchema)
@users_blp.response(200, AttributeOperationResponseSchema, description="Attributes removed")
@users_blp.alt_response(400, schema=ErrorSchema, description="Validation error")
@users_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@users_blp.alt_response(403, schema=ErrorSchema, description="Insufficient role")
@require_oauth_token
@handle_exceptions(default_exception=DatabaseError, logger=logger)
def remove_user_attribute(data: dict[str, Any], target_user_id: int):
    """Eliminar atributos de un usuario"""
    current_user_id = get_current_user().id

    if not USER_MANAGER.can_administer_user(current_user_id, target_user_id):
        logger.warning(
            f"Usuario {current_user_id} intento eliminar atributos de {target_user_id} sin permiso"
        )
        raise EllysiaException(
            "No tienes permiso para gestionar atributos de este usuario",
            status_code=403,
        )

    attrs_to_remove = data["attributes"]
    USER_MANAGER.remove_user_attributes(
        user_id=target_user_id, attribute_names=attrs_to_remove,
    )

    logger.info(f"Atributos {attrs_to_remove} eliminados del usuario {target_user_id}")
    return {"message": "Attributes removed", "attributes": attrs_to_remove}


# =========================================================================
# MFA (TOTP) ENDPOINTS
# =========================================================================


@users_blp.get("/mfa")
@users_blp.response(200, MfaStatusResponseSchema, description="MFA status")
@users_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@require_oauth_token
@handle_exceptions(default_exception=DatabaseError, logger=logger)
def get_mfa_status():
    """Consultar si el usuario autenticado tiene MFA (TOTP) activado"""
    return MFA_MANAGER.get_status(get_current_user().id)


@users_blp.post("/mfa/totp/setup")
@users_blp.response(200, MfaTotpSetupResponseSchema, description="TOTP setup started")
@users_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@users_blp.alt_response(409, schema=ErrorSchema, description="MFA already enabled")
@require_oauth_token
@limiter.limit("10 per hour; 20 per day")
@handle_exceptions(default_exception=DatabaseError, logger=logger)
def setup_totp():
    """Generar un secreto TOTP y su URI de aprovisionamiento (para el QR)"""
    user = get_current_user()
    result = MFA_MANAGER.setup_totp(user.id, user.username)
    logger.info(f"Setup de TOTP iniciado para: {user.username}")
    return result


@users_blp.post("/mfa/totp/confirm")
@users_blp.arguments(MfaTotpConfirmRequestSchema)
@users_blp.response(200, MfaTotpConfirmResponseSchema, description="TOTP confirmed")
@users_blp.alt_response(400, schema=ErrorSchema, description="TOTP setup not started")
@users_blp.alt_response(401, schema=ErrorSchema, description="Invalid code")
@require_oauth_token
@limiter.limit("10 per hour; 30 per day")
@handle_exceptions(default_exception=DatabaseError, logger=logger)
def confirm_totp(data: dict[str, Any]):
    """Confirmar el primer codigo TOTP y obtener los codigos de recuperacion"""
    user = get_current_user()
    recovery_codes = MFA_MANAGER.confirm_totp(user.id, data["code"])
    logger.info(f"MFA (TOTP) activado para: {user.username}")
    return {
        "message": "MFA activado correctamente. Guarda tus codigos de recuperacion en un lugar seguro.",
        "recoveryCodes": recovery_codes,
    }


@users_blp.delete("/mfa/totp")
@users_blp.arguments(MfaDisableRequestSchema)
@users_blp.response(200, RevokeResponseSchema, description="TOTP disabled")
@users_blp.alt_response(401, schema=ErrorSchema, description="Invalid code or not authenticated")
@require_oauth_token
@limiter.limit("10 per hour; 20 per day")
@handle_exceptions(default_exception=DatabaseError, logger=logger)
def disable_totp(data: dict[str, Any]):
    """Desactivar MFA (TOTP). Requiere un codigo TOTP o de recuperacion vigente."""
    user = get_current_user()
    MFA_MANAGER.disable_totp(user.id, code=data.get("code"), recovery_code=data.get("recoveryCode"))
    logger.info(f"MFA (TOTP) desactivado para: {user.username}")
    return {"message": "MFA desactivado correctamente"}
