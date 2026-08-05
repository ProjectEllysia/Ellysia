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
from src.modules.shared.schemas import ErrorSchema
from src.modules.shared import utcnow_naive

from .services import Role, require_oauth_token, require_role
from .managers import UserManager, OAuthTokenManager, MFAManager
import src.modules.system.config_reading as CR
from .exceptions import (
    InvalidCredentialsError,
    PasswordChangedError,
    MfaChallengeInvalidError,
    InvalidMfaCodeError,
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

    user_id = OAUTH_MANAGER.verify_mfa_challenge(challenge_token)
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
@require_role(Role.ADMIN)
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
@require_role(Role.ADMIN)
@handle_exceptions(default_exception=DatabaseError, logger=logger)
def add_user_attribute(data: dict[str, Any], target_user_id: int):
    """Anadir atributos a un usuario"""
    current_user_id = get_current_user().id

    if not USER_MANAGER.can_manage_user(current_user_id, target_user_id):
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
@require_role(Role.ADMIN)
@handle_exceptions(default_exception=DatabaseError, logger=logger)
def remove_user_attribute(data: dict[str, Any], target_user_id: int):
    """Eliminar atributos de un usuario"""
    current_user_id = get_current_user().id

    if not USER_MANAGER.can_manage_user(current_user_id, target_user_id):
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
