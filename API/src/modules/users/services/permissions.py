import logging
from enum import Enum
from functools import wraps
from typing import List, Optional, Set

from flask import request, jsonify

from src.modules.shared._exceptions import MissingParameterError, MissingJsonBodyError, EllysiaException, ErrorCode

from ..managers import OAuthTokenManager
from ..repositories import AttributeRepository, UserRepository
from src.modules.infrastructure import UnitOfWork


logger = logging.getLogger(__name__)


# =========================================================================
# ROLE ENUM — structural identity (who the user is)
# =========================================================================

class Role(Enum):
    """
    Structural roles that express a user's identity tier.

    Roles are mutually exclusive and stored in User.role — never in
    UserAttribute. The hierarchy is: ROOT > ADMIN > USER.

    Use Role to gate access based on identity level (e.g. only admins
    can create users). Use AttributeType for fine-grained capability checks
    (e.g. only users with themis_read can list scans).
    """
    ROOT  = "role_root"
    ADMIN = "role_admin"
    USER  = "role_user"

    @property
    def db_name(self) -> str:
        return self.value # type: ignore

    @classmethod
    def hierarchy(cls) -> List[str]:
        """Return role values ordered from least to most privileged."""
        return ["role_user", "role_admin", "role_root"]

    def rank(self) -> int:
        """Return the privilege rank of this role (higher = more privileged)."""
        return self.hierarchy().index(self.value) # type: ignore


# =========================================================================
# AttributeType ENUM — fine-grained ABAC capabilities (what the user can do)
# =========================================================================

_ATTRIBUTE_DESCRIPTIONS: dict[str, str] = {
    "aegis_create":    "Create access for Aegis awareness pills",
    "aegis_read":      "Read access for Aegis awareness pills",
    "aegis_update":    "Update access for Aegis awareness pills",
    "aegis_delete":    "Delete access for Aegis awareness pills",
    "themis_create": "Create access for Themis security scans",
    "themis_read":   "Read access for Themis security scans",
    "themis_update": "Update access for Themis security scans",
    "themis_delete": "Delete access for Themis security scans",
    "themis_folder_create": "Create access for Themis scan folders",
    "themis_folder_read":   "Read access for Themis scan folders",
    "themis_folder_update": "Update access for Themis scan folders",
    "themis_folder_delete": "Delete access for Themis scan folders",
    "acheron_create":  "Create access for Acheron vault secrets",
    "acheron_read":    "Read access for Acheron vault secrets",
    "acheron_update":  "Update access for Acheron vault secrets",
    "acheron_delete":  "Delete access for Acheron vault secrets",
    "iris_create":     "Create access for Iris email header analysis",
    "iris_read":       "Read access for Iris email header analysis",
    "iris_update":     "Update access for Iris email header analysis",
    "iris_delete":     "Delete access for Iris email header analysis",
    "themis_schedule_create": "Create access for scheduled scans",
    "themis_schedule_read":   "Read access for scheduled scans",
    "themis_schedule_delete": "Delete access for scheduled scans",
    "hygeia_create":   "Create access for Hygeia monitored assets",
    "hygeia_read":     "Read access for Hygeia monitored assets",
    "hygeia_update":   "Update access for Hygeia monitored assets",
    "hygeia_delete":   "Delete access for Hygeia monitored assets",
}


class AttributeType(Enum):
    """
    ABAC capability attributes for fine-grained access control.

    Attributes follow the naming convention {MODULE}_{OPERATION} and are
    stored as rows in the UserAttribute table. They express what a user
    can do within a specific module, independently of their role tier.

    A user's effective permissions are the union of:
        - All permissions granted by their Role (via ROLE_PERMISSIONS), AND
        - Any extra AttributeType rows in UserAttribute.

    Root users bypass all AttributeType checks — they have implicit access
    to every operation without needing explicit attribute rows.
    """
    AEGIS_CREATE    = "aegis_create"
    AEGIS_READ      = "aegis_read"
    AEGIS_UPDATE    = "aegis_update"
    AEGIS_DELETE    = "aegis_delete"

    THEMIS_CREATE = "themis_create"
    THEMIS_READ   = "themis_read"
    THEMIS_UPDATE = "themis_update"
    THEMIS_DELETE = "themis_delete"

    THEMIS_FOLDER_CREATE = "themis_folder_create"
    THEMIS_FOLDER_READ   = "themis_folder_read"
    THEMIS_FOLDER_UPDATE = "themis_folder_update"
    THEMIS_FOLDER_DELETE = "themis_folder_delete"

    ACHERON_CREATE  = "acheron_create"
    ACHERON_READ    = "acheron_read"
    ACHERON_UPDATE  = "acheron_update"
    ACHERON_DELETE  = "acheron_delete"

    IRIS_CREATE     = "iris_create"
    IRIS_READ       = "iris_read"
    IRIS_UPDATE     = "iris_update"
    IRIS_DELETE     = "iris_delete"

    THEMIS_SCHEDULE_CREATE = "themis_schedule_create"
    THEMIS_SCHEDULE_READ   = "themis_schedule_read"
    THEMIS_SCHEDULE_DELETE = "themis_schedule_delete"

    HYGEIA_CREATE = "hygeia_create"
    HYGEIA_READ   = "hygeia_read"
    HYGEIA_UPDATE = "hygeia_update"
    HYGEIA_DELETE = "hygeia_delete"

    @property
    def db_name(self) -> str:
        return self.value  # type: ignore

    @property
    def db_description(self) -> str:
        return _ATTRIBUTE_DESCRIPTIONS.get(self.value, "")  # type: ignore


# =========================================================================
# ROLE → AttributeType MATRIX
# =========================================================================

# Defines the baseline permissions each role grants implicitly.
# When checking permissions, a user's effective set is:
#     ROLE_PERMISSIONS[user.role]  ∪  {explicit UserAttribute rows}
#
# Root is intentionally absent — it short-circuits all checks.

ROLE_PERMISSIONS: dict[Role, Set[AttributeType]] = {
    Role.USER: {
        AttributeType.AEGIS_READ,
        AttributeType.THEMIS_READ,
        AttributeType.ACHERON_READ,
        AttributeType.IRIS_READ,
        AttributeType.THEMIS_SCHEDULE_READ,
        AttributeType.THEMIS_FOLDER_CREATE,
        AttributeType.THEMIS_FOLDER_READ,
        AttributeType.THEMIS_FOLDER_UPDATE,
        AttributeType.THEMIS_FOLDER_DELETE,
        AttributeType.HYGEIA_CREATE,
        AttributeType.HYGEIA_READ,
        AttributeType.HYGEIA_UPDATE,
        AttributeType.HYGEIA_DELETE,
    },
    Role.ADMIN: {
        AttributeType.AEGIS_CREATE,
        AttributeType.AEGIS_READ,
        AttributeType.AEGIS_UPDATE,
        AttributeType.AEGIS_DELETE,
        AttributeType.THEMIS_CREATE,
        AttributeType.THEMIS_READ,
        AttributeType.THEMIS_UPDATE,
        AttributeType.THEMIS_DELETE,
        AttributeType.THEMIS_FOLDER_CREATE,
        AttributeType.THEMIS_FOLDER_READ,
        AttributeType.THEMIS_FOLDER_UPDATE,
        AttributeType.THEMIS_FOLDER_DELETE,
        AttributeType.ACHERON_READ,
        AttributeType.IRIS_CREATE,
        AttributeType.IRIS_READ,
        AttributeType.IRIS_UPDATE,
        AttributeType.IRIS_DELETE,
        AttributeType.THEMIS_SCHEDULE_CREATE,
        AttributeType.THEMIS_SCHEDULE_READ,
        AttributeType.THEMIS_SCHEDULE_DELETE,
        AttributeType.HYGEIA_CREATE,
        AttributeType.HYGEIA_READ,
        AttributeType.HYGEIA_UPDATE,
        AttributeType.HYGEIA_DELETE,
    },
}


# =========================================================================
# DECORATORS
# =========================================================================

def require_oauth_token(f):
    """
    Verifica el Bearer token en la cabecera Authorization.

    Inyecta en el request:
        - request.current_user_id   (int)
        - request.current_username  (str)
        - request.current_user_role (str)

    Cierra siempre la sesión del OAuthTokenManager en un bloque
    finally para que la conexión se devuelva al pool.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            auth_header = request.headers.get("Authorization")
            if not auth_header:
                return jsonify({
                    "error": "unauthorized",
                    "error_description": "Missing Authorization header",
                }), 401

            parts = auth_header.split()
            if len(parts) != 2 or parts[0].lower() != "bearer":
                return jsonify({
                    "error": "unauthorized",
                    "error_description": "Invalid Authorization header format. Use: Bearer <token>",
                }), 401

            token = parts[1]
            manager = OAuthTokenManager()
            payload = manager.verify_access_token(token)

            if not payload:
                # Distinguir un token obsoleto por cambio de contraseña de un fallo
                # genérico, para que el cliente muestre la pantalla dedicada.
                if manager.is_token_stale_by_password(token):
                    return jsonify({
                        "error": "password_changed",
                        "error_description": "Tu contraseña ha cambiado. Inicia sesión de nuevo.",
                        "code": ErrorCode.PASSWORD_CHANGED.value,
                    }), 401
                return jsonify({
                    "error": "invalid_token",
                    "error_description": "The access token is invalid or expired",
                }), 401

            request.current_user_id   = int(payload.get("sub", "0"))      # type: ignore[attr-defined]
            request.current_username  = payload.get("username", "")       # type: ignore[attr-defined]
            request.current_user_role = payload.get("role", "role_user")  # type: ignore[attr-defined]

            return f(*args, **kwargs)

        except (EllysiaException, MissingParameterError, MissingJsonBodyError):
            raise
        except Exception as exc:
            logger.exception("Error durante la autenticación")
            return jsonify({
                "error": "server_error",
                "error_description": "Authentication error",
            }), 500

    return decorated


def require_role(minimum_role: Role):
    """
    Verifica que el usuario tiene al menos el rol indicado en la jerarquía.

    Jerarquía (de menor a mayor): USER < ADMIN < ROOT.
    Debe usarse DESPUÉS de @require_oauth_token.

    S9: el rol se revalida contra BD en cada llamada en vez de confiar solo
    en el claim del JWT — un cambio de rol (p. ej. degradar a un admin)
    surte efecto en la siguiente petición, no solo cuando el access token
    expire (ventana de hasta ``access_token_expiry_minutes``). Se acepta el
    coste de una query extra por petición porque este decorador solo protege
    endpoints de baja frecuencia (``/system``, `/users``); los endpoints de
    alto tráfico (Themis/Iris/Aegis/Acheron) usan ``require_attributes``, que
    no se toca aquí para no duplicar su query ya existente en el hot path.

    Args:
        minimum_role: Rol mínimo requerido.

    Returns:
        403 si el usuario está por debajo del nivel requerido.

    Ejemplo:
        @require_oauth_token
        @require_role(Role.ADMIN)
        def crear_usuario(): ...
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user_id = getattr(request, "current_user_id", None)

            user_role_str = Role.USER.value
            if user_id is not None:
                with UnitOfWork() as uow:
                    db_user = UserRepository(uow).get_by_id(user_id)
                if db_user is not None:
                    user_role_str = db_user.role

            try:
                user_role = Role(user_role_str)
            except ValueError:
                user_role = Role.USER

            if user_role.rank() < minimum_role.rank():
                logger.warning(
                    f"Usuario {user_id} (rol={user_role_str}) denegado. "
                    f"Se requiere mínimo: {minimum_role.value}"
                )
                return jsonify({
                    "error": "forbidden",
                    "error_description": f"Requires at least role: {minimum_role.value}",
                }), 403

            return f(*args, **kwargs)
        return decorated
    return decorator


def require_attributes(
    at_least_one: Optional[List[AttributeType]] = None,
    all_required: Optional[List[AttributeType]] = None,
):
    """
    Verifica permisos ABAC del usuario teniendo en cuenta su rol.

    Los permisos efectivos son la unión de:
        - Permisos base del rol (ROLE_PERMISSIONS)
        - Atributos explícitos en UserAttribute

    Los usuarios con Role.ROOT bypasean siempre esta verificación.
    Debe usarse DESPUÉS de @require_oauth_token.

    Args:
        at_least_one: El usuario debe tener AL MENOS UNO de estos permisos.
        all_required: El usuario debe tener TODOS estos permisos.

    Returns:
        403 si el usuario no cumple los requisitos.

    Ejemplo:
        @require_oauth_token
        @require_permissions(at_least_one=[AttributeType.THEMIS_READ])
        def listar_scans(): ...

        @require_oauth_token
        @require_permissions(all_required=[AttributeType.ACHERON_CREATE, AttributeType.ACHERON_READ])
        def crear_secreto(): ...
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user_id       = getattr(request, "current_user_id", None)
            user_role_str = getattr(request, "current_user_role", Role.USER.value)

            if user_id is None:
                return jsonify({
                    "error": "forbidden",
                    "error_description": "Authentication required before AttributeType check",
                }), 403

            # Root bypasses all AttributeType checks.
            if user_role_str == Role.ROOT.value:
                return f(*args, **kwargs)

            try:
                # Calcular permisos efectivos usando el repositorio
                try:
                    role_enum = Role(user_role_str)
                except ValueError:
                    role_enum = Role.USER
                baseline = {permission.db_name for permission in ROLE_PERMISSIONS.get(role_enum, set())}

                with UnitOfWork() as uow:
                    repo = AttributeRepository(uow)
                    extra_attrs = {attr.attribute_name for attr in repo.get_by_user(user_id)}
                effective = baseline | extra_attrs

                missing_at_least_one: List[AttributeType] = []
                if at_least_one:
                    missing_at_least_one = [permission for permission in at_least_one if permission.db_name not in effective]

                missing_all_required: List[AttributeType] = []
                if all_required:
                    missing_all_required = [permission for permission in all_required if permission.db_name not in effective]

                has_at_least_one = not at_least_one or len(missing_at_least_one) < len(at_least_one)
                has_all_required = not all_required or len(missing_all_required) == 0

                if not has_at_least_one or not has_all_required:
                    logger.warning(
                        f"Usuario {user_id} (rol={user_role_str}) denegado en {f.__name__}. "
                        f"at_least_one_missing={[permission.db_name for permission in missing_at_least_one]}, "
                        f"all_required_missing={[permission.db_name for permission in missing_all_required]}"
                    )
                    return jsonify({
                        "error": "forbidden",
                        "error_description": "Insufficient permissions",
                        "missing_permissions": {
                            "at_least_one": [permission.db_name for permission in missing_at_least_one],
                            "all_required":  [permission.db_name for permission in missing_all_required],
                        },
                    }), 403

                logger.info(
                    f"Usuario {user_id} autorizado para {f.__name__}. "
                    f"at_least_one={at_least_one}, all_required={all_required}"
                )
                return f(*args, **kwargs)

            except (EllysiaException, MissingParameterError, MissingJsonBodyError):
                raise
            except Exception as exc:
                logger.error(f"Error en require_permissions: {exc}", exc_info=True)
                return jsonify({
                    "error": "server_error",
                    "error_description": "AttributeType check failed",
                }), 500

        return decorated
    return decorator

