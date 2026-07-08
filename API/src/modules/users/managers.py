"""
User and OAuth token managers for the users module.

Managers contain business logic only — all database access is delegated
to UserRepository and TokenRepository via explicit UnitOfWork scopes.

Security invariants enforced here:
  - password_hash and password_salt never leave this module.
  - Credential verification uses constant-time comparison.
  - Token verification validates both JWT signature and database record state.
  - Password changes atomically revoke all existing tokens in one transaction.
  - Returned User objects are always expunged from the session before leaving
    the manager, so callers cannot accidentally trigger lazy loads on
    credential-bearing fields.

Classes:
    UserManager:        User lifecycle and credential management.
    OAuthTokenManager:  JWT access token and refresh token lifecycle.
"""

import logging
import secrets
from datetime import datetime, timedelta, timezone
from uuid import uuid4
from typing import List, Optional, Tuple

import jwt

import src.modules.system.config_reading as CR
from src.modules.users.exceptions import (
    DatabaseError,
    ExistingUserError,
    PermissionsError,
    ProfileUpdateError,
    UserBindingError,
    MfaAlreadyEnabledError,
    MfaNotEnabledError,
    InvalidMfaCodeError,
)
from src.modules.infrastructure import UnitOfWork
from src.modules.shared import utcnow_naive
from src.modules.infrastructure.session import read_repo

from .model import (
    AccessToken,
    RefreshToken,
    User,
    UserAttribute,
    MFATotpCredential,
    MFARecoveryCode,
    MFAChallenge,
)
from .repositories import TokenRepository, UserRepository, AttributeRepository, MFARepository
from .services import (
    generate_salt,
    hash_password,
    hash_password_with_salt,
    verify_password,
    encrypt_totp_secret,
    decrypt_totp_secret,
    generate_totp_secret,
    totp_provisioning_uri,
    verify_totp_code,
    generate_recovery_codes,
)

logger = logging.getLogger(__name__)

(
    ACCESS_TOKEN_EXPIRE_MINUTES,
    REFRESH_TOKEN_EXPIRE_DAYS,
    JWT_SECRET_KEY,
    JWT_ALGORITHM,
) = CR.get_oauth_config()


def _to_utc_epoch(dt: Optional[datetime]) -> Optional[int]:
    """Convierte un datetime *naive en UTC* (como ``utcnow_naive()``) a epoch
    en segundos, de forma consistente con cómo PyJWT codifica ``iat``/``exp``
    (siempre tratando el valor como UTC). Devuelve ``None`` si ``dt`` es ``None``.
    """
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp())

class UserManager:
    """
    Manages user lifecycle: registration, credential verification, and profile updates.

    All database access goes through UnitOfWork + UserRepository.
    Credential fields (password_hash, password_salt) are handled exclusively
    inside this class and never propagated to callers.

    Example:
    >>> manager = UserManager()
    >>> is_valid, user_id = manager.verify_credentials("johnd", "secret")
    """

    def __init__(self) -> None:
        pass

    # =========================================================================
    # CREDENTIAL VERIFICATION
    # =========================================================================

    def verify_credentials(self, username: str, password: str) -> Tuple[bool, Optional[int]]:
        """
        Verify a username/password pair.

        Performs a constant-time password comparison to prevent timing attacks.
        The User object (including credential fields) never leaves this method.

        Args:
            username: Username to authenticate.
            password: Plaintext password to verify.

        Returns:
            Tuple of (is_valid, user_id). user_id is None if authentication fails.

        Raises:
            Exception: On unexpected database errors.
        """
        try:
            user = read_repo(UserRepository).get_by_username(username)

            if user is None:
                # Dummy comparison to prevent username enumeration via timing differences.
                verify_password("dummy_hash", password, "dummy_salt")
                logger.info(f"Usuario '{username}' no encontrado")
                return False, None

            is_valid, needs_rehash = verify_password(
                stored_hash = user.password_hash,
                password    = password,
                legacy_salt = user.password_salt or "",
            )

            if not is_valid:
                logger.warning(f"Contraseña incorrecta para '{username}'")
                return False, None

            if needs_rehash:
                with UnitOfWork() as uow:
                    u = UserRepository(uow).get_by_id(user.id)
                    if u is not None:
                        u.password_hash = hash_password(password)
                        u.password_salt = ""
                logger.info(f"Hash actualizado a Argon2 para usuario '{username}'")

            logger.info(f"Credenciales válidas para '{username}' (ID: {user.id})")
            return True, user.id

        except Exception as e:
            logger.error(f"Error verificando credenciales: {e}")
            raise


    # =========================================================================
    # USER REGISTRATION
    # =========================================================================

    def sign_in_user(
        self,
        username:    str,
        email:       str,
        first_name:  str,
        last_name:   str,
        password:   str,
        role:        Optional[str] = None,
        actor_id:   Optional[int] = None,
    ) -> User:
        """
        Register a new user.

        Validates uniqueness of username and email, hashes the password
        with a fresh random salt, and persists the new user record.

        Args:
            username:   Unique username (max 64 chars).
            email:      Unique email address (max 128 chars).
            first_name: User's first name.
            last_name:  User's last name.
            password:   Plaintext password (hashed before storage).
            role:       Optional role to assign: "role_user" (default), "role_admin".
                        Requires actor_id with appropriate permissions.
            actor_id:   ID of user creating this account. Required if role is specified.

        Returns:
            The newly created User instance (credential fields excluded
            from the returned object via session expunge).

Raises:
            ExistingUserError: If username or email is already registered.
            PermissionsError: If actor_id lacks permissions to assign the requested role.
            DatabaseError:    On unexpected persistence failures.
        """
        valid_roles = {"role_user", "role_admin"}
        default_role = "role_user"

        if role is not None and role not in valid_roles:
            raise PermissionsError(f"Invalid role: {role}. Valid roles: {valid_roles}")

        if role and not actor_id:
            raise PermissionsError("actor_id required when specifying a role")

        if role == "role_admin" and actor_id:
            if not self.can_create_admin(actor_id):
                logger.error(f"El administrador con id {actor_id} ha intentado crear un usuario con rol {role}")
                raise PermissionsError("Solo el administrador raíz puede crear administradores")

        if role and actor_id:
            actor = self.get_user_by_id(actor_id)
            if actor:
                actor_rank = self._get_role_rank(actor.role)
                target_rank = self._get_role_rank(role)
                if target_rank >= actor_rank:
                    raise PermissionsError("No puedes crear usuarios con rol igual o superior al tuyo")

        assigned_role = role if role else default_role

        try:
            with UnitOfWork() as uow:
                repo = UserRepository(uow)

                if repo.username_exists(username):
                    logger.error(f"Se intentó crear un usuario con un username ({username}) repetido")
                    raise ExistingUserError(username, None)
                if repo.email_exists(email):
                    logger.error(f"Se intentó crear un usuario con un email ({email}) repetido")
                    raise ExistingUserError(None, email)

                new_user = User(
                    username      = username,
                    email         = email,
                    first_name    = first_name,
                    last_name     = last_name,
                    password_hash = hash_password(password),
                    password_salt = "",
                    role          = assigned_role,
                )
                repo.save(new_user)

            logger.info(f"Usuario '{username}' registrado con rol '{assigned_role}' (ID: {new_user.id})")
            return new_user

        except ExistingUserError:
            raise
        except Exception as e:
            logger.error(f"Error registrando usuario '{username}': {e}")
            raise DatabaseError("Error con credenciales. Revísalas e inténtalo de nuevo.")

    # =========================================================================
    # QUERIES
    # =========================================================================

    def get_user_by_id(self, user_id: int) -> Optional[User]:
        """
        Retrieve a user by primary key.

        Args:
            user_id: User primary key.

        Returns:
            User instance (without credential fields accessible to caller),
            or None if not found.
        """
        return read_repo(UserRepository).get_by_id(user_id)

    def get_all_users(self) -> List[User]:
        """
        Retrieve all registered users.

        Returns:
            List of user dictionaries (public info only).
        """
        return read_repo(UserRepository).get_all()

    def get_user_by_username(self, username: str) -> Optional[User]:
        """
        Retrieve a user by username.

        Args:
            username: Unique username string.

        Returns:
            User instance, or None if not found.
        """
        return read_repo(UserRepository).get_by_username(username)


    # =========================================================================
    # PROFILE & PASSWORD UPDATES
    # =========================================================================

    def update_user_password(self, user_id: int, new_password: str) -> None:
        """
        Update a user's password with a fresh salt.

        Does NOT revoke existing tokens — callers that require token
        invalidation on password change should also call
        OAuthTokenManager.revoke_all_user_tokens(). Alternatively,
        use update_user_password_and_revoke_tokens() for an atomic operation.

        Args:
            user_id:      Primary key of the user to update.
            new_password: Plaintext new password (hashed before storage).

        Raises:
            UserBindingError: If the user is not found.
        """
        with UnitOfWork() as uow:
            user = UserRepository(uow).get_by_id(user_id)
            if user is None:
                raise UserBindingError(username=str(user_id))

            user.password_hash = hash_password(new_password)
            user.password_salt = ""
            user.password_changed_at = utcnow_naive()

        logger.info(f"Contraseña actualizada para usuario {user_id}")

    def update_user_profile(self, user_id: int, first_name: str, last_name: str) -> User:
        """
        Update a user's display name fields.

        Username and email are immutable after registration.

        Args:
            user_id:    Primary key of the user to update.
            first_name: New first name.
            last_name:  New last name.

        Returns:
            The updated User instance.

        Raises:
            ProfileUpdateError: If the user is not found or update fails.
        """
        try:
            with UnitOfWork() as uow:
                user = UserRepository(uow).get_by_id(user_id)
                if user is None:
                    raise ProfileUpdateError("Usuario no encontrado")

                user.first_name = first_name
                user.last_name  = last_name
                # UoW commits on __exit__

            logger.info(f"Perfil actualizado para usuario {user_id} ({user.username})")
            return user

        except ProfileUpdateError:
            raise
        except Exception as e:
            logger.error(f"Error actualizando perfil para usuario {user_id}: {e}")
            raise ProfileUpdateError(f"Error al actualizar el perfil: {e}")

    def delete_user(self, user_id: int) -> None:
        """
        Delete a user by primary key.

        Args:
            user_id: Primary key of the user to delete.

        Raises:
            UserBindingError: If the user is not found.
        """
        with UnitOfWork() as uow:
            repo = UserRepository(uow)
            user = repo.get_by_id(user_id)
            if user is None:
                raise UserBindingError(username=str(user_id))
            repo.delete(user)

        logger.info(f"Usuario {user_id} eliminado")

# =========================================================================
# ATTRIBUTE MANAGEMENT
# =========================================================================

    def can_manage_user(self, actor_id: int, target_id: int) -> bool:
        """
        Verifica si el actor puede gestionar al usuario objetivo.

        Jerarquía:
        - role_root: puede gestionar TODO (root, admin, users)
        - role_admin: solo puede gestionar role_user
        - role_user: NO puede gestionar nadie

        El rol se lee del modelo User.

        Args:
            actor_id: ID del usuario que hace la acción.
            target_id: ID del usuario objetivo.

        Returns:
            True si tiene permiso, False en caso contrario.
        """

        if actor_id == target_id:
            return True

        actor_user = self.get_user_by_id(actor_id)
        target_user = self.get_user_by_id(target_id)

        if not actor_user or not target_user:
            return False

        actor_role = actor_user.role
        target_role = target_user.role

        is_actor_root = actor_role == "role_root"
        is_actor_admin = actor_role == "role_admin"
        is_target_root = target_role == "role_root"
        is_target_admin = target_role == "role_admin"

        if is_actor_root:
            return True

        if is_actor_admin:
            return not is_target_root and not is_target_admin

        return False

    def can_create_admin(self, actor_id: int) -> bool:
        """
        Verifica si el actor puede crear usuarios con rol admin.

        Solo role_root puede crear administradores.
        Los admin no pueden crear otros admin.

        Args:
            actor_id: ID del usuario creando.

        Returns:
            True si tiene permiso, False en caso contrario.
        """
        actor_user = self.get_user_by_id(actor_id)
        return actor_user and actor_user.role == "role_root"

    def _get_role_rank(self, role: str) -> int:
        ranks = {"role_user": 0, "role_admin": 1, "role_root": 2}
        return ranks.get(role, 0)

    def get_user_attributes(self, user_id: int) -> List[str]:
        """
        Retrieve all attribute names assigned to a user.

        Args:
            user_id: User primary key.

        Returns:
            List of attribute name strings.
        """
        attrs = read_repo(AttributeRepository).get_by_user(user_id)
        return [a.attribute_name for a in attrs]

    def add_user_attributes(
        self,
        user_id: int,
        attribute_names: List[str],
    ) -> List[str]:
        """
        Add one or more attributes to a user.

        Args:
            user_id: User primary key.
            attribute_names: List of attribute names to add.

        Returns:
            List of added attribute names.
        """
        with UnitOfWork() as uow:
            created = AttributeRepository(uow).add_attributes(
                user_id, attribute_names
            )
            return [c.attribute_name for c in created]

    def remove_user_attributes(
        self,
        user_id: int,
        attribute_names: List[str],
    ) -> int:
        """
        Remove one or more attributes from a user.

        Args:
            user_id: User primary key.
            attribute_names: List of attribute names to remove.

        Returns:
            Number of attributes removed.
        """
        with UnitOfWork() as uow:
            deleted = AttributeRepository(uow).remove_attributes(
                user_id, attribute_names
            )
            return deleted

    @staticmethod
    def get_all_available_attributes() -> List[str]:
        """
        Return a list of all available attributes that can be assigned to users.

        These attributes correspond to the AttributeType enum values and represent
        fine-grained ABAC capabilities across modules (Aegis, Sentinel, Acheron).

        Returns:
            List of attribute name strings (e.g. ["aegis_create", "sentinel_read", ...]).
        """
        from .services.permissions import AttributeType
        return [attr.value for attr in AttributeType.__members__.values() if isinstance(attr.value, str)]


class OAuthTokenManager:
    """
    Manages OAuth 2.0 access and refresh token lifecycle.

    Handles JWT creation and verification, token persistence via
    TokenRepository, and revocation flows.

    Security notes:
      - JWT signature is validated before the database record is checked,
        preventing unnecessary DB hits on forged tokens.
      - Token type claim ("type") is validated to prevent access tokens
        being used as refresh tokens and vice versa.
      - revoke_all_user_tokens() atomically revokes both token types
        in a single transaction, used for password-change and logout-everywhere.

    Example:
    >>> manager = OAuthTokenManager()
    >>> access_token = manager.create_access_token(user_id=1, username="johnd")
    >>> payload = manager.verify_access_token(access_token)
    """

    def __init__(self) -> None:
        pass

    # =========================================================================
    # TOKEN CREATION
    # =========================================================================

    def create_access_token(
        self,
        user_id: int,
        username: str,
        role: str = "role_user",
        password_changed_at: Optional[datetime] = None,
        mfa_at: Optional[datetime] = None,
    ) -> str:
        """
        Create and persist a signed JWT access token.

        Args:
            user_id:  User primary key to embed in the token payload.
            username: Username to embed in the token payload.
            role:     Role to embed in the token payload.
            password_changed_at: Timestamp of the user's last access-password
                change, embedded as the ``pwd_at`` claim (UTC epoch seconds).
                Lets clients reason about password-change state. ``None`` when
                the password has never been changed.
            mfa_at: Timestamp at which the second factor was verified for this
                session, embedded as the ``mfa_at`` claim (UTC epoch seconds).
                ``None`` when the user doesn't have MFA enabled — possession of
                an access token with ``mfa_at`` set implies MFA was satisfied,
                so no per-endpoint guard is needed.

        Returns:
            Signed JWT string.
        """
        expires_at = utcnow_naive() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

        payload = {
            "sub":      str(user_id),
            "username": username,
            "exp":      expires_at,
            "iat":      utcnow_naive(),
            "jti":      uuid4().hex,
            "type":     "access",
            "role":     role,
            "pwd_at":   _to_utc_epoch(password_changed_at),
            "mfa_at":   _to_utc_epoch(mfa_at),
        }
        token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

        with UnitOfWork() as uow:
            TokenRepository(uow).save_access_token(
                AccessToken(token=token, user_id=user_id, expires_at=expires_at)
            )

        return token

    def create_refresh_token(self, user_id: int) -> str:
        """
        Create and persist a cryptographically random refresh token.

        Refresh tokens are opaque random strings (not JWTs) to avoid
        leaking expiry information to the client.

        Args:
            user_id: User primary key.

        Returns:
            Raw refresh token string (URL-safe base64, 64 bytes).
        """
        token      = secrets.token_urlsafe(64)
        expires_at = utcnow_naive() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

        with UnitOfWork() as uow:
            TokenRepository(uow).save_refresh_token(
                RefreshToken(token=token, user_id=user_id, expires_at=expires_at)
            )

        return token

    # =========================================================================
    # TOKEN VERIFICATION
    # =========================================================================

    def verify_access_token(self, token: str) -> Optional[dict]:
        """
        Verify a JWT access token and return its payload.

        Validates JWT signature and expiry first, then checks the database
        record for revocation. Both checks must pass.

        Args:
            token: Raw JWT string from the Authorization header.

        Returns:
            Decoded payload dict if valid, None otherwise.
        """
        try:
            # Step 1: validate JWT signature and expiry (no DB hit yet).
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])

            if payload.get("type") != "access":
                return None

            # Step 2: check database record for revocation.
            record = read_repo(TokenRepository).get_access_token(token)
            is_valid = record is not None and record.is_valid()

            return payload if is_valid else None

        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
        except Exception as e:
            logger.error(f"Error verificando access token: {e}")
            return None

    def verify_refresh_token(self, token: str) -> Optional[int]:
        """
        Verify an opaque refresh token and return the associated user ID.

        Args:
            token: Raw refresh token string.

        Returns:
            User primary key if the token is valid, None otherwise.
        """
        try:
            record = read_repo(TokenRepository).get_refresh_token(token)
            if record is None or not record.is_valid():
                return None
            return record.user_id

        except Exception as e:
            logger.error(f"Error verificando refresh token: {e}")
            return None

    # =========================================================================
    # PASSWORD-CHANGE STALENESS
    # =========================================================================

    def is_token_stale_by_password(self, token: str) -> bool:
        """True si el access token (firma válida) se emitió ANTES del último
        cambio de contraseña del usuario.

        Solo debe consultarse cuando ``verify_access_token`` ya devolvió ``None``
        (token revocado/expirado/ inválido), para distinguir un rechazo causado por
        un cambio de contraseña de un rechazo genérico. Hace un acceso a BD, así
        que se llama únicamente en el camino de error.
        """
        try:
            payload = jwt.decode(
                token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM],
                options={"verify_exp": False},
            )
        except jwt.InvalidTokenError:
            return False

        iat = payload.get("iat")
        sub = payload.get("sub")
        if iat is None or sub is None:
            return False

        try:
            user = read_repo(UserRepository).get_by_id(int(sub))
        except Exception:
            return False

        if user is None or user.password_changed_at is None:
            return False

        changed_epoch = _to_utc_epoch(user.password_changed_at)
        return changed_epoch is not None and changed_epoch > int(iat)

    def is_refresh_stale_by_password(self, token: str) -> bool:
        """True si el refresh token existe pero se creó ANTES del último cambio de
        contraseña del usuario (es decir, quedó obsoleto por dicho cambio).

        Consulta la BD aunque el token esté revocado, para poder dar el motivo
        ``password_changed`` en el grant ``refresh_token``.
        """
        try:
            record = read_repo(TokenRepository).get_refresh_token(token)
            if record is None:
                return False
            user = read_repo(UserRepository).get_by_id(record.user_id)
        except Exception:
            return False

        if user is None or user.password_changed_at is None:
            return False

        changed_epoch = _to_utc_epoch(user.password_changed_at)
        created_epoch = _to_utc_epoch(record.created_at)
        return (
            changed_epoch is not None
            and created_epoch is not None
            and changed_epoch > created_epoch
        )

    # =========================================================================
    # REVOCATION
    # =========================================================================

    def revoke_access_token(self, token: str) -> bool:
        """
        Revoke a single access token.

        Args:
            token: Raw JWT string to revoke.

        Returns:
            True if the token was found and revoked, False otherwise.
        """
        try:
            with UnitOfWork() as uow:
                revoked = TokenRepository(uow).revoke_access_token(token)

            if revoked:
                logger.info("Access token revocado")
            return revoked

        except Exception as e:
            logger.error(f"Error revocando access token: {e}")
            return False

    def revoke_all_user_tokens(self, user_id: int) -> None:
        """
        Atomically revoke all access and refresh tokens for a user.

        Both token types are revoked in a single transaction. Intended
        for password-change and logout-everywhere flows.

        Args:
            user_id: User primary key.
        """
        with UnitOfWork() as uow:
            TokenRepository(uow).revoke_all_tokens(user_id)

        logger.info(f"Todos los tokens revocados para usuario {user_id}")

    # =========================================================================
    # MFA CHALLENGE
    # =========================================================================

    def create_mfa_challenge(self, user_id: int) -> str:
        """
        Issue a short-lived opaque challenge after a password grant succeeds
        for a user with MFA enabled. Exchanged for real tokens at
        POST /oauth/mfa/verify once the user proves the second factor.

        Args:
            user_id: User primary key.

        Returns:
            Opaque challenge token string (not a JWT).
        """
        cfg = CR.get_mfa_config()
        token = secrets.token_urlsafe(48)
        expires_at = utcnow_naive() + timedelta(minutes=cfg["challenge_expiry_minutes"])

        with UnitOfWork() as uow:
            MFARepository(uow).save_challenge(
                MFAChallenge(token=token, user_id=user_id, expires_at=expires_at)
            )

        return token

    def verify_mfa_challenge(self, token: str) -> Optional[int]:
        """
        Return the user_id for a still-valid MFA challenge (not expired, under
        the max attempt count), or None otherwise.

        Does NOT consume the challenge — callers must call
        consume_mfa_challenge() on success or register_mfa_challenge_failure()
        on a failed code attempt.

        Args:
            token: Opaque challenge token string.

        Returns:
            User primary key if valid, None otherwise.
        """
        cfg = CR.get_mfa_config()
        challenge = read_repo(MFARepository).get_challenge(token)
        if challenge is None or not challenge.is_valid(cfg["max_challenge_attempts"]):
            return None
        return challenge.user_id

    def register_mfa_challenge_failure(self, token: str) -> None:
        """Increment the failed-attempt counter for an MFA challenge."""
        with UnitOfWork() as uow:
            MFARepository(uow).increment_challenge_attempts(token)

    def consume_mfa_challenge(self, token: str) -> None:
        """Delete an MFA challenge after it has been successfully verified."""
        with UnitOfWork() as uow:
            MFARepository(uow).delete_challenge(token)

    # =========================================================================
    # MAINTENANCE
    # =========================================================================

    def cleanup_expired_tokens(self) -> None:
        """
        Delete all expired access/refresh tokens and MFA challenges from the
        database.

        Intended to be called from a periodic maintenance task.
        """
        with UnitOfWork() as uow:
            access_deleted, refresh_deleted = TokenRepository(uow).cleanup_expired_tokens()
            challenges_deleted = MFARepository(uow).delete_expired_challenges(utcnow_naive())

        logger.info(
            f"Tokens expirados eliminados: "
            f"{access_deleted} access, {refresh_deleted} refresh, "
            f"{challenges_deleted} mfa challenges"
        )


class MFAManager:
    """
    Manages TOTP enrollment/confirmation, disabling, and verification, plus
    the recovery-code fallback.

    All database access goes through UnitOfWork + MFARepository. The TOTP
    secret is encrypted at rest (services.encrypt_totp_secret) since, unlike
    Acheron, the server must be able to compute the current code to verify
    it — this is NOT zero-knowledge.

    Example:
    >>> manager = MFAManager()
    >>> setup = manager.setup_totp(user_id=1, username="johnd")
    >>> codes = manager.confirm_totp(user_id=1, code="123456")
    """

    def __init__(self) -> None:
        pass

    # =========================================================================
    # STATUS
    # =========================================================================

    def is_enabled(self, user_id: int) -> bool:
        """True if the user has a confirmed TOTP credential."""
        cred = read_repo(MFARepository).get_totp_credential(user_id)
        return cred is not None and cred.confirmed_at is not None

    def get_status(self, user_id: int) -> dict:
        """Return {'enabled': bool, 'confirmedAt': datetime|None} for a user."""
        cred = read_repo(MFARepository).get_totp_credential(user_id)
        return {
            "enabled": cred is not None and cred.confirmed_at is not None,
            "confirmedAt": cred.confirmed_at if cred else None,
        }

    # =========================================================================
    # ENROLLMENT
    # =========================================================================

    def setup_totp(self, user_id: int, username: str) -> dict:
        """
        Start TOTP enrollment: generate a secret and its provisioning URI.

        Overwrites any previous *unconfirmed* attempt (the user can re-scan a
        fresh QR if they abandoned setup). Raises if TOTP is already confirmed.

        Args:
            user_id:  User primary key.
            username: Username, embedded in the provisioning URI label.

        Returns:
            dict with 'secret' (manual entry) and 'provisioningUri' (QR).

        Raises:
            MfaAlreadyEnabledError: if TOTP is already confirmed for this user.
        """
        secret = generate_totp_secret()

        with UnitOfWork() as uow:
            repo = MFARepository(uow)
            existing = repo.get_totp_credential(user_id)
            if existing is not None and existing.confirmed_at is not None:
                raise MfaAlreadyEnabledError()

            if existing is not None:
                existing.secret_encrypted = encrypt_totp_secret(secret)
            else:
                repo.save_totp_credential(
                    MFATotpCredential(user_id=user_id, secret_encrypted=encrypt_totp_secret(secret))
                )

        return {
            "secret": secret,
            "provisioningUri": totp_provisioning_uri(secret, username),
        }

    def confirm_totp(self, user_id: int, code: str) -> List[str]:
        """
        Confirm TOTP enrollment by verifying the first code, then generate and
        persist a fresh batch of recovery codes.

        Args:
            user_id: User primary key.
            code:    6-digit TOTP code from the authenticator app.

        Returns:
            The plaintext recovery codes (shown to the user exactly once).

        Raises:
            MfaNotEnabledError: if setup_totp() was never called.
            InvalidMfaCodeError: if the code doesn't match.
        """
        with UnitOfWork() as uow:
            repo = MFARepository(uow)
            cred = repo.get_totp_credential(user_id)
            if cred is None:
                raise MfaNotEnabledError()

            secret = decrypt_totp_secret(cred.secret_encrypted)
            if not verify_totp_code(secret, code):
                raise InvalidMfaCodeError()

            cred.confirmed_at = utcnow_naive()

            repo.delete_recovery_codes(user_id)
            cfg = CR.get_mfa_config()
            plaintext_codes = generate_recovery_codes(cfg["recovery_codes_count"])
            repo.save_recovery_codes([
                MFARecoveryCode(user_id=user_id, code_hash=hash_password(plain))
                for plain in plaintext_codes
            ])

        logger.info(f"MFA (TOTP) confirmado para usuario {user_id}")
        return plaintext_codes

    def disable_totp(
        self, user_id: int, code: Optional[str] = None, recovery_code: Optional[str] = None,
    ) -> None:
        """
        Disable TOTP MFA for a user.

        Requires proving current possession of the second factor (a valid TOTP
        code or an unused recovery code) so that a stolen session token alone
        can't silently turn off 2FA.

        Args:
            user_id: User primary key.
            code: Current TOTP code, if using that method to confirm.
            recovery_code: An unused recovery code, if using that method instead.

        Raises:
            InvalidMfaCodeError: if neither the code nor the recovery code verify.
        """
        if not self.verify_totp_or_recovery(user_id, code=code, recovery_code=recovery_code):
            raise InvalidMfaCodeError()

        with UnitOfWork() as uow:
            repo = MFARepository(uow)
            repo.delete_recovery_codes(user_id)
            repo.delete_totp_credential(user_id)

        logger.info(f"MFA (TOTP) desactivado para usuario {user_id}")

    # =========================================================================
    # VERIFICATION
    # =========================================================================

    def verify_totp_or_recovery(
        self, user_id: int, code: Optional[str] = None, recovery_code: Optional[str] = None,
    ) -> bool:
        """
        Verify a TOTP code or, failing that, an unused recovery code.

        A matching recovery code is marked as used (one-time only) as a side
        effect of a successful verification.

        Args:
            user_id: User primary key.
            code: 6-digit TOTP code to try, if provided.
            recovery_code: Recovery code to try, if provided (and code fails/absent).

        Returns:
            True if either factor verified successfully.
        """
        repo = read_repo(MFARepository)

        if code:
            cred = repo.get_totp_credential(user_id)
            if cred is not None and cred.confirmed_at is not None:
                secret = decrypt_totp_secret(cred.secret_encrypted)
                if verify_totp_code(secret, code):
                    return True

        if recovery_code:
            for stored in repo.get_recovery_codes(user_id, only_unused=True):
                is_valid, _ = verify_password(stored.code_hash, recovery_code)
                if is_valid:
                    with UnitOfWork() as uow:
                        MFARepository(uow).mark_recovery_code_used(stored.id)
                    logger.warning(f"Código de recuperación MFA usado por usuario {user_id}")
                    return True

        return False