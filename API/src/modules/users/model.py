"""
Database models for user authentication and authorization.

This module contains SQLAlchemy models for managing users, access tokens,
and refresh tokens for OAuth 2.0 authentication.

Classes:
    User: Main user entity with credentials and relationships.
    AccessToken: OAuth 2.0 access token for API authentication.
    RefreshToken: OAuth 2.0 refresh token for token renewal.

Example:
>>> from src.modules.users.model import User, AccessToken
>>> user = User(username="admin", email="admin@example.com")
>>> print(user)
'User(id=None, username='admin', role='role_user')'
"""

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import relationship

from src.modules.shared import Base, utcnow_naive


# =========================================================================
# TOKEN MODELS
# =========================================================================

class AccessToken(Base):
    """
    OAuth 2.0 access token issued to users for API authentication.

    Stores access tokens with expiration times and revocation status.
    Tokens are validated against expiry and revocation state.

    Attributes:
        id: Primary key, auto-incrementing integer.
        token: Unique token string (indexed for fast lookup).
        user_id: Foreign key to User.id.
        expires_at: Token expiration timestamp.
        created_at: Token creation timestamp (automatic).
        revoked: Revocation status (0=active, 1=revoked).

    Relationships:
        user: User that owns this token.

    Example:
    >>> token = AccessToken(token="abc123...", user_id=1, expires_at=datetime(2025,1,1))
    >>> token.is_valid()
    True
    """
    __tablename__ = "AccessToken"

    id         = Column(Integer,     primary_key=True, autoincrement=True)
    token      = Column(String(512), unique=True, nullable=False, index=True)
    user_id    = Column(Integer,     ForeignKey("User.id"), nullable=False)
    expires_at = Column(DateTime,    nullable=False)
    created_at = Column(DateTime,    nullable=False, default=utcnow_naive)
    revoked    = Column(Integer,     default=0)  # 0=activo, 1=revocado

    user = relationship("User", back_populates="tokens")

    def is_valid(self) -> bool:
        """
        Check if the token is still valid.

        Returns:
            True if token is not revoked and has not expired.
        """
        return not self.revoked and utcnow_naive() < self.expires_at

    def __str__(self):
        return f"AccessToken(id={self.id}, user_id={self.user_id}, expires_at={self.expires_at})"


class RefreshToken(Base):
    """
    OAuth 2.0 refresh token for renewing access tokens.

    Stores refresh tokens with expiration times and revocation status.
    Used to obtain new access tokens when the current one expires.

    Attributes:
        id: Primary key, auto-incrementing integer.
        token: Unique token string (indexed for fast lookup).
        user_id: Foreign key to User.id.
        expires_at: Token expiration timestamp.
        created_at: Token creation timestamp (automatic).
        revoked: Revocation status (0=active, 1=revoked).

    Relationships:
        user: User that owns this token.

    Example:
    >>> token = RefreshToken(token="refresh123...", user_id=1, expires_at=datetime(2025,1,1))
    >>> token.is_valid()
    True
    """
    __tablename__ = "RefreshToken"

    id         = Column(Integer,     primary_key=True, autoincrement=True)
    token      = Column(String(512), unique=True, nullable=False, index=True)
    user_id    = Column(Integer,     ForeignKey("User.id"), nullable=False)
    expires_at = Column(DateTime,    nullable=False)
    created_at = Column(DateTime,    nullable=False, default=utcnow_naive)
    revoked    = Column(Integer,     default=0)

    user = relationship("User", back_populates="refresh_tokens")

    def is_valid(self) -> bool:
        """
        Check if the token is still valid.

        Returns:
            True if token is not revoked and has not expired.
        """
        return not self.revoked and utcnow_naive() < self.expires_at  # type: ignore

    def __str__(self):
        return f"RefreshToken(id={self.id}, user_id={self.user_id})"


# =========================================================================
# USER MODEL
# =========================================================================

class User(Base):
    """
    Represents a user in the system with authentication credentials.

    Stores user identity information including username, email, and
    hashed passwords. The `role` column captures the user's structural
    identity (root / admin / user) and is kept separate from ABAC
    attributes, which express fine-grained capabilities per module.

    Attributes:
        id: Primary key, auto-incrementing integer.
        username: Unique username (max 64 characters).
        email: Unique email address (max 128 characters).
        first_name: User's first name (max 64 characters).
        last_name: User's last name (max 64 characters).
        role: Structural role — one of "role_root", "role_admin", "role_user".
        created_at: Account creation timestamp (automatic).
        password_hash: Hashed password (max 128 characters).
        password_salt: Salt used for password hashing (max 128 characters).
        password_changed_at: Timestamp of the last access-password change
            (nullable; None means never changed since this column was added).

    Relationships:
        scans: List of Scan objects (security scans performed).
        tokens: List of AccessToken objects (active OAuth tokens).
        refresh_tokens: List of RefreshToken objects (token refresh tokens).
        vaults: List of Vault objects (encrypted secrets vaults).
        analyses: List of IrisAnalysis objects (email header analyses).
        documents: List of all Document objects (polymorphic relationship).
        attributes: List of UserAttribute objects (ABAC capability attributes).
    """

    __tablename__ = "User"

    id              = Column(Integer,       primary_key=True, autoincrement=True)
    username        = Column(String(64),    unique=True, nullable=False)
    email           = Column(String(128),   unique=True, nullable=False)
    first_name      = Column(String(64),    nullable=False)
    last_name       = Column(String(64),    nullable=False)
    role            = Column(String(32),    nullable=False, default="role_user")
    created_at      = Column(DateTime,      nullable=False, default=utcnow_naive)
    password_hash   = Column(String(128),   nullable=False)
    password_salt   = Column(String(128),   nullable=False)
    # Marca de la última vez que se cambió la contraseña de acceso. Permite a los
    # clientes (web/móvil) detectar que un token/sesión quedó obsoleto por un
    # cambio de contraseña (ver require_oauth_token y el grant refresh_token).
    password_changed_at = Column(DateTime,  nullable=True)

    # Verificación del correo (alta pública). Tres columnas y no una tabla
    # aparte porque solo hay un token vivo por usuario y no interesa el
    # histórico. NULL en email_verified_at = sin verificar: la cuenta entra y
    # navega, pero QuotaManager no le deja consumir nada que cueste dinero.
    # Del hash se guarda un SHA-256 y no un Argon2 como en los códigos de
    # recuperación: el token son 32 bytes aleatorios, así que no hay nada que
    # adivinar a fuerza bruta y un KDF lento solo añadiría latencia.
    email_verified_at             = Column(DateTime,     nullable=True)
    email_verification_hash       = Column(String(128),  nullable=True)
    email_verification_expires_at = Column(DateTime,     nullable=True)

    # La cuenta nació con una contraseña que el usuario no eligió (alta por
    # invitación a una organización) y tiene que cambiarla. Va aparte de
    # password_changed_at porque ese NULL ya significa otra cosa: "nunca se
    # cambió", que también es cierto de las cuentas antiguas.
    must_change_password = Column(Boolean, nullable=False, default=False)

    scans          = relationship("Scan",         back_populates="user", cascade="all, delete-orphan")
    tokens         = relationship("AccessToken",  back_populates="user", cascade="all, delete-orphan")
    refresh_tokens = relationship("RefreshToken", back_populates="user", cascade="all, delete-orphan")
    vaults         = relationship("Vault",        back_populates="user", cascade="all, delete-orphan")

    mfa_totp_credential = relationship(
        "MFATotpCredential", back_populates="user",
        uselist=False, cascade="all, delete-orphan",
    )
    mfa_recovery_codes = relationship(
        "MFARecoveryCode", back_populates="user", cascade="all, delete-orphan",
    )

    analyses = relationship(
        "IrisAnalysis",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    documents = relationship(
        "Document",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    attributes = relationship(
        "UserAttribute",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    def __str__(self):
        return f"User(id={self.id}, username='{self.username}', role='{self.role}')"

    def __repr__(self):
        return f"<User(id={self.id}, username='{self.username}', role='{self.role}')>"


# =========================================================================
# USER ATTRIBUTE MODEL
# =========================================================================


class UserAttribute(Base):
    """
    ABAC capability attributes assigned to a user.

    Each row represents a single fine-grained permission (e.g.
    "themis_read", "aegis_create"). Role-level identity
    (root / admin / user) is stored exclusively in User.role and
    must NEVER appear here.

    Attributes:
        user_id: Foreign key to User.id (part of composite PK).
        attribute_name: Attribute identifier matching a Permission enum value
                        (e.g. "themis_read", "acheron_delete").

    Relationships:
        user: User that owns this attribute assignment.

    Example:
    >>> ua = UserAttribute(user_id=1, attribute_name="themis_read")
    >>> print(ua)
    'UserAttribute(user_id=1, attribute_name='themis_read')'
    """
    __tablename__ = "UserAttribute"

    user_id = Column(Integer, ForeignKey("User.id"), primary_key=True)
    attribute_name = Column(String(64), primary_key=True)

    user = relationship("User", back_populates="attributes")

    def __str__(self):
        return f"UserAttribute(user_id={self.user_id}, attribute_name='{self.attribute_name}')"

    def __repr__(self):
        return f"<UserAttribute(user_id={self.user_id}, attribute_name='{self.attribute_name}')>"


# =========================================================================
# MFA (TOTP) MODELS
# =========================================================================


class MFATotpCredential(Base):
    """
    TOTP (Time-based One-Time Password) credential for a user.

    One row per user (unique ``user_id``). ``secret_encrypted`` holds the
    shared TOTP secret, encrypted at rest with a server-side key — unlike
    Acheron this is NOT zero-knowledge, since the server must be able to
    compute the current code to verify a login attempt.

    ``confirmed_at`` is NULL until the user proves control of the secret by
    submitting a valid code during setup; MFA only counts as "enabled" once
    confirmed (see MFAManager.is_enabled).

    Attributes:
        user_id: Foreign key to User.id (unique — one credential per user).
        secret_encrypted: Fernet-encrypted Base32 TOTP secret.
        confirmed_at: When the user confirmed enrollment (None = pending).
        created_at: When the credential was created (setup started).
    """
    __tablename__ = "MFATotpCredential"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("User.id"), nullable=False, unique=True)
    secret_encrypted = Column(String(512), nullable=False)
    confirmed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, default=utcnow_naive)

    user = relationship("User", back_populates="mfa_totp_credential")

    def __repr__(self) -> str:
        return f"<MFATotpCredential user_id={self.user_id} confirmed={self.confirmed_at is not None}>"


class MFARecoveryCode(Base):
    """
    One-time recovery code for MFA, used when the user loses their TOTP device.

    Attributes:
        user_id: Foreign key to User.id.
        code_hash: Argon2id hash of the recovery code (same hasher as passwords).
        used_at: When the code was consumed (None = still usable).
        created_at: Batch creation timestamp.
    """
    __tablename__ = "MFARecoveryCode"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("User.id"), nullable=False)
    code_hash = Column(String(512), nullable=False)
    used_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, default=utcnow_naive)

    user = relationship("User", back_populates="mfa_recovery_codes")

    def __repr__(self) -> str:
        return f"<MFARecoveryCode id={self.id} user_id={self.user_id} used={self.used_at is not None}>"


class MFAChallenge(Base):
    """
    Short-lived challenge issued after a successful password grant when the
    user has MFA enabled; exchanged for real tokens at POST /oauth/mfa/verify.

    Unlike AccessToken/RefreshToken, tracks ``attempts`` so failed TOTP/recovery
    guesses can be capped server-side — a 6-digit TOTP code is brute-forceable
    online, unlike Acheron's client-side-only vault checker.

    Attributes:
        token: Opaque random string handed to the client (not a JWT).
        user_id: Foreign key to User.id.
        expires_at: Short expiry (minutes, see config_reading.MfaConfig).
        attempts: Number of failed verification attempts so far.
        created_at: Issuance timestamp.
    """
    __tablename__ = "MFAChallenge"

    id = Column(Integer, primary_key=True, autoincrement=True)
    token = Column(String(512), unique=True, nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("User.id"), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    attempts = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime, nullable=False, default=utcnow_naive)

    user = relationship("User")

    def is_valid(self, max_attempts: int) -> bool:
        """True if the challenge is under the allowed attempt count and not expired."""
        return self.attempts < max_attempts and utcnow_naive() < self.expires_at

    def __repr__(self) -> str:
        return f"<MFAChallenge id={self.id} user_id={self.user_id} attempts={self.attempts}>"