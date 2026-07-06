"""
Repository for user identity and OAuth token persistence.

Provides typed data access for User, AccessToken and RefreshToken models.
All credential fields (password_hash, password_salt) are handled exclusively
within manager-layer methods — repositories never return or log them.

Classes:
    UserRepository:  CRUD and lookup operations for User records.
    TokenRepository: CRUD and lookup operations for AccessToken and RefreshToken.

Usage:
    # Read-only query
    with UnitOfWork() as uow:
        repo = UserRepository(uow)
        user = repo.get_by_username("johnd")

    # Write operation (manager controls the transaction)
    with UnitOfWork() as uow:
        repo = UserRepository(uow)
        repo.save(new_user)
        # UoW commits on __exit__
"""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from sqlalchemy.orm import Session, joinedload, selectinload

from .model import (
    AccessToken,
    RefreshToken,
    User,
    UserAttribute,
    MFATotpCredential,
    MFARecoveryCode,
    MFAChallenge,
)

from src.modules.infrastructure.base_repository import BaseRepository, UnitOfWork


class UserRepository(BaseRepository[User]):
    """
    Repository for User entity persistence.

    Provides typed query methods for user lookup. Credential fields
    (password_hash, password_salt) are present on the returned model
    instances but are only accessed within the manager layer — never
    logged, serialised, or exposed beyond it.

    Example:
    >>> with UnitOfWork() as uow:
    ...     repo = UserRepository(uow)
    ...     user = repo.get_by_username("johnd")
    """

    def __init__(self, uow: UnitOfWork | None = None, session: Session | None = None) -> None:
        super().__init__(User, uow=uow, session=session)

    # =========================================================================
    # LOOKUPS
    # =========================================================================

    def get_by_id(self, user_id: int) -> Optional[User]:
        """
        Retrieve a User by primary key.

        Args:
            user_id: User primary key.

        Returns:
            User instance, or None if not found.
        """
        return (
            self._session.query(User)
            .options(selectinload(User.attributes))
            .filter(User.id == user_id)
            .first()
        )

    def get_by_username(self, username: str) -> Optional[User]:
        """
        Retrieve a User by username (case-sensitive).

        Args:
            username: Unique username string.

        Returns:
            User instance, or None if not found.
        """
        return (
            self._session.query(User)
            .options(selectinload(User.attributes))
            .filter(User.username == username)
            .first()
        )

    def get_by_email(self, email: str) -> Optional[User]:
        """
        Retrieve a User by email address.

        Args:
            email: Unique email address.

        Returns:
            User instance, or None if not found.
        """
        return (
            self._session.query(User)
            .options(selectinload(User.attributes))
            .filter(User.email == email)
            .first()
        )

    def username_exists(self, username: str) -> bool:
        """
        Check whether a username is already taken.

        Args:
            username: Username to check.

        Returns:
            True if at least one User with this username exists.
        """
        return self.exists("username", username)

    def email_exists(self, email: str) -> bool:
        """
        Check whether an email address is already registered.

        Args:
            email: Email address to check.

        Returns:
            True if at least one User with this email exists.
        """
        return self.exists("email", email)

    def get_all(self) -> List[User]:
        """
        Retrieve all registered users.

        Returns:
            List of all User instances.
        """
        return (
            self._session.query(User)
            .options(joinedload(User.attributes))
            .distinct()
            .all()
        )


class TokenRepository(BaseRepository[AccessToken]):
    """
    Repository for AccessToken and RefreshToken persistence.

    Manages token creation, lookup, revocation, and cleanup.
    Both token types are handled in the same repository since their
    lifecycle is always coordinated (revoke-all, cleanup-expired).

    Example:
        >>> with UnitOfWork() as uow:
        ...     repo = TokenRepository(uow)
        ...     token = repo.get_access_token("eyJ...")
        ...     if token and token.is_valid():
        ...         ...
    """

    def __init__(self, uow: UnitOfWork | None = None, session: Session | None = None) -> None:
        # Primary model is AccessToken; RefreshToken queries use _session directly.
        super().__init__(AccessToken, uow=uow, session=session)

    # =========================================================================
    # INTERNAL HELPERS (shared by AccessToken / RefreshToken)
    # =========================================================================

    def _get_token(self, model, token: str):
        """Retrieve a token record of ``model`` by its raw token string."""
        return (
            self._session.query(model)
            .filter(model.token == token)
            .one_or_none()
        )

    def _revoke_all(self, model, user_id: int) -> None:
        """Mark every token of ``model`` owned by ``user_id`` as revoked."""
        self._session.query(model).filter(
            model.user_id == user_id
        ).update({"revoked": 1}, synchronize_session=False)
        self._session.flush()

    def _delete_expired(self, model, before: datetime) -> int:
        """Delete tokens of ``model`` whose ``expires_at`` is before ``before``."""
        deleted = (
            self._session.query(model)
            .filter(model.expires_at < before)
            .delete(synchronize_session=False)
        )
        self._session.flush()
        return deleted

    # =========================================================================
    # ACCESS TOKEN
    # =========================================================================

    def get_access_token(self, token: str) -> Optional[AccessToken]:
        """
        Retrieve an AccessToken record by its token string.

        Args:
            token: Raw JWT access token string.

        Returns:
            AccessToken instance, or None if not found.
        """
        return self._get_token(AccessToken, token)

    def save_access_token(self, token: AccessToken) -> AccessToken:
        """
        Persist a new AccessToken record.

        Args:
            token: AccessToken instance to persist.

        Returns:
            The same instance with server-generated fields populated.
        """
        return self.save(token)

    def revoke_access_token(self, token: str) -> bool:
        """
        Revoke a single access token by its string value.

        Args:
            token: Raw JWT token string to revoke.

        Returns:
            True if a token was found and revoked, False otherwise.
        """
        record = self.get_access_token(token)
        if record is None:
            return False

        record.revoked = 1
        self._session.flush()
        return True

    def revoke_all_access_tokens(self, user_id: int) -> None:
        """
        Revoke all active access tokens for a user.

        Args:
            user_id: User primary key.
        """
        self._revoke_all(AccessToken, user_id)

    def delete_expired_access_tokens(self, before: datetime) -> int:
        """
        Delete access tokens that expired before the given timestamp.

        Args:
            before: Cutoff datetime; tokens with expires_at < before are deleted.

        Returns:
            Number of rows deleted.
        """
        return self._delete_expired(AccessToken, before)

    # =========================================================================
    # REFRESH TOKEN
    # =========================================================================

    def get_refresh_token(self, token: str) -> Optional[RefreshToken]:
        """
        Retrieve a RefreshToken record by its token string.

        Args:
            token: Raw refresh token string.

        Returns:
            RefreshToken instance, or None if not found.
        """
        return self._get_token(RefreshToken, token)

    def save_refresh_token(self, token: RefreshToken) -> RefreshToken:
        """
        Persist a new RefreshToken record.

        Args:
            token: RefreshToken instance to persist.

        Returns:
            The same instance with server-generated fields populated.
        """
        return self.save(token)

    def revoke_all_refresh_tokens(self, user_id: int) -> None:
        """
        Revoke all active refresh tokens for a user.

        Args:
            user_id: User primary key.
        """
        self._revoke_all(RefreshToken, user_id)

    def delete_expired_refresh_tokens(self, before: datetime) -> int:
        """
        Delete refresh tokens that expired before the given timestamp.

        Args:
            before: Cutoff datetime; tokens with expires_at < before are deleted.

        Returns:
            Number of rows deleted.
        """
        return self._delete_expired(RefreshToken, before)

    # =========================================================================
    # COMBINED OPERATIONS
    # =========================================================================

    def revoke_all_tokens(self, user_id: int) -> None:
        """
        Revoke all access and refresh tokens for a user in one transaction.

        Intended for password-change and logout-everywhere flows.

        Args:
            user_id: User primary key.
        """
        self.revoke_all_access_tokens(user_id)
        self.revoke_all_refresh_tokens(user_id)

    def cleanup_expired_tokens(self) -> tuple[int, int]:
        """
        Delete all expired access and refresh tokens.

        Returns:
            Tuple of (access_tokens_deleted, refresh_tokens_deleted).
        """
        now = datetime.utcnow()
        access_deleted  = self.delete_expired_access_tokens(now)
        refresh_deleted = self.delete_expired_refresh_tokens(now)
        return access_deleted, refresh_deleted


class AttributeRepository(BaseRepository[UserAttribute]):
    """
    Repository for UserAttribute entity persistence.

    Manages attribute assignments between users and permission attributes.

    Example:
        >>> with UnitOfWork() as uow:
        ...     repo = AttributeRepository(uow)
        ...     attrs = repo.get_by_user(5)
    """

    def __init__(self, uow: UnitOfWork | None = None, session: Session | None = None) -> None:
        super().__init__(UserAttribute, uow=uow, session=session)

    def get_by_user(self, user_id: int) -> List[UserAttribute]:
        """
        Retrieve all attributes assigned to a user.

        Args:
            user_id: User primary key.

        Returns:
            List of UserAttribute instances.
        """
        return (
            self._session.query(UserAttribute)
            .filter(UserAttribute.user_id == user_id)
            .all()
        )

    def get_by_user_and_attribute(
        self,
        user_id: int,
        attribute_name: str,
    ) -> Optional[UserAttribute]:
        """
        Check if a specific attribute is assigned to a user.

        Args:
            user_id: User primary key.
            attribute_name: Attribute name string.

        Returns:
            UserAttribute instance if found, None otherwise.
        """
        return (
            self._session.query(UserAttribute)
            .filter(
                UserAttribute.user_id == user_id,
                UserAttribute.attribute_name == attribute_name,
            )
            .one_or_none()
        )

    def add_attribute(self, user_id: int, attribute_name: str) -> UserAttribute:
        """
        Assign an attribute to a user.

        Args:
            user_id: User primary key.
            attribute_name: Attribute name to assign.

        Returns:
            The created UserAttribute instance.

        Raises:
            exc: If the attribute already exists (constraint violation).
        """
        ua = UserAttribute(
            user_id=user_id,
            attribute_name=attribute_name,
        )
        self._session.add(ua)
        self._session.flush()
        return ua

    def add_attributes(
        self,
        user_id: int,
        attribute_names: List[str],
    ) -> List[UserAttribute]:
        """
        Assign multiple attributes to a user (skip existing ones).

        Args:
            user_id: User primary key.
            attribute_names: List of attribute names to assign.

        Returns:
            List of created UserAttribute instances.
        """
        created = []
        for attr_name in attribute_names:
            existing = self.get_by_user_and_attribute(user_id, attr_name)
            if existing is None:
                ua = UserAttribute(
                    user_id=user_id,
                    attribute_name=attr_name,
                )
                self._session.add(ua)
                created.append(ua)
        self._session.flush()
        return created

    def remove_attribute(self, user_id: int, attribute_name: str) -> bool:
        """
        Remove an attribute from a user.

        Args:
            user_id: User primary key.
            attribute_name: Attribute name to remove.

        Returns:
            True if an attribute was deleted, False if it didn't exist.
        """
        deleted = (
            self._session.query(UserAttribute)
            .filter(
                UserAttribute.user_id == user_id,
                UserAttribute.attribute_name == attribute_name,
            )
            .delete(synchronize_session=False)
        )
        self._session.flush()
        return deleted > 0

    def remove_attributes(
        self,
        user_id: int,
        attribute_names: List[str],
    ) -> int:
        """
        Remove multiple attributes from a user.

        Args:
            user_id: User primary key.
            attribute_names: List of attribute names to remove.

        Returns:
            Number of attributes deleted.
        """
        deleted = (
            self._session.query(UserAttribute)
            .filter(
                UserAttribute.user_id == user_id,
                UserAttribute.attribute_name.in_(attribute_names),
            )
            .delete(synchronize_session=False)
        )
        self._session.flush()
        return deleted


class MFARepository(BaseRepository[MFATotpCredential]):
    """
    Repository for MFA persistence: TOTP credentials, recovery codes, and
    login challenges. Grouped together since their lifecycle is coordinated
    (enabling/disabling TOTP always touches credential + recovery codes).

    Example:
        >>> with UnitOfWork() as uow:
        ...     repo = MFARepository(uow)
        ...     cred = repo.get_totp_credential(user_id=1)
    """

    def __init__(self, uow: UnitOfWork | None = None, session: Session | None = None) -> None:
        super().__init__(MFATotpCredential, uow=uow, session=session)

    # =========================================================================
    # TOTP CREDENTIAL
    # =========================================================================

    def get_totp_credential(self, user_id: int) -> Optional[MFATotpCredential]:
        """Retrieve the (at most one) TOTP credential for a user, confirmed or not."""
        return (
            self._session.query(MFATotpCredential)
            .filter(MFATotpCredential.user_id == user_id)
            .one_or_none()
        )

    def save_totp_credential(self, credential: MFATotpCredential) -> MFATotpCredential:
        """Persist a new TOTP credential."""
        return self.save(credential)

    def delete_totp_credential(self, user_id: int) -> None:
        """Delete the TOTP credential for a user, if any."""
        self._session.query(MFATotpCredential).filter(
            MFATotpCredential.user_id == user_id
        ).delete(synchronize_session=False)
        self._session.flush()

    # =========================================================================
    # RECOVERY CODES
    # =========================================================================

    def get_recovery_codes(self, user_id: int, only_unused: bool = False) -> List[MFARecoveryCode]:
        """Retrieve recovery codes for a user, optionally filtering to unused ones."""
        query = self._session.query(MFARecoveryCode).filter(MFARecoveryCode.user_id == user_id)
        if only_unused:
            query = query.filter(MFARecoveryCode.used_at.is_(None))
        return query.all()

    def save_recovery_codes(self, codes: List[MFARecoveryCode]) -> None:
        """Persist a freshly generated batch of recovery codes."""
        self._session.add_all(codes)
        self._session.flush()

    def delete_recovery_codes(self, user_id: int) -> None:
        """Delete all recovery codes for a user (used before regenerating a batch)."""
        self._session.query(MFARecoveryCode).filter(
            MFARecoveryCode.user_id == user_id
        ).delete(synchronize_session=False)
        self._session.flush()

    def mark_recovery_code_used(self, code_id: int) -> None:
        """Mark a recovery code as consumed so it can't be reused."""
        code = self._session.query(MFARecoveryCode).filter(MFARecoveryCode.id == code_id).one_or_none()
        if code is not None:
            code.used_at = datetime.utcnow()
            self._session.flush()

    # =========================================================================
    # LOGIN CHALLENGES
    # =========================================================================

    def get_challenge(self, token: str) -> Optional[MFAChallenge]:
        """Retrieve an MFAChallenge record by its opaque token string."""
        return (
            self._session.query(MFAChallenge)
            .filter(MFAChallenge.token == token)
            .one_or_none()
        )

    def save_challenge(self, challenge: MFAChallenge) -> MFAChallenge:
        """Persist a newly issued MFA challenge."""
        self._session.add(challenge)
        self._session.flush()
        return challenge

    def increment_challenge_attempts(self, token: str) -> None:
        """Increment the failed-attempt counter for a challenge."""
        self._session.query(MFAChallenge).filter(MFAChallenge.token == token).update(
            {"attempts": MFAChallenge.attempts + 1}, synchronize_session=False
        )
        self._session.flush()

    def delete_challenge(self, token: str) -> None:
        """Delete a challenge (after successful verification, so it can't be reused)."""
        self._session.query(MFAChallenge).filter(
            MFAChallenge.token == token
        ).delete(synchronize_session=False)
        self._session.flush()

    def delete_expired_challenges(self, before: datetime) -> int:
        """Delete challenges whose expires_at is before the given timestamp."""
        deleted = (
            self._session.query(MFAChallenge)
            .filter(MFAChallenge.expires_at < before)
            .delete(synchronize_session=False)
        )
        self._session.flush()
        return deleted
