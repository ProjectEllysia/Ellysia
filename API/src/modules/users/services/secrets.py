"""
Password hashing and verification using Argon2id.

Provides forward-compatible verification: hashes starting with '$argon2'
are verified with Argon2, while legacy SHA-256+salt hashes are verified
with hmac.compare_digest and transparently migrated to Argon2 on next login.

Functions:
    hash_password         — Hash a password with Argon2id (includes salt).
    verify_password       — Verify a password; returns (valid, needs_rehash).
    generate_salt         — Legacy helper kept for DB compatibility during migration.
    hash_password_with_salt — Legacy SHA-256 helper kept for migration path only.
"""

import hashlib
import hmac
import os

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

import src.modules.system.config_reading as CR
from src.modules.shared._crypto import decrypt_at_rest, encrypt_at_rest


def _get_hasher() -> PasswordHasher:
    return PasswordHasher(**CR.argon2_config().as_kwargs())


def hash_password(password: str) -> str:
    """Hash a password with Argon2id. The salt is embedded in the returned string."""
    return _get_hasher().hash(password)


def verify_password(
    stored_hash: str,
    password: str,
    legacy_salt: str = "",
) -> tuple[bool, bool]:
    """
    Verify a password against a stored hash.

    Supports both Argon2id hashes (new) and legacy SHA-256+salt hashes.
    Uses constant-time comparison in both paths.

    Args:
        stored_hash:  The hash stored in the database.
        password:     The plaintext password to verify.
        legacy_salt:  The salt used for the legacy SHA-256 hash (ignored for Argon2).

    Returns:
        (is_valid, needs_rehash) — needs_rehash is True when the hash uses the
        legacy format or when Argon2 parameters have changed (check_needs_rehash).
    """
    if stored_hash.startswith("$argon2"):
        ph = _get_hasher()
        try:
            ph.verify(stored_hash, password)
            needs_rehash = ph.check_needs_rehash(stored_hash)
            return True, needs_rehash
        except VerifyMismatchError:
            return False, False
        except (VerificationError, InvalidHashError):
            return False, False

    # Legacy SHA-256+salt path
    expected = hash_password_with_salt(password, legacy_salt)
    is_valid = hmac.compare_digest(expected, stored_hash)
    return is_valid, is_valid  # needs_rehash == is_valid (upgrade on success)


# ---------------------------------------------------------------------------
# Legacy helpers — kept only for the migration path (SHA-256 verification).
# Do NOT use for new passwords.
# ---------------------------------------------------------------------------

def generate_salt() -> str:
    """Return an empty string. Argon2 embeds its own salt; kept for API compat."""
    return ""


def hash_password_with_salt(password: str, salt: str) -> str:
    """SHA-256 hash of salt+password. Used only to verify legacy stored hashes."""
    return hashlib.sha256((salt + password).encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# TOTP secret encryption at rest.
#
# Unlike Acheron (zero-knowledge — the server never sees plaintext secrets),
# the server MUST be able to read the TOTP secret to compute the current code
# and verify a login attempt. "Encrypted at rest" here means protected against
# someone reading the database directly, not hidden from the application.
# ---------------------------------------------------------------------------

def encrypt_totp_secret(secret: str) -> str:
    """Encrypt a TOTP secret for storage, using the server-side MFA_ENCRYPTION_KEY."""
    return encrypt_at_rest(secret, purpose="mfa")


def decrypt_totp_secret(token: str) -> str:
    """Decrypt a TOTP secret previously produced by encrypt_totp_secret()."""
    return decrypt_at_rest(token, purpose="mfa")
