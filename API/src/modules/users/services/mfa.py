"""
TOTP and recovery-code primitives for MFA.

Pure functions only — no DB access, no encryption-at-rest (that lives in
services.secrets.encrypt_totp_secret / decrypt_totp_secret, called by the
manager layer around these).

Functions:
    generate_totp_secret    — Random Base32 secret for a new TOTP enrollment.
    totp_provisioning_uri   — otpauth:// URI an authenticator app scans as a QR.
    verify_totp_code        — Verify a 6-digit code against a secret.
    generate_recovery_codes — N one-time recovery codes, human-friendly format.
"""

import secrets as _secrets
from typing import List

import pyotp

import src.modules.system.config_reading as CR

_RECOVERY_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def generate_totp_secret() -> str:
    """Generate a new random Base32 TOTP secret."""
    return pyotp.random_base32()


def totp_provisioning_uri(secret: str, username: str) -> str:
    """Build the otpauth:// URI an authenticator app scans as a QR code."""
    issuer = CR.mfa_config().issuer
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)


def verify_totp_code(secret: str, code: str) -> bool:
    """Verify a 6-digit TOTP code, tolerating +/-1 time step of clock drift."""
    if not code or not code.isdigit():
        return False
    return pyotp.TOTP(secret).verify(code, valid_window=1)


def generate_recovery_codes(count: int) -> List[str]:
    """Generate `count` one-time recovery codes in 'XXXX-XXXX' format."""
    def _one_code() -> str:
        raw = "".join(_secrets.choice(_RECOVERY_CODE_ALPHABET) for _ in range(8))
        return f"{raw[:4]}-{raw[4:]}"

    return [_one_code() for _ in range(count)]
