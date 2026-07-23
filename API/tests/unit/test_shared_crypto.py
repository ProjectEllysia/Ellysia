"""Tests unitarios de shared._crypto (cifrado en reposo por purpose)."""

from __future__ import annotations

import pytest

from src.modules.shared._crypto import decrypt_at_rest, encrypt_at_rest

pytestmark = pytest.mark.unit


def test_roundtrip_for_known_purpose():
    token = encrypt_at_rest("hunter2", purpose="mfa")
    assert token != "hunter2"
    assert decrypt_at_rest(token, purpose="mfa") == "hunter2"


def test_purposes_are_not_interchangeable():
    # Encrypted under "mfa", decrypting under "iris_mailbox" (a different
    # Fernet key) must fail loudly, not silently return garbage.
    from cryptography.fernet import InvalidToken

    token = encrypt_at_rest("some-refresh-token", purpose="iris_mailbox")
    with pytest.raises(InvalidToken):
        decrypt_at_rest(token, purpose="mfa")


def test_unknown_purpose_raises_clear_error(monkeypatch):
    monkeypatch.delenv("SOMETHING_UNCONFIGURED_ENCRYPTION_KEY", raising=False)
    with pytest.raises(ValueError, match="SOMETHING_UNCONFIGURED_ENCRYPTION_KEY"):
        encrypt_at_rest("x", purpose="something_unconfigured")
