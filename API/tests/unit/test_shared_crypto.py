"""Tests unitarios de shared._crypto (cifrado en reposo por purpose)."""

from __future__ import annotations

import pathlib
import re

import pytest

from src.modules.shared._crypto import EncryptedText, decrypt_at_rest, encrypt_at_rest

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


# ---------------------------------------------------------------------------
# Un solo patrón de cifrado en reposo
#
# El repositorio llegó a tener dos formas de cifrar una columna conviviendo:
# el tipo ``EncryptedText`` en unos sitios y llamadas sueltas a
# ``encrypt_at_rest``/``decrypt_at_rest`` repartidas por los managers en
# otros. Quien añadía un campo sensible no tenía ninguna señal de cuál
# imitar. Los dos tests de esta sección son lo que impide que vuelva a
# pasar: uno fija qué columnas están cifradas y con qué clave, y el otro
# corta de raíz que reaparezca una llamada manual.
# ---------------------------------------------------------------------------

# (modelo, columna, purpose) de cada columna cifrada en reposo del proyecto.
# Añadir un campo sensible nuevo implica añadirlo aquí.
_ENCRYPTED_COLUMNS = [
    ("src.modules.users.model", "MFATotpCredential", "totp_secret", "mfa"),
    ("src.modules.features.iris.model", "IrisMailboxConnection", "refresh_token", "iris_mailbox"),
    ("src.modules.features.iris.model", "IrisMailboxConnection", "access_token", "iris_mailbox"),
    ("src.modules.features.iris.model", "IrisRawMessage", "content", "iris_raw_message"),
]


@pytest.mark.parametrize("module_path,model_name,column_name,purpose", _ENCRYPTED_COLUMNS)
def test_every_secret_column_is_an_encrypted_text(module_path, model_name, column_name, purpose):
    """Cada columna sensible declara ``EncryptedText`` y su ``purpose``.

    Comprueba el tipo declarado, no un round-trip: un test de round-trip
    seguiría pasando si alguien devolviera la columna a ``Text`` y volviera a
    cifrar a mano en el manager, que es justo la regresión que aquí importa.
    """
    import importlib

    model = getattr(importlib.import_module(module_path), model_name)
    column_type = model.__table__.c[column_name].type

    assert isinstance(column_type, EncryptedText), (
        f"{model_name}.{column_name} guarda un secreto y debe declararse "
        f"EncryptedText, no {type(column_type).__name__}"
    )
    assert column_type._purpose == purpose


def test_no_column_is_encrypted_by_hand_any_more():
    """Nadie vuelve a cifrar una columna llamando a mano a ``encrypt_at_rest``.

    Fuera de ``_crypto.py`` (que las define) y de las migraciones de Alembic
    (que sí trabajan con la fila cruda, sin ORM que aplique el tipo), estas
    dos funciones no deben aparecer en ``src/``: si un manager las llama es
    que alguien ha vuelto al patrón viejo.
    """
    source_root = pathlib.Path(__file__).resolve().parents[2] / "src"
    call_pattern = re.compile(r"(?<![\w.])(?:en|de)crypt_at_rest\s*\(")

    offenders = []
    for path in source_root.rglob("*.py"):
        if path.name == "_crypto.py":
            continue
        if call_pattern.search(path.read_text(encoding="utf-8")):
            offenders.append(str(path.relative_to(source_root)))

    assert not offenders, (
        "Cifrado manual en reposo fuera de _crypto.py; usa el tipo de columna "
        f"EncryptedText en su lugar: {offenders}"
    )
