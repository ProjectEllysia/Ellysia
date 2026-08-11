"""
Cifrado en reposo del lado servidor, para secretos que la aplicación
necesita poder leer (a diferencia de Acheron: zero-knowledge real, el
servidor nunca ve el plaintext — ver ``acheron/model.py``).

Generalización del patrón que ya usaba ``users/services/secrets.py`` para
el secreto TOTP: Fernet con una clave por ``purpose`` desde variables de
entorno. Cada ``purpose`` tiene su propia clave (``config_reading.
get_encryption_key``), así que comprometer una no compromete las demás y
cada una se puede rotar por separado.
"""

from __future__ import annotations

from cryptography.fernet import Fernet


def _get_fernet(purpose: str) -> Fernet:
    # Lazy import: config_reading pulls in system/__init__.py, which pulls
    # in users (permissions, secrets.py -> this module) — importing it at
    # module scope here would deadlock that cycle during shared/__init__.py's
    # own eager import of this module.
    import src.modules.system.config_reading as CR
    key = CR.get_encryption_key(purpose)
    return Fernet(key.encode("utf-8") if isinstance(key, str) else key)


def encrypt_at_rest(plaintext: str, purpose: str) -> str:
    """Cifra *plaintext* con la clave Fernet del ``purpose`` dado."""
    return _get_fernet(purpose).encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt_at_rest(token: str, purpose: str) -> str:
    """Descifra un token producido por ``encrypt_at_rest`` con el mismo ``purpose``."""
    return _get_fernet(purpose).decrypt(token.encode("utf-8")).decode("utf-8")
