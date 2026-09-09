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
from sqlalchemy import Text
from sqlalchemy.types import TypeDecorator


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


class EncryptedText(TypeDecorator):
    """Columna de texto que se cifra al escribir y se descifra al leer, de
    forma transparente para quien la usa.

    Introducida para ``IrisRawMessage.content`` (M09/B19): el motor de
    reglas de Iris lee el raw de un mensaje en más de diez puntos distintos
    de ``managers/analysis.py``, y repetir ``encrypt_at_rest``/
    ``decrypt_at_rest`` a mano en cada uno de ellos convertía cada lectura en
    una oportunidad de olvidarse de descifrar (o de cifrar antes de guardar).
    Con este tipo, ``modelo.campo`` es siempre el texto plano en Python; lo
    único que cambia es lo que llega a la fila de la base de datos.

    Ver el issue de seguimiento sobre si el resto de columnas cifradas a
    mano del repositorio (``IrisMailboxConnection.refresh_token_enc``/
    ``access_token_enc``, el secreto TOTP de MFA) deberían migrar a este
    mismo patrón para no dejar dos formas de hacer lo mismo conviviendo.

    Uso: ``Column(EncryptedText(purpose="mi_proposito"), nullable=False)`` --
    el ``purpose`` es el mismo concepto que ya usan ``encrypt_at_rest``/
    ``decrypt_at_rest``: cada uno tiene su propia clave, así que comprometer
    una no compromete las demás.
    """

    impl = Text
    cache_ok = True

    def __init__(self, purpose: str, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._purpose = purpose

    def process_bind_param(self, value, dialect):
        """Se llama al escribir: cifra el texto plano antes de mandarlo a la BD."""
        if value is None:
            return None
        return encrypt_at_rest(value, purpose=self._purpose)

    def process_result_value(self, value, dialect):
        """Se llama al leer: descifra lo que viene de la BD antes de dárselo a Python."""
        if value is None:
            return None
        return decrypt_at_rest(value, purpose=self._purpose)
