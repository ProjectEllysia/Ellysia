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

    **Es la única forma de cifrar en reposo que hay en el repositorio.**
    Todo secreto que la aplicación necesite poder leer se declara con este
    tipo; no queda ni un solo sitio que llame a ``encrypt_at_rest``/
    ``decrypt_at_rest`` a mano sobre una columna, y añadir uno volvería a
    dejar dos maneras distintas de hacer lo mismo conviviendo -- que era
    exactamente el problema. Quien añada un campo sensible nuevo no tiene
    que elegir patrón: copia el de al lado.
    ``tests/unit/test_shared_crypto.py`` lo comprueba columna a columna.

    Con este tipo, ``modelo.campo`` es siempre el texto plano en Python; lo
    único que cambia es lo que llega a la fila de la base de datos. Eso
    quita de en medio el modo de fallo que motivó el tipo: el motor de
    reglas de Iris lee el raw de un mensaje en más de diez puntos distintos
    de ``managers/analysis.py``, y repetir el descifrado a mano en cada uno
    convertía cada lectura en una oportunidad de olvidarse.

    El coste que hay que conocer: el descifrado pasa a ocurrir **al cargar
    la fila**, no en el punto donde se usa el valor. Para los secretos que
    la mayoría de las consultas no miran (los tokens de OAuth de un buzón,
    el secreto TOTP) la columna se declara además ``deferred``, de modo que
    solo se descifra cuando alguien toca el atributo -- ver
    ``IrisMailboxConnection.refresh_token`` y
    ``MFATotpCredential.totp_secret``.

    Uso: ``Column(EncryptedText(purpose="mi_proposito"), nullable=False)`` --
    el ``purpose`` es el mismo concepto que ya usan ``encrypt_at_rest``/
    ``decrypt_at_rest``: cada uno tiene su propia clave (variable de entorno
    ``<PURPOSE>_ENCRYPTION_KEY``), así que comprometer una no compromete las
    demás y cada una se puede rotar por separado.

    Attributes:
        purpose: Identificador de la clave Fernet con la que se cifra esta
            columna, tal y como lo resuelve
            ``config_reading.get_encryption_key``. Cadena en minúsculas y
            snake_case (``"mfa"``, ``"iris_mailbox"``,
            ``"iris_raw_message"``); no es un valor libre, tiene que existir
            como variable de entorno o el primer acceso a la columna lanza.
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
