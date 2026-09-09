"""
Lock distribuido por conexión para el sync de buzón de Iris (B02).

``IrisMailboxManager.submit_sync()`` ya evita reencolar un job mientras el
anterior sigue "started" (mismo ``job_id`` determinista, ver
``TaskQueue.submit``), pero esa protección depende de que RQ mantenga el
estado del job al día -- un worker que muere a mitad de sync deja la fila
"started" en Redis para siempre, sin nada que la libere. Este lock es la
capa que sí se autorrecupera: un ``SET NX EX`` con TTL propio, renovado
mientras el sync avanza (ver ``IrisMailboxManager._drain_pending``) y
liberado explícitamente al terminar -- si nadie lo libera, expira solo.

Cada adquisición lleva un token propio para que liberar/renovar solo actúe
sobre el lock que el titular actual sostiene: si el TTL ya expiró y otro
sync lo adquirió mientras tanto, un ``finally`` tardío del titular anterior
no debe poder borrar el lock del nuevo titular.
"""

from __future__ import annotations

import logging
import secrets

from src.modules.system.taskqueue.connection import RedisConnectionFactory

logger = logging.getLogger(__name__)

_LOCK_KEY_PREFIX = "iris:mailbox-sync:"

# Solo borra/renueva si el token todavía coincide con el titular actual --
# sin esto, un release() o renew() tardío (el proceso se quedó colgado más
# allá del TTL) podría pisar el lock de quien lo adquirió después.
_RELEASE_SCRIPT = """
if redis.call("get", KEYS[1]) == ARGV[1] then
    return redis.call("del", KEYS[1])
else
    return 0
end
"""

_RENEW_SCRIPT = """
if redis.call("get", KEYS[1]) == ARGV[1] then
    return redis.call("expire", KEYS[1], ARGV[2])
else
    return 0
end
"""


class MailboxSyncLock:
    """Un único sync activo por conexión, con TTL autorrecuperable.

    Typical usage::

        lock = MailboxSyncLock(connection_id, ttl_seconds=900)
        if not lock.acquire():
            return  # ya hay un sync en curso -- no-op idempotente
        try:
            ...  # trabajo del sync; lock.renew() en cada mensaje procesado
        finally:
            lock.release()
    """

    def __init__(self, connection_id: int, ttl_seconds: int) -> None:
        self._key = f"{_LOCK_KEY_PREFIX}{connection_id}"
        self._ttl_seconds = ttl_seconds
        self._token = secrets.token_hex(16)
        self._redis = RedisConnectionFactory.decoded()

    def acquire(self) -> bool:
        """Intenta adquirir el lock. True si tuvo éxito."""
        return bool(self._redis.set(self._key, self._token, nx=True, ex=self._ttl_seconds))

    def renew(self) -> None:
        """Extiende el TTL mientras el titular sigue trabajando.

        No-op silencioso si el lock ya expiró (Redis caído, TTL agotado) --
        el sync en curso simplemente deja de estar protegido a partir de ahí,
        que es preferible a tumbar un sync que ya iba bien encaminado.
        """
        try:
            self._redis.eval(_RENEW_SCRIPT, 1, self._key, self._token, self._ttl_seconds)
        except Exception:
            logger.warning("No se pudo renovar el lock de sync %s", self._key, exc_info=True)

    def release(self) -> None:
        """Libera el lock si todavía es el titular. No-op si ya expiró."""
        try:
            self._redis.eval(_RELEASE_SCRIPT, 1, self._key, self._token)
        except Exception:
            logger.warning(
                "No se pudo liberar el lock de sync %s; expirará solo por TTL.",
                self._key, exc_info=True,
            )
