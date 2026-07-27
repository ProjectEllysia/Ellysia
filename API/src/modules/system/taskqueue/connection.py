"""
taskqueue/connection.py
───────────────────────
Fuente única de conexiones Redis para el sistema de tareas.

RQ necesita una conexión binaria (``decode_responses=False``) porque
serializa los jobs con pickle. Las claves propias del taskqueue (hashes,
sorted sets, flags de cancelación) son cadenas y se manejan mejor con una
conexión decodificada. ``RedisConnectionFactory`` centraliza la lectura de
configuración para que host/port/db/password vivan en un único lugar y no
se dupliquen entre la cola y el worker.
"""

from __future__ import annotations

import redis as redis_lib

import src.modules.system.config_reading as CR

_logger = CR.get_logger(__name__)

def ping_redis() -> bool:
    try:
        redis_cfg = CR.get_redis_config()
        r = redis_lib.Redis(
            host=redis_cfg["host"],
            port=redis_cfg["port"],
            db=redis_cfg["db"],
            password=redis_cfg["password"],
            socket_connect_timeout=redis_cfg.get("socket_connect_timeout", 2),
        )
        r.ping()
        r.close()
        _logger.info("Redis conectado correctamente")
    except Exception as e:
        _logger.warning("Redis no disponible — la cola de tareas no funcionara: %s", e)


class RedisConnectionFactory:
    """Crea conexiones Redis a partir de la configuración central."""

    @staticmethod
    def _kwargs(blocking: bool = False) -> dict:
        cfg = CR.get_redis_config()
        kwargs = {
            "host": cfg["host"],
            "port": cfg["port"],
            "db": cfg["db"],
            "password": cfg["password"],
            # Sin connect timeout, un Redis caído bloquearía indefinidamente al
            # conectar, dejando el API colgado y "comiéndose" los CTRL+C.
            "socket_connect_timeout": 5,
        }
        if not blocking:
            # Timeout de lectura para que un Redis lento no cuelgue las
            # operaciones normales (estado de la cola, cancelación, apagado).
            # NO se aplica a la conexión del worker: RQ usa comandos bloqueantes
            # (BLPOP) para sacar jobs y un socket_timeout los abortaría.
            kwargs["socket_timeout"] = 5
        return kwargs

    @classmethod
    def raw(cls, blocking: bool = False) -> redis_lib.Redis:
        """Conexión binaria para RQ (jobs serializados con pickle).

        ``blocking=True`` para el bucle del worker (dequeue con BLPOP), que no
        debe llevar ``socket_timeout``.
        """
        return redis_lib.Redis(**cls._kwargs(blocking=blocking), decode_responses=False)

    @classmethod
    def decoded(cls) -> redis_lib.Redis:
        """Conexión decodificada para las claves string del taskqueue."""
        return redis_lib.Redis(**cls._kwargs(), decode_responses=True)
