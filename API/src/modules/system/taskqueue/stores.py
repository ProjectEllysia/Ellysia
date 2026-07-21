"""
taskqueue/stores.py
───────────────────
Colaboradores con responsabilidad única (SRP) para el estado del taskqueue
en Redis. ``TaskQueue`` compone estos stores en lugar de tocar Redis
directamente:

- ``ExternalIdStore``    mapa external_id -> job_id (hash).
- ``CancellationStore``  señales de cancelación cooperativa (claves con TTL).
- ``HistoryStore``       historial de tareas terminadas (zset + snapshots).
- ``ProgressStore``      progreso 0-100 almacenado en ``job.meta``.
"""

from __future__ import annotations

import json
import time
from typing import List, Optional

import redis as redis_lib


class ExternalIdStore:
    """Mapa ``external_id`` -> ``job_id`` almacenado en un hash de Redis."""

    KEY = "taskqueue:external_ids"

    def __init__(self, conn: redis_lib.Redis) -> None:
        self._redis = conn

    def set(self, external_id: str, job_id: str) -> None:
        self._redis.hset(self.KEY, external_id, job_id)

    def get(self, external_id: str) -> Optional[str]:
        return self._redis.hget(self.KEY, external_id)

    def remove_by_job_id(self, job_id: str) -> None:
        # C7: recorre el hash completo en vez de salir en la primera
        # coincidencia — si 2 external_ids apuntaran al mismo job_id (p. ej.
        # tras un reencolado), el segundo mapping quedaba huérfano.
        cursor = 0
        while True:
            cursor, items = self._redis.hscan(self.KEY, cursor=cursor)
            for key, val in items.items():
                if val == job_id:
                    self._redis.hdel(self.KEY, key)
            if cursor == 0:
                break


class CancellationStore:
    """Señales de cancelación cooperativa: claves con TTL que los workers
    consultan periódicamente para detenerse de forma ordenada."""

    PREFIX = "taskqueue:cancel:"
    TTL = 3600

    def __init__(self, conn: redis_lib.Redis) -> None:
        self._redis = conn

    def signal(self, task_id: str) -> None:
        self._redis.set(self.PREFIX + task_id, "1", ex=self.TTL)

    def is_cancelled(self, task_id: str) -> bool:
        return bool(self._redis.exists(self.PREFIX + task_id))

    def clear(self, task_id: str) -> None:
        self._redis.delete(self.PREFIX + task_id)


class HistoryStore:
    """Historial de tareas terminadas (completadas, fallidas y canceladas).

    Guarda un *snapshot* JSON de cada tarea al terminar, en un hash paralelo
    al sorted set de ordenación. Así el historial no depende de que el job
    siga existiendo en Redis (RQ los expira con ``result_ttl``) y se evita el
    N+1 de hacer ``Job.fetch`` por cada entrada al listar.
    """

    KEY = "taskqueue:history"
    SNAP_KEY = "taskqueue:history:snap"

    def __init__(self, conn: redis_lib.Redis, max_items: int, ttl: int) -> None:
        self._redis = conn
        self._max = max_items
        self._ttl = ttl
        self._migrate_legacy()

    def record(self, snapshot: dict) -> None:
        """Registra el snapshot de una tarea terminada en el historial."""
        task_id = snapshot.get("id")
        if not task_id:
            return
        pipe = self._redis.pipeline()
        pipe.zadd(self.KEY, {task_id: time.time()})
        pipe.hset(self.SNAP_KEY, task_id, json.dumps(snapshot))
        if self._ttl > 0:
            pipe.expire(self.KEY, self._ttl)
            pipe.expire(self.SNAP_KEY, self._ttl)
        pipe.execute()
        if self._max > 0 and self._redis.zcard(self.KEY) > self._max:
            self._trim()

    def list(self, category: Optional[str] = None) -> List[dict]:
        """Devuelve los snapshots, del más reciente al más antiguo."""
        ids = self._redis.zrevrange(self.KEY, 0, -1)
        if not ids:
            return []
        snaps = self._redis.hmget(self.SNAP_KEY, ids)
        out: List[dict] = []
        for raw in snaps:
            if not raw:
                continue
            try:
                data = json.loads(raw)
            except (ValueError, TypeError):
                continue
            if category is not None and data.get("category") != category:
                continue
            out.append(data)
        return out

    def count(self) -> int:
        return self._redis.zcard(self.KEY)

    def _trim(self) -> None:
        total = self._redis.zcard(self.KEY)
        excess = total - self._max
        if excess <= 0:
            return
        to_remove = self._redis.zrange(self.KEY, 0, excess - 1)
        if not to_remove:
            return
        pipe = self._redis.pipeline()
        for task_id in to_remove:
            pipe.zrem(self.KEY, task_id)
            pipe.hdel(self.SNAP_KEY, task_id)
        pipe.execute()

    def _migrate_legacy(self) -> None:
        """La versión inicial almacenaba el historial como Hash y un hash
        ``:status`` paralelo. Si se detecta el formato antiguo, se descarta
        para reconstruirlo con el nuevo esquema (zset + snapshots)."""
        try:
            if self._redis.type(self.KEY) == "hash":
                self._redis.delete(self.KEY)
                self._redis.delete(f"{self.KEY}:status")
        except redis_lib.RedisError:
            pass


class ProgressStore:
    """Progreso 0-100 de una tarea, almacenado en ``job.meta``.

    Opera sobre un objeto ``Job`` de RQ (no sobre Redis directamente) porque
    el progreso vive junto a los metadatos del job.
    """

    @staticmethod
    def write(job, progress: int) -> None:
        job.meta["progress"] = progress
        job.save_meta()

    @staticmethod
    def read(job) -> int:
        return (job.meta or {}).get("progress", 0)
