"""
taskqueue/task.py
─────────────────
Task dataclass and TaskStatus enum for the RQ-backed task system.
Serializable representation of a background task.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from rq.job import Job


class TaskStatus(Enum):
    PENDING   = "pending"
    RUNNING   = "running"
    COMPLETED = "completed"
    FAILED    = "failed"
    CANCELLED = "cancelled"
    TIMEOUT   = "timeout"

    def __str__(self) -> str:
        return self.value


@dataclass
class Task:
    """Serializable representation of a background task, backed by an RQ job."""

    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    name: str = ""
    category: str = ""
    external_id: Optional[str] = None
    status: TaskStatus = TaskStatus.PENDING
    progress: int = 0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    error: Optional[str] = None

    @classmethod
    def from_rq_job(
        cls,
        job: Job,
        category: str = "",
        external_id: Optional[str] = None,
    ) -> Task:
        # C8: refresh=False es correcto aquí — todos los callers pasan un
        # `job` recién obtenido de `Job.fetch()` (HGETALL completo, status
        # incluido), así que un refresh aquí sería un round-trip a Redis
        # redundante en el path de sondeo más frecuente de la app
        # (GET /themis/results cada 4s). Si algún caller nuevo empezara a
        # reutilizar una instancia de `Job` entre llamadas, este supuesto
        # dejaría de cumplirse y sí haría falta refrescar.
        meta = job.meta or {}
        return cls(
            id=job.id,
            name=job.description or f"task-{job.id[:8]}",
            category=category or meta.get("category", ""),
            external_id=external_id or meta.get("external_id"),
            status=cls._rq_status_to_task_status(job.get_status(refresh=False)),
            progress=meta.get("progress", 0),
            created_at=job.created_at or datetime.now(timezone.utc),
            started_at=job.started_at,
            finished_at=job.ended_at,
            error=job.exc_info,
        )

    @staticmethod
    def _rq_status_to_task_status(rq_status: str | None) -> TaskStatus:
        if rq_status is None:
            return TaskStatus.PENDING
        rq_status = rq_status.lower()
        if rq_status in ("queued", "scheduled", "deferred"):
            return TaskStatus.PENDING
        if rq_status == "started":
            return TaskStatus.RUNNING
        if rq_status == "finished":
            return TaskStatus.COMPLETED
        if rq_status == "failed":
            return TaskStatus.FAILED
        if rq_status == "stopped":
            return TaskStatus.CANCELLED
        return TaskStatus.PENDING

    def to_dict(self) -> dict:
        return {
            "id":          self.id,
            "name":        self.name,
            "category":    self.category,
            "externalId":  self.external_id,
            "status":      str(self.status),
            "progress":    self.progress,
            "createdAt":   self.created_at.isoformat() if self.created_at else None,
            "startedAt":   self.started_at.isoformat() if self.started_at else None,
            "finishedAt":  self.finished_at.isoformat() if self.finished_at else None,
            "error":       self.error,
        }
