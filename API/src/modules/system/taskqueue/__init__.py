"""
taskqueue/__init__.py
────────────────────
Public API for the RQ-backed background task queue system.
"""

from .deadline import JobDeadlineExceeded
from .dispatcher import OutboxDispatcher
from .job_context import JobHandle, job_context
from .outbox import TaskDispatch, build_dispatch
from .queue import DEFAULT_QUEUE, ITaskQueue, QueueRegistry, TaskQueue
from .task import Task, TaskStatus
from .tracking import TaskTrackingMixin
from .connection import ping_redis

__all__ = [
    "ITaskQueue",
    "JobDeadlineExceeded",
    "JobHandle",
    "job_context",
    "OutboxDispatcher",
    "Task",
    "TaskDispatch",
    "TaskQueue",
    "TaskStatus",
    "TaskTrackingMixin",
    "build_dispatch",
    "ping_redis",
    "QueueRegistry",
    "DEFAULT_QUEUE",
]
