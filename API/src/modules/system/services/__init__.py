"""Servicios internos del módulo de sistema."""

from .log_reader import (
    LogNotFoundError,
    LogQueryError,
    LogSnapshotChangedError,
    read_logs,
)

__all__ = [
    "LogNotFoundError",
    "LogQueryError",
    "LogSnapshotChangedError",
    "read_logs",
]
