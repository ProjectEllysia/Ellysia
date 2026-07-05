"""Ellysia's own vulnerability engine (native detection).

Home for everything that makes Ellysia a scanner in its own right rather than an
orchestrator of Nmap/Nikto/OpenVAS. Managers live in ``sentinel/managers.py`` and
repositories in ``sentinel/repositories.py`` by project convention; the detection
logic (the engine, and in later phases the dissectors, checks and transport)
lives here.
"""

from __future__ import annotations

from .engine import (
    EllysiaEngine,
    Service,
    services_from_open_ports,
    QOD_OPEN_PORT,
)

__all__ = [
    "EllysiaEngine",
    "Service",
    "services_from_open_ports",
    "QOD_OPEN_PORT",
]
