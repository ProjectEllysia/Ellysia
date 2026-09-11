"""
system/__init__.py
Mecanismo transversal: logging, configuración y TaskQueue.

No importa ``endpoints`` a propósito: el blueprint de ``/system`` necesita los
decoradores de permisos de ``users``, y casi todo el proyecto importa este paquete
(``config_reading``, la cola) muy pronto. Cargar aquí los endpoints haría que
cualquier lectura de la configuración arrastrase ``users`` y cerrase un ciclo de
imports. ``run.py`` importa ``system_blp`` directamente de ``system.endpoints``.
"""

from .logging import configure_logging
from .taskqueue import TaskQueue, Task, TaskStatus, ping_redis

__all__ = [
    "configure_logging",
    "TaskQueue",
    "Task",
    "TaskStatus",
    "ping_redis",
]
