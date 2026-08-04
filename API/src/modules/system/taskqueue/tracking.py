"""
taskqueue/tracking.py
─────────────────────
Mixin reutilizable para los managers que respaldan una entidad de dominio
con una tarea en segundo plano (DRY).

Antes, iris y themis repetían el mismo patrón "buscar la tarea por
external_id y, si existe, leer estado/progreso". Este mixin lo centraliza y
fija en un único lugar el formato del ``external_id`` y la categoría de cola.

La subclase debe:
- exponer ``self._tq`` (una ``ITaskQueue``), y
- definir ``EXTERNAL_ID_PREFIX`` y ``TASK_CATEGORY``.
"""

from __future__ import annotations

from typing import Optional

from .queue import ITaskQueue, TaskQueue
from .task import Task


class TaskTrackingMixin:
    """Acceso uniforme al estado/progreso de la tarea de una entidad (DRY).

    **Propósito**: Iris y Themis repetían el mismo patrón:
        - external_id_for(entity_id) → construir el ID lógico
        - find_task(entity_id) → buscar el job en TaskQueue
        - task_status_of(entity_id) → obtener status (string)
        - task_progress_of(entity_id) → obtener progreso (0-100)

    Este mixin lo centraliza en un solo lugar para que los managers respondan
    rápidamente "¿en qué estado está mi escaneo/análisis?" sin duplicar lógica.

    **Cómo usarlo (ejemplo: ScanManager)**:
        class ScanManager(TaskTrackingMixin):
            EXTERNAL_ID_PREFIX = "themis-scan:"  # ← define el prefijo
            TASK_CATEGORY = "themis.scan"         # ← define la categoría de cola
            _tq: ITaskQueue  # ← inyectable (singleton o fake en tests)

            def get_scan_status(self, scan_id: int) -> Optional[str]:
                return self.task_status_of(scan_id)  # ← busca por scan_id

    **Flujo**:
        1. Manager: get_scan_status(123)
        2. task_status_of(123) → find_task(123)
        3. external_id_for(123) → "themis-scan:123"
        4. TaskQueue.get_task_by_external_id("themis-scan:123", "themis.scan")
        5. ExternalIdStore busca el job_id de RQ
        6. Fetch del job desde Redis, convierte a Task
        7. Retorna status (PENDING/RUNNING/COMPLETED/FAILED/CANCELLED/TIMEOUT)

    **Ventajas**:
        - No toca el job_id interno de RQ
        - Funciona con inyección (tests pueden pasar FakeTaskQueue)
        - Centraliza el formato del external_id en un solo lugar
    """

    EXTERNAL_ID_PREFIX: str = ""
    TASK_CATEGORY: Optional[str] = None

    _tq: ITaskQueue

    def __init__(self, task_queue: Optional[ITaskQueue] = None, *args, **kwargs) -> None:
        """Centraliza ``self._tq = task_queue or TaskQueue.get_instance()``,
        repetido antes en cada manager que hereda de este mixin (A10).

        ``*args``/``**kwargs`` se reenvían a ``super().__init__`` para no
        romper cooperación con otras clases base en el MRO (p. ej.
        ``ScanManager(TaskTrackingMixin, ABC)``).
        """
        self._tq: ITaskQueue = task_queue or TaskQueue.get_instance()
        super().__init__(*args, **kwargs)

    def external_id_for(self, entity_id) -> str:
        """Construye el external_id canónico para una entidad.

        Ejemplo (ScanManager con EXTERNAL_ID_PREFIX="themis-scan:"):
            external_id_for(123) → "themis-scan:123"

        Esto se usa como clave para mapear entidades de dominio a RQ jobs.
        """
        return f"{self.EXTERNAL_ID_PREFIX}{entity_id}"

    def find_task(self, entity_id) -> Optional[Task]:
        """Busca la tarea (job) asociada a una entidad de dominio.

        Retorna None si:
            - El job nunca se encoló (no llamó a submit)
            - El job fue eliminado del historial (TTL expirado)
            - El external_id no coincide con el TASK_CATEGORY esperado
        """
        return self._tq.get_task_by_external_id(
            self.external_id_for(entity_id), self.TASK_CATEGORY
        )

    def task_status_of(self, entity_id) -> Optional[str]:
        """Status del job asociado a la entidad (string).

        Retorna: "pending", "running", "completed", "failed", "cancelled", "timeout"
        O None si el job no existe.
        """
        task = self.find_task(entity_id)
        return str(task.status) if task else None

    def task_progress_of(self, entity_id) -> Optional[int]:
        """Progreso (0-100) del job asociado a la entidad.

        Retorna: int 0-100 si el job existe y está corriendo, None en otro caso.
        """
        task = self.find_task(entity_id)
        return task.progress if task else None
