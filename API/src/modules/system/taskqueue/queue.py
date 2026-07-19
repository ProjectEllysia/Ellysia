"""
taskqueue/queue.py
──────────────────
Cola de tareas asincrónica respaldada por RQ + Redis.

**Flujo completo (cómo funciona)**:
    1. Manager: self._tq.submit(func=MyManager.execute_task, category="mi.tarea", ...)
    2. TaskQueue.submit() → enqueue en RQ (Redis) → retorna Task (PENDING)
    3. Worker (proceso separado): escucha colas vía QueueRegistry.names()
    4. Cuando ve un job → Job.fetch() → ejecuta func(args)
    5. Callbacks RQ registran resultado/error en el historial
    6. Manager: self.task_status_of(entity_id) → consulta estado desde Redis
    7. API responde al cliente con status/progreso

**Arquitectura (SRP)**:
    - ``ITaskQueue`` (Protocol): Contrato que los managers usan
    - ``QueueRegistry``: Registro de categorías (OCP: cada módulo registra sus colas)
    - ``TaskQueue``: Fachada que orquesta:
        - ``ExternalIdStore``: mapa external_id → job_id de RQ
        - ``CancellationStore``: bandera "solicitar cancelación"
        - ``HistoryStore``: últimas N tareas (TTL)
        - ``ProgressStore``: progreso (job.meta["progress"])
        - ``RedisConnectionFactory``: conexiones a Redis
    - RQ Job: cola física en Redis

**Relación QueueRegistry vs RQ Queue**:
    - QueueRegistry: lista de NOMBRES ("themis.scan", "aegis.generate", ...)
    - RQ Queue: la cola FÍSICA en Redis con ese nombre
    - Workers: leen QueueRegistry.names() → crean RQ Queue para cada
    - TaskQueue._queue_for(): resuelve category → QueueRegistry.is_registered → RQ Queue

**Ventajas vs SeQueue (anterior)**:
    - Persiste en Redis (sobrevive reinicios)
    - Workers en procesos separados (o threads) → aislados de crashes
    - Escalable (N workers, una sola Redis)
    - FIFO ordering (RQ maneja)
    - Callbacks de RQ para logging/historial
    - Cancelación cooperativa (worker chequea job.cancelled())
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone
from typing import Callable, ClassVar, Dict, List, Optional, Protocol, runtime_checkable

import redis as redis_lib
import rq
from rq import Worker
from rq.job import Callback, Job
from rq.registry import StartedJobRegistry
from rq.worker_registration import clean_worker_registry


logger = logging.getLogger(__name__)

import src.modules.system.config_reading as CR
from src.modules.shared._exceptions import IllegalStateError

from .connection import RedisConnectionFactory
from .stores import (
    CancellationStore,
    ExternalIdStore,
    HistoryStore,
    ProgressStore,
)
from .task import Task, TaskStatus


DEFAULT_QUEUE = "default"
_DEFAULT_TIMEOUT = 600


class QueueRegistry:
    """Registro central de colas (categorías) para la ejecución asincrónica.

    **Propósito (Open/Closed Principle)**:
    Permite que cada módulo (themis, aegis, iris) registre sus propias
    colas sin modificar el código core de TaskQueue. Los workers consultan
    este registro al arrancar para saber cuáles colas escuchar.

    **Flujo de inicialización**:
        1. API arranca (run.py)
        2. Importa los módulos (aegis, iris, themis)
        3. Cada módulo/__init__.py llama QueueRegistry.register("categoría")
        4. Workers arrancan, leen QueueRegistry.names(), crean RQ Queues
        5. Managers submit(category="categoría") → usa la cola registrada

    **Relación con RQ Queue**:
        - QueueRegistry mantiene NOMBRES (strings: "themis.scan", etc)
        - RQ Queue es la cola FÍSICA en Redis con ese nombre
        - Los workers crean una RQ Queue para cada nombre registrado
    """

    _names: set = {DEFAULT_QUEUE}
    _lock = threading.Lock()

    @classmethod
    def register(cls, *names: str) -> None:
        """Registra una o varias categorías de cola.

        Idempotente: llamar dos veces con el mismo nombre no causa duplicados.

        Típicamente llamado desde módulo/__init__.py:
            from src.modules.system.taskqueue import QueueRegistry
            QueueRegistry.register("themis.scan", "themis.report")

        Args:
            *names: Nombres de colas a registrar. Ej: "aegis.generate", "iris.analyze"
        """
        with cls._lock:
            for name in names:
                if name:
                    cls._names.add(name)

    @classmethod
    def names(cls) -> List[str]:
        """Devuelve todos los nombres de cola registrados, ordenados.

        Usado por:
            - Workers (worker.py) para crear RQ Queues que escuchar
            - TaskQueue._queue_for() para resolver la cola de una categoría
            - CLI/admin para listar colas activas
        """
        with cls._lock:
            return sorted(cls._names)

    @classmethod
    def is_registered(cls, name: str) -> bool:
        """Comprueba si una categoría está registrada.

        Si está registrada, el submit usará esa cola específica.
        Si no, cae a "default".
        """
        with cls._lock:
            return name in cls._names

    @classmethod
    def resolve_queue_name(cls, category: str) -> str:
        """Resuelve el nombre de cola para una categoría.

        Si la categoría está registrada, retorna la categoría.
        Si no, retorna "default".

        Usado por TaskQueue._queue_for() para resolver category → nombre RQ.
        """
        return category if cls.is_registered(category) else DEFAULT_QUEUE



# =============================================================================
# CALLBACKS DE RQ (se ejecutan en el worker al terminar el job)
# =============================================================================

def _record_terminal(job: "Job", status: "TaskStatus", error: str | None = None) -> None:
    try:
        tq = TaskQueue.get_instance()
        data = Task.from_rq_job(job).to_dict()
        data["status"] = str(status)
        if error and not data.get("error"):
            data["error"] = error
        if not data.get("finishedAt"):
            data["finishedAt"] = datetime.now(timezone.utc).isoformat()
        tq._history.record(data)
        tq._external.remove_by_job_id(job.id)
    except Exception:  # noqa: BLE001 - un fallo de historial no debe tumbar el job
        logger.warning(
            "No se pudo registrar el historial del job %s",
            getattr(job, "id", "?"), exc_info=True,
        )

def _on_job_success(job, connection, result, *args, **kwargs):
    _record_terminal(job, TaskStatus.COMPLETED)

def _on_job_failure(job, connection, exc_type, exc_value, traceback, *args, **kwargs):
    error = None
    if exc_type is not None:
        error = f"{getattr(exc_type, '__name__', exc_type)}: {exc_value}"
    _record_terminal(job, TaskStatus.FAILED, error=error)

# =============================================================================
# FACHADA
# =============================================================================

@runtime_checkable
class ITaskQueue(Protocol):
    """Contrato para la cola de tareas respaldada por RQ + Redis.

    Permite a los managers encolar trabajos asincronos y consultar su estado
    sin acoplarse a detalles de implementación (RQ/Redis). Los tests inyectan
    una implementación en memoria (FakeTaskQueue) que respeta este contrato.

    Flujo de vida de un trabajo:
        1. Manager llama submit(func=MyManager.execute_task, external_id="...", ...)
        2. Se enqueue en Redis bajo la cola correspondiente
        3. Workers (procesos separados) escuchan las colas y ejecutan los jobs
        4. Manager consulta estado vía get_task_by_external_id() → lee de Redis
        5. Al terminar, callbacks de RQ registran snapshots en el historial
    """

    def submit(
        self,
        func: Callable,
        *,
        name: str = "",
        category: str = "",
        args: tuple = (),
        kwargs: Optional[dict] = None,
        external_id: Optional[str] = None,
        timeout: int = 600,
    ) -> Task:
        """Enqueue un trabajo para ejecución asincrona por los workers.

        Args:
            func: Callable a ejecutar. Típicamente un @staticmethod del manager
                  que construye su instancia y llama al método interno.
                  Ej: func=NmapScanManager.execute_nmap_scan
            name: ID único del job en RQ (opcional). Si se repite, cancela el anterior.
            category: Categoría registrada en QueueRegistry. Si no está registrada,
                     cae a "default". Ej: "themis.scan", "aegis.generate", "iris.analyze"
            args: Argumentos posicionales para func().
            kwargs: Argumentos nombrados para func().
            external_id: ID lógico del dominio (scan_id, document_id, etc).
                        Permite consultar el job sin conocer el job_id de RQ.
                        Formato típico: "themis-scan:123" (prefijo + entidad_id).
            timeout: Segundos antes de que RQ mate el job si sigue corriendo.

        Returns:
            Task: Representación serializable del job encolado (id, status=PENDING, etc).
                  El manager la usa para devolver al cliente (JSON).
        """
        ...

    def cancel(self, task_id: str) -> bool:
        """Solicita cancelación de un job en ejecución.

        - Si está pending (queued): lo cancela inmediatamente y lo elimina.
        - Si está running (started): envía una señal cooperativa (job.cancelled() será True).
        - Si ya terminó: no hace nada (retorna False).

        Retorna True si la cancelación fue viable (pending o running).
        """
        ...

    def get_task(self, task_id: str) -> Optional[Task]:
        """Consulta el estado actual de un job por su job_id de RQ.

        Usado internamente. Para consultas desde el manager, preferir
        get_task_by_external_id() (más natural: buscar por entidad, no por RQ job_id).
        """
        ...

    def get_task_by_external_id(
        self, external_id: str, category: Optional[str] = None
    ) -> Optional[Task]:
        """Consulta un job por su external_id (ID lógico del dominio).

        Flujo:
            1. ExternalIdStore busca el external_id en Redis
            2. Obtiene el job_id de RQ asociado
            3. Fetch del RQ Job desde Redis
            4. Convierte a Task (status, progreso, timestamps)

        Retorna None si no hay job registrado con ese external_id, o si el
        job fue eliminado del historial (mantiene últimos N items por TTL).

        Usado por managers vía TaskTrackingMixin para responder "¿en qué estado
        está mi escaneo/análisis/documento?"
        """
        ...

    def update_progress(self, task_id: str, progress: int) -> None:
        """Actualiza el progreso (0-100) de un job en ejecución.

        Los workers llaman esto vía job.progress(pct) dentro del job_context.
        El progreso se almacena en job.meta["progress"] en Redis.
        """
        ...

    def is_cancelled(self, task_id: str) -> bool:
        """Consulta si se ha solicitado cancelación de este job.

        Los workers llaman esto vía job.cancelled() para decidir si deben
        salir temprano (cancelación cooperativa, no forzada).
        """
        ...

    def clear_cancel_signal(self, task_id: str) -> None:
        """Limpia la bandera de cancelación después de que el job termina.

        Los context managers (job_context) lo llaman al salir para evitar
        que señales viejas interfieran con futuros reintentos.
        """
        ...


def _reject_if_still_running(job_id: str, status: str) -> None:
    """Rechaza el reencolado si ya hay un job "started" con el mismo job_id (C4).

    La cancelación de un job "started" es cooperativa: ``TaskQueue.cancel()``
    solo señaliza y retorna de inmediato, sin esperar a que el worker note la
    bandera y termine. Si ``submit()`` igual reencolara con el mismo job_id,
    durante la ventana en que el job viejo sigue vivo dos ejecuciones lógicas
    compartirían un mismo job_id de RQ (metadata/callbacks/historial
    mezclados). Se rechaza explícitamente en vez de arriesgar esa corrupción
    silenciosa; el caller puede reintentar cuando el job viejo termine.
    """
    if status == "started":
        friendly = (
            f"Ya hay una tarea '{job_id}' en ejecución; espera a que "
            "termine o cancélala antes de reintentar."
        )
        # IllegalStateError autogenera un user_message genérico a partir de
        # expected_state/current_state si no se pasa explícito — sin esto el
        # mensaje legible de arriba nunca llegaría al cliente.
        raise IllegalStateError(
            friendly,
            expected_state="not_started",
            current_state=status,
            user_message=friendly,
        )


class TaskQueue:
    """Singleton fachada de la cola de tareas (RQ + Redis)."""

    _instance: ClassVar[Optional[TaskQueue]] = None
    _instance_lock = threading.Lock()

    def __init__(self) -> None:
        taskqueue_cfg = CR.get_taskqueue_config()

        self._redis = RedisConnectionFactory.raw()
        self._decoded = RedisConnectionFactory.decoded()

        self._external = ExternalIdStore(self._decoded)
        self._cancel = CancellationStore(self._decoded)
        self._history = HistoryStore(
            self._decoded,
            int(taskqueue_cfg.get("history_max_items", 200)),
            int(taskqueue_cfg.get("history_ttl_seconds", 3600)),
        )

        self._queue_cache: Dict[str, rq.Queue] = {}

    # =========================================================================
    # SINGLETON
    # =========================================================================

    @classmethod
    def get_instance(cls) -> TaskQueue:
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    @classmethod
    def _reset_instance(cls) -> None:
        with cls._instance_lock:
            cls._instance = None

    # =========================================================================
    # PUBLIC API
    # =========================================================================

    def submit(
        self,
        func: Callable,
        *,
        name: str = "",
        category: str = "",
        args: tuple = (),
        kwargs: Optional[dict] = None,
        external_id: Optional[str] = None,
        timeout: int = _DEFAULT_TIMEOUT,
    ) -> Task:
        """Enqueue un trabajo para ejecución asincrona en background.

        **Paso a paso**:
            1. Resuelve la cola (category → QueueRegistry.is_registered → RQ Queue)
            2. Si el job_id (name) ya existe en estado activo, lo cancela
            3. Enqueue el job en RQ con callbacks (_on_job_success, _on_job_failure)
            4. Registra el mapeo external_id → job_id en Redis
            5. Retorna un Task (snapshot para el cliente)

        **Retorno inmediato**: No espera a que el job termine, solo lo enqueue.

        **Callbacks de RQ**: Al terminar, ejecutan _on_job_success/_on_job_failure,
        que registran snapshots en el historial (últimas N tareas por TTL).

        **Ejemplo (manager)**:
            self._tq.submit(
                func=NmapScanManager.execute_nmap_scan,
                name=f"scan-{scan_id}",
                category="themis.scan",
                args=(scan_id, target_host, target_ports, timeout),
                external_id=f"themis-scan:{scan_id}",
                timeout=3600
            )
        """

        queue = self._queue_for(category)

        job_id = name if name else None
        if job_id:
            existing = self._try_fetch_job(job_id)
            if existing is not None:
                status = existing.get_status(refresh=True)
                _reject_if_still_running(job_id, status)
                if status == "queued" or status == "scheduled":
                    logger.warning(
                        "Task %s already exists with status %s, cancelling old job",
                        job_id, status,
                    )
                    self.cancel(job_id)
                else:
                    try:
                        existing.delete()
                    except Exception:
                        pass

        try:
            job = queue.enqueue(
                func,
                args=args,
                kwargs=kwargs or {},
                job_id=job_id,
                job_timeout=timeout,
                on_success=Callback(_on_job_success),
                on_failure=Callback(_on_job_failure),
                meta={
                    "category": category,
                    "external_id": external_id,
                    "progress": 0,
                },
            )
        except ValueError as exc:
            logger.error("Failed to submit task %s: %s", name, exc)
            raise

        if external_id:
            self._external.set(external_id, job.id)

        logger.debug(
            "Task %s submitted [category=%s, external=%s]",
            job.id, category, external_id,
        )
        return Task.from_rq_job(job, category=category, external_id=external_id)

    def cancel(self, task_id: str) -> bool:
        """Solicita cancelación de un job en ejecución.

        **Comportamiento según estado**:
            - PENDING (queued/scheduled): Cancela inmediatamente, elimina del job store,
              registra snapshot CANCELLED en historial. Retorna True.
            - RUNNING (started): Envía bandera cooperativa. El worker llama job.cancelled()
              en su loop y sale si es True. Retorna True.
            - TERMINADO (finished/failed): No puede cancelarse. Retorna False.

        **Cancelación cooperativa**: No mata el proceso, solo señaliza. El worker debe
        revisar job.cancelled() periódicamente y salir voluntariamente. Permite cleanup.

        **Limpia automáticamente**: Remueve el mapeo external_id→job_id para que
        futuros get_task_by_external_id no lo encuentren.
        """
        job = self._try_fetch_job(task_id)
        if job is None:
            logger.warning("Task %s not found for cancellation", task_id)
            return False

        status = job.get_status(refresh=True)
        if status is None:
            return False

        if status in ("queued", "scheduled"):
            snapshot = Task.from_rq_job(job).to_dict()
            snapshot["status"] = str(TaskStatus.CANCELLED)
            snapshot["finishedAt"] = datetime.now(timezone.utc).isoformat()
            try:
                job.cancel()
                job.delete()
            except Exception:
                pass
            self._cancel.clear(task_id)
            self._external.remove_by_job_id(task_id)
            self._history.record(snapshot)
            logger.info("Task %s cancelled (was pending)", task_id)
            return True

        if status == "started":
            if self._worker_alive(job.worker_name):
                self._cancel.signal(task_id)
                logger.info("Task %s cancel signal sent (is running)", task_id)
                return True

            logger.warning(
                "Task %s is started but its worker (%s) is gone, force-cancelling",
                task_id, job.worker_name,
            )
            return self._force_cancel_started(job)

        logger.warning("Task %s cannot be cancelled (status=%s)", task_id, status)
        return False

    def cancel_all(self) -> None:
        logger.info("TaskQueue cancel_all")

        for queue_name in QueueRegistry.names():
            queue = self._queue_for(queue_name)
            for job_id in queue.get_job_ids():
                self.cancel(job_id)

            started = StartedJobRegistry(name=queue_name, connection=self._redis)
            for job_id in started.get_job_ids():
                logger.info("Cancelling running job %s", job_id)
                self.cancel(job_id)

    def is_cancelled(self, task_id: str) -> bool:
        return self._cancel.is_cancelled(task_id)

    def clear_cancel_signal(self, task_id: str) -> None:
        self._cancel.clear(task_id)

    def get_task(self, task_id: str) -> Optional[Task]:
        job = self._try_fetch_job(task_id)
        if job is None:
            return None
        return Task.from_rq_job(job)

    def get_task_by_external_id(
        self, external_id: str, category: Optional[str] = None
    ) -> Optional[Task]:
        """Consulta el estado de un job por su ID lógico del dominio.

        **Por qué external_id**: El manager no quiere saber del job_id interno de RQ.
        Solo sabe que encoló un scan (external_id="themis-scan:123") y quiere saber
        su estado sin recordar el job_id de RQ.

        **Flujo**:
            1. ExternalIdStore.get(external_id) → obtiene job_id de RQ
            2. RQ Job.fetch(job_id) desde Redis → obtiene el job
            3. Task.from_rq_job(job) → mapea RQ status a Task status
            4. Retorna Task (id, status, progreso, timestamps, error)

        **Dónde se usa**: TaskTrackingMixin (find_task, task_status_of, task_progress_of)
        llama esto para que managers respondan "¿en qué estado está mi escaneo?"

        **Si retorna None**:
            - No hay mapping external_id→job_id en Redis, o
            - El job fue eliminado del historial (últimas N items por TTL)
        """
        job_id = self._external.get(external_id)
        if job_id is None:
            logger.debug("get_task_by_external_id: no job_id for external_id=%s", external_id)
            return None
        task = self.get_task(job_id)
        if task is None:
            logger.debug(
                "get_task_by_external_id: task not found for job_id=%s (external_id=%s)",
                job_id, external_id,
            )
            return None
        if category is not None and task.category != category:
            logger.debug(
                "get_task_by_external_id: category mismatch (expected=%s, actual=%s)",
                category, task.category,
            )
            return None
        return task

    def get_running(self, category: Optional[str] = None) -> List[dict]:
        all_job_ids = []
        for queue_name in QueueRegistry.names():
            started = StartedJobRegistry(name=queue_name, connection=self._redis)
            all_job_ids.extend(started.get_job_ids())
        tasks = self._jobs_to_tasks(all_job_ids, category)
        return sorted(tasks, key=lambda t: t.get("createdAt") or "")

    def get_pending(self, category: Optional[str] = None) -> List[dict]:
        all_pending_ids = []
        for queue_name in QueueRegistry.names():
            queue = self._queue_for(queue_name)
            started_ids = set(
                StartedJobRegistry(name=queue_name, connection=self._redis).get_job_ids()
            )
            job_ids = queue.get_job_ids()
            pending_ids = [j for j in job_ids if j not in started_ids]
            all_pending_ids.extend(pending_ids)
        tasks = self._jobs_to_tasks(all_pending_ids, category)
        return sorted(tasks, key=lambda t: t.get("createdAt") or "")

    def get_history(self, category: Optional[str] = None) -> List[dict]:
        tasks = self._history.list(category)
        return sorted(
            tasks,
            key=lambda t: t.get("finishedAt") or t.get("startedAt") or t.get("createdAt") or "",
            reverse=True,
        )

    def get_status(self) -> dict:
        running_count = 0
        pending_count = 0
        try:
            for queue_name in QueueRegistry.names():
                queue = self._queue_for(queue_name)
                started = StartedJobRegistry(name=queue_name, connection=self._redis)
                running_count += started.count
                pending_count += queue.count
        except Exception as exc:
            logger.warning("Error reading queue status from Redis: %s", exc)
            running_count = 0
            pending_count = 0

        return {
            "maxWorkers":    CR.get_taskqueue_config().get("max_workers", 4),
            "aliveWorkers":  self._count_alive_workers(),
            "runningCount":  running_count,
            "pendingCount":  pending_count,
            "historyCount":  self._history.count(),
        }

    def update_progress(self, task_id: str, progress: int) -> None:
        if not (0 <= progress <= 100):
            return
        job = self._try_fetch_job(task_id)
        if job is None:
            return
        ProgressStore.write(job, progress)

    # =========================================================================
    # REDIS ACCESS
    # =========================================================================

    @property
    def redis(self) -> redis_lib.Redis:
        return self._redis

    # =========================================================================
    # INTERNAL
    # =========================================================================

    def _queue_for(self, category: str) -> rq.Queue:
        """Obtiene la RQ Queue para una categoría (resolver + cachear).

        **Flujo**:
            1. QueueRegistry.resolve_queue_name(category) → resuelve a nombre
            2. Cachea/fetch la RQ Queue física con ese nombre
            3. Retorna la RQ Queue lista para enqueue

        **Separación de responsabilidades**:
            - QueueRegistry: sabe qué categorías existen (resolve_queue_name)
            - TaskQueue: crea/cachea las RQ Queues físicas (necesita self._redis)

        **Ejemplo**:
            Manager: submit(category="themis.scan")
              ↓
            _queue_for("themis.scan")
              ↓
            resolve_queue_name("themis.scan") → "themis.scan" (está registrada)
              ↓
            Cachea RQ Queue("themis.scan", connection=redis)
              ↓
            queue.enqueue(func, args, ...)
        """
        name = QueueRegistry.resolve_queue_name(category)
        if category and category != DEFAULT_QUEUE and name == DEFAULT_QUEUE:
            # Fallback silencioso = bug invisible: un typo en category= (o un
            # módulo que olvidó QueueRegistry.register(...)) haría correr el job
            # en la cola equivocada sin ningún aviso.
            logger.warning(
                "Categoría de cola '%s' no registrada; el job irá a '%s'. "
                "¿Typo en category= o falta QueueRegistry.register(...)?",
                category, DEFAULT_QUEUE,
            )
        queue = self._queue_cache.get(name)
        if queue is None:
            queue = rq.Queue(name=name, connection=self._redis, default_timeout=_DEFAULT_TIMEOUT)
            self._queue_cache[name] = queue
        return queue

    def _count_alive_workers(self) -> int:
        """Número real de workers vivos registrados en Redis.

        ``rq:workers`` es un *set* que solo se limpia cuando el worker hace un
        shutdown limpio (``register_death``). Si el proceso muere de forma
        abrupta (kill, reload del servidor, etc.) su clave ``rq:worker:<name>``
        puede expirar por TTL pero el nombre sigue en el set, inflando el
        contador ("19/4 workers"). Por eso ``Worker.count`` no es fiable.

        En su lugar se recorre ``Worker.all`` y se cuentan solo los que están
        vivos de verdad (misma comprobación de PID que ``_worker_alive``),
        purgando de paso las entradas muertas del set global → cada lectura de
        estado auto-sanea el registro.
        """
        try:
            for queue_name in QueueRegistry.names():
                clean_worker_registry(self._queue_for(queue_name))
            alive = 0
            for w in Worker.all(connection=self._redis):
                if self._worker_alive(w.name):
                    alive += 1
                else:
                    try:
                        self._redis.srem("rq:workers", w.key)
                    except Exception:
                        pass
            return alive
        except Exception as exc:
            logger.debug("No se pudo contar workers vivos: %s", exc)
            return -1

    def _worker_alive(self, worker_name: Optional[str]) -> bool:
        """Comprueba si el worker que tomó un job sigue vivo de verdad.

        No basta con que exista la clave ``rq:worker:<name>``: cuando un
        worker muere abruptamente (kill -9, crash) sin pasar por
        ``register_death``, su registro queda en Redis con el TTL completo
        (cientos/miles de segundos) aunque el proceso ya no exista. Si solo
        miráramos la clave, una cancelación cooperativa para ese job nunca
        sería leída y el job quedaría "started" para siempre.

        Por eso, si el worker corre en este mismo host (mismo hostname),
        se comprueba además que su PID siga existiendo.
        """
        if not worker_name:
            return False
        try:
            data = self._decoded.hgetall(f"rq:worker:{worker_name}")
        except Exception:
            return False
        if not data:
            return False

        pid = data.get("pid")
        hostname = data.get("hostname")
        if pid and hostname:
            import socket
            import psutil
            if hostname == socket.gethostname():
                try:
                    return psutil.pid_exists(int(pid))
                except (ValueError, TypeError):
                    pass
        return True

    def _force_cancel_started(self, job: Job) -> bool:
        """Cancela un job "started" cuyo worker ya no existe.

        No hay nadie que vaya a leer la señal cooperativa, así que se quita
        directamente del ``StartedJobRegistry``, se borra el job y se registra
        como CANCELLED en el historial.
        """
        task_id = job.id
        snapshot = Task.from_rq_job(job).to_dict()
        snapshot["status"] = str(TaskStatus.CANCELLED)
        snapshot["finishedAt"] = datetime.now(timezone.utc).isoformat()

        try:
            registry = StartedJobRegistry(name=job.origin, connection=self._redis)
            registry.remove(job)
        except Exception:
            pass

        try:
            job.delete()
        except Exception:
            pass

        self._cancel.clear(task_id)
        self._external.remove_by_job_id(task_id)
        self._history.record(snapshot)
        logger.info("Task %s force-cancelled (worker was gone)", task_id)
        return True

    def _try_fetch_job(self, task_id: str) -> Optional[Job]:
        try:
            return rq.job.Job.fetch(task_id, connection=self._redis)
        except rq.exceptions.NoSuchJobError: # type: ignore
            logger.debug("_try_fetch_job: job %s not found in Redis", task_id)
            return None
        except Exception as exc:
            logger.warning("_try_fetch_job: unexpected error for %s: %s", task_id, exc)
            return None

    def _jobs_to_tasks(self, job_ids: List[str], category: Optional[str] = None) -> List[dict]:
        tasks = []
        for jid in job_ids:
            job = self._try_fetch_job(jid)
            if job is None:
                continue
            data = Task.from_rq_job(job).to_dict()
            if category is not None and data.get("category") != category:
                continue
            tasks.append(data)
        return tasks
