# TaskQueue — Sistema de Tareas Asincrónicas con Redis + RQ

## Visión General

`TaskQueue` es el subsistema de colas de tareas de Ellysia. Coordina la **ejecución asincrónica** de operaciones costosas (análisis, escaneos, generación de documentos) usando **Redis** como backend persistente y **RQ** (Redis Queue) para orquestación. Las tareas sobreviven a reinicios de la API, se monitorean en tiempo real y soportan cancelación cooperativa.

### Características clave
- **Persistencia**: tareas almacenadas en Redis (no se pierden al reiniciar).
- **Progreso**: monitoreo de `%` completado en tiempo real.
- **Cancelación cooperativa**: señales de cancelación que respetan el job en ejecución.
- **Historial**: snapshot de todas las tareas (completadas, fallidas, canceladas).
- **Multiplataforma**: funciona idénticamente en Windows y Linux (sin `fork`).
- **SOLID**: arquitectura desacoplada con inyección de dependencias.

---

## Arquitectura SOLID

El refactor convierte `TaskQueue` en una **fachada delgada** que orquesta colaboradores especializados:

```
TaskQueue (fachada)
├── RedisConnectionFactory      → Una única fuente de conexiones Redis
├── QueueRegistry               → Registro OCP de categorías/colas (sin hardcoding)
├── ExternalIdStore             → Mapa external_id ↔ job_id (SRP)
├── CancellationStore           → Señales de cancelación (SRP)
├── HistoryStore                → Snapshot de tareas finalizadas (SRP)
└── ProgressStore               → Progreso almacenado en job.meta (SRP)
```

**Por qué**:
- **S**RP: cada componente tiene una única responsabilidad.
- **O**CP: los nuevos módulos registran sus colas sin editar el núcleo.
- **L**SP: los colaboradores son intercambiables (importantes en testing).
- **I**SP: `ITaskQueue` protocol define la superficie mínima que necesitan los managers.
- **D**IP: los managers reciben `ITaskQueue` por inyección, no piden el singleton.

---

## Componentes Principales

### 1. RedisConnectionFactory (`connection.py`)
Centraliza la creación de conexiones Redis, evitando duplicación de configuración.

```python
from src.modules.system.taskqueue.connection import RedisConnectionFactory

# Conexión raw (decode_responses=False) para RQ
raw_redis = RedisConnectionFactory.raw()

# Conexión decodificada (decode_responses=True) para leer claves de taskqueue
decoded_redis = RedisConnectionFactory.decoded()
```

### 2. QueueRegistry (`registry.py`)
Registro de colas **registrables por módulo** (adiós a constantes hardcodeadas).

```python
from src.modules.system.taskqueue import QueueRegistry

# En src/modules/iris/__init__.py (al importar el módulo)
QueueRegistry.register("iris.analyze")

# En src/modules/sentinel/__init__.py
QueueRegistry.register("sentinel.scan", "sentinel.report")

# Luego, TaskQueue automáticamente conoce estas colas
registered = QueueRegistry.names()  # ['default', 'iris.analyze', 'sentinel.scan', ...]
```

### 3. ITaskQueue (`interfaces.py`)
**Contrato** que implementa `TaskQueue` y que pueden inyectar los managers. Permite testear sin Redis.

```python
from src.modules.system.taskqueue import ITaskQueue

class MyManager:
    def __init__(self, task_queue: ITaskQueue | None = None):
        self._tq = task_queue or TaskQueue.get_instance()

    def submit_work(self):
        self._tq.submit(func=my_work, external_id="mywork:123")
```

### 4. Stores (`stores.py`)
Cuatro colaboradores especializados:

#### ExternalIdStore
Mapeo bidireccional `external_id ↔ job_id` (clave Redis: `taskqueue:external_ids`).

```python
external_store = ExternalIdStore(redis_conn)
external_store.set("iris-analysis:42", "job-abc123")
job_id = external_store.get("iris-analysis:42")  # "job-abc123"
external_store.remove_by_job_id("job-abc123")
```

#### CancellationStore
Señales de cancelación cooperativa (prefijo `taskqueue:cancel:*`, TTL 1h).

```python
cancel_store = CancellationStore(redis_conn)
cancel_store.signal("job-abc123")       # Marca el job para cancelar
is_cancelled = cancel_store.is_cancelled("job-abc123")  # True
cancel_store.clear("job-abc123")        # Limpia la señal
```

#### HistoryStore
**Snapshots** de tareas finalizadas (zset `taskqueue:history` + hash `taskqueue:history:snap`).

```python
history_store = HistoryStore(redis_conn)
snapshot = {
    "id": "job-abc123",
    "status": "completed",
    "finishedAt": "2026-06-14T10:30:00Z",
    ...
}
history_store.record(snapshot)
tasks = history_store.list(category="iris.analyze")  # Filtra por categoría
```

#### ProgressStore
Lee/escribe el progreso en `job.meta["progress"]`.

```python
ProgressStore.write(job, 75)  # Actualiza a 75%
progress = ProgressStore.read(job)  # Lee el % actual
```

### 5. TaskQueue (`queue.py`)
**Fachada** que orquesta los stores. Interfaz pública que usan los managers y endpoints.

```python
from src.modules.system.taskqueue import TaskQueue

tq = TaskQueue.get_instance()

# Enviar tarea
task = tq.submit(
    func=my_expensive_function,
    args=(arg1, arg2),
    category="iris.analyze",
    external_id="iris-analysis:42",
    timeout=600
)

# Monitorear
task = tq.get_task_by_external_id("iris-analysis:42")
# Cancelar
tq.cancel(task.id)

# Historial
history = tq.get_history(category="iris.analyze")

# Estado general
status = tq.get_status()
# {
#   "maxWorkers": 4,
#   "aliveWorkers": 2,
#   "runningCount": 3,
#   "pendingCount": 5,
#   "historyCount": 42
# }
```

### 6. job_context (`job_context.py`)
**Helper compartido** para funciones ejecutadas dentro del worker. Elimina la duplicación de `_cancel_check` / `_update_progress`.

```python
from src.modules.system.taskqueue import job_context

def execute_my_task(entity_id):
    with job_context() as job:
        # job.progress(pct)     → actualiza el progreso
        # job.cancelled()       → comprueba si se pidió cancelar
        # job.clear_cancel()    → se llama automáticamente al salir

        for i, item in enumerate(items):
            if job.cancelled():
                break
            process(item)
            job.progress((i + 1) * 100 // len(items))
```

### 7. TaskTrackingMixin (`tracking.py`)
**Mixin reutilizable** para managers que respaldan entidades con tareas en segundo plano. Centraliza el patrón de "buscar tarea por `external_id` + leer estado/progreso".

```python
from src.modules.system.taskqueue import TaskTrackingMixin, ITaskQueue

class IrisManager(TaskTrackingMixin):
    EXTERNAL_ID_PREFIX = "iris-analysis:"
    TASK_CATEGORY = "iris.analyze"

    def __init__(self, task_queue: ITaskQueue | None = None):
        self._tq = task_queue or TaskQueue.get_instance()

    def analyze(self, analysis_id):
        self._tq.submit(..., external_id=self.external_id_for(analysis_id))

    def get_status(self, analysis_id):
        return self.task_status_of(analysis_id)  # "pending", "running", "completed", etc.

    def get_progress(self, analysis_id):
        return self.task_progress_of(analysis_id)  # 0-100
```

---

## Cómo Crear una Nueva Tarea

### Paso 1: Definir el entry point en el manager

El punto de entrada que RQ invoca es un `@staticmethod` del propio manager —
no hace falta un módulo `rq_tasks.py` separado. Como `@staticmethod`, RQ lo
serializa por referencia (`modulo.Clase.metodo`) sin necesidad de picklear
ninguna instancia. El staticmethod construye su propia instancia del manager
y delega en un método interno que usa `job_context()` para progreso/cancelación:

```python
from src.modules.system.taskqueue import job_context

class MyAnalysisManager(TaskTrackingMixin):
    @staticmethod
    def execute_my_analysis(analysis_id: int, config: dict) -> None:
        """Entry point enviado a la TaskQueue."""
        MyAnalysisManager()._run_analysis(analysis_id, config)

    def _run_analysis(self, analysis_id: int, config: dict) -> None:
        """Ejecutada en el worker. Usa job_context para progreso/cancelación."""
        with job_context() as job:
            analysis = get_analysis(analysis_id)

            for step_idx, step in enumerate(analysis.steps):
                # Cancelación cooperativa
                if job.cancelled():
                    break

                # Procesar step
                result = process_step(step, config)

                # Actualizar progreso
                progress_pct = (step_idx + 1) * 100 // len(analysis.steps)
                job.progress(progress_pct)

            # Persistir resultado
            analysis.result = result
            analysis.save()
```

### Paso 2: Registrar la categoría de cola

En `src/modules/mymodule/__init__.py` (al importar blueprints):

```python
from src.modules.system.taskqueue import QueueRegistry

# ... otras importaciones ...

# Registrar la cola para esta categoría
QueueRegistry.register("mymodule.analysis")
```

### Paso 3: Crear el manager

En `src/modules/mymodule/managers.py`:

```python
from src.modules.system.taskqueue import (
    ITaskQueue, TaskQueue, TaskTrackingMixin
)

class MyAnalysisManager(TaskTrackingMixin):
    EXTERNAL_ID_PREFIX = "analysis:"
    TASK_CATEGORY = "mymodule.analysis"

    def __init__(self, user: User, task_queue: ITaskQueue | None = None):
        self.user = user
        self._tq = task_queue or TaskQueue.get_instance()

    def start_analysis(self, config: dict) -> int:
        """Lanza un análisis asincrónico y devuelve el ID."""
        # Crear entidad en BD
        analysis = MyAnalysis(user_id=self.user.id, config=config)
        analysis.save()

        # Enviar tarea (referencia directa al staticmethod del manager)
        self._tq.submit(
            func=MyAnalysisManager.execute_my_analysis,
            args=(analysis.id, config),
            name=f"Analysis-{analysis.id}",
            category=self.TASK_CATEGORY,
            external_id=self.external_id_for(analysis.id),
            timeout=1200,
        )

        return analysis.id

    def get_analysis_status(self, analysis_id: int) -> str | None:
        """Estado de la tarea: 'pending', 'running', 'completed', etc."""
        return self.task_status_of(analysis_id)

    def get_analysis_progress(self, analysis_id: int) -> int | None:
        """Progreso 0-100."""
        return self.task_progress_of(analysis_id)

    def cancel_analysis(self, analysis_id: int) -> bool:
        """Solicita la cancelación de la tarea."""
        task = self.find_task(analysis_id)
        if task is None:
            return False
        return self._tq.cancel(task.id)
```

### Paso 4: Exponer en la API

En `src/modules/mymodule/endpoints.py`:

```python
from flask import Blueprint, request, jsonify
from src.modules.mymodule.managers import MyAnalysisManager
from src.modules.users import current_user

bp = Blueprint("mymodule", __name__, url_prefix="/mymodule")

@bp.route("/analysis", methods=["POST"])
def start_analysis():
    config = request.json
    mgr = MyAnalysisManager(current_user())
    analysis_id = mgr.start_analysis(config)
    return jsonify({"analysisId": analysis_id}), 202

@bp.route("/analysis/<int:analysis_id>/status", methods=["GET"])
def get_analysis_status(analysis_id):
    mgr = MyAnalysisManager(current_user())
    status = mgr.get_analysis_status(analysis_id)
    progress = mgr.get_analysis_progress(analysis_id)
    return jsonify({
        "status": status,
        "progress": progress,
    })

@bp.route("/analysis/<int:analysis_id>/cancel", methods=["POST"])
def cancel_analysis(analysis_id):
    mgr = MyAnalysisManager(current_user())
    success = mgr.cancel_analysis(analysis_id)
    return jsonify({"cancelled": success})
```

---

## Ejemplos Prácticos

### Ejemplo 1: Tarea simple sin progreso

```python
class MyManager(TaskTrackingMixin):
    @staticmethod
    def execute_simple_job(param: str) -> None:
        # Sin job_context, porque no necesitamos progreso ni cancelación
        result = expensive_computation(param)
        persist_result(result)

    def start(self, param: str) -> None:
        self._tq.submit(
            func=MyManager.execute_simple_job,
            args=(param,),
            category="mymodule.simple",
        )
```

### Ejemplo 2: Tarea con bucle y progreso

```python
def execute_batch_processing(batch_id: int, items: list):
    with job_context() as job:
        batch = get_batch(batch_id)

        for idx, item in enumerate(items):
            if job.cancelled():
                batch.status = "cancelled"
                batch.save()
                return

            process_item(item)
            job.progress((idx + 1) * 100 // len(items))

        batch.status = "completed"
        batch.save()
```

### Ejemplo 3: Tarea con callback de progreso externo

```python
def execute_scan(scan_id: int, target: str):
    with job_context() as job:
        # Pasar job.progress como callback al scanner
        scanner = MyScanner(
            target=target,
            progress_callback=job.progress,
            cancel_check=job.cancelled,
        )
        result = scanner.run()
        save_result(scan_id, result)
```

### Ejemplo 4: Inyectar una cola fake en tests

```python
# test_mymodule.py
from src.modules.system.taskqueue import ITaskQueue, TaskTrackingMixin
from src.modules.mymodule.managers import MyAnalysisManager

class FakeTaskQueue:
    """Implementación en memoria de ITaskQueue para tests."""
    def __init__(self):
        self.submitted = []

    def submit(self, func, **kwargs):
        self.submitted.append(kwargs)
        from src.modules.system.taskqueue import Task, TaskStatus
        return Task(id="fake-1", status=TaskStatus.PENDING)

    def cancel(self, task_id):
        return True

    def get_task(self, task_id):
        return None

    def get_task_by_external_id(self, external_id, category=None):
        return None

    def update_progress(self, task_id, progress):
        pass

    def is_cancelled(self, task_id):
        return False

    def clear_cancel_signal(self, task_id):
        pass

def test_analysis_manager_inyects_queue():
    fake_queue = FakeTaskQueue()
    user = create_test_user()
    mgr = MyAnalysisManager(user, task_queue=fake_queue)

    analysis_id = mgr.start_analysis({})

    assert len(fake_queue.submitted) == 1
    assert fake_queue.submitted[0]["category"] == "mymodule.analysis"
```

---

## Monitoreo en Tiempo Real

### Estado General

```python
status = TaskQueue.get_instance().get_status()
# {
#   "maxWorkers": 4,              # Config
#   "aliveWorkers": 2,            # Workers activos ahora
#   "runningCount": 3,            # Tareas en ejecución
#   "pendingCount": 5,            # Tareas encoladas
#   "historyCount": 42,           # Tareas completadas/fallidas/canceladas
# }
```

### Historial

```python
tq = TaskQueue.get_instance()

# Todas las tareas finalizadas
all_finished = tq.get_history()

# Solo de una categoría
iris_tasks = tq.get_history(category="iris.analyze")

# Cada entrada es un snapshot con:
# {
#   "id": "job-abc123",
#   "status": "completed",
#   "category": "iris.analyze",
#   "externalId": "iris-analysis:42",
#   "createdAt": "2026-06-14T10:00:00Z",
#   "startedAt": "2026-06-14T10:05:00Z",
#   "finishedAt": "2026-06-14T10:30:00Z",
#   "error": null,
#   ...
# }
```

### Endpoints Públicos

- `GET /system/tasks/status` → Estado general (`maxWorkers`, `aliveWorkers`, conteos).
- `GET /system/tasks/running` → Tareas en ejecución.
- `GET /system/tasks/pending` → Tareas encoladas.
- `GET /system/tasks/history` → Historial.

---

## Debugging

### Inspeccionar la cola en Redis

```bash
# Ver todas las colas activas
redis-cli --raw KEYS 'rq:*' | head -20

# Ver tareas encoladas en la cola 'default'
redis-cli LRANGE 'rq:queue:default' 0 -1

# Ver tareas en ejecución
redis-cli SMEMBERS 'rq:started:default'

# Ver snapshot de historial
redis-cli HGETALL 'taskqueue:history:snap'

# Ver mapeo external_id → job_id
redis-cli HGETALL 'taskqueue:external_ids'
```

### Ver logs del worker

```bash
# En otra terminal, con el worker corriendo:
tail -f API/logs/taskqueue_worker.log

# O si usas la API con worker integrado:
tail -f API/logs/api.log | grep TaskQueue
```

### Simular una cancelación

```python
from src.modules.system.taskqueue import TaskQueue

tq = TaskQueue.get_instance()
# Si hay una tarea corriendo con id "job-abc123":
tq.cancel("job-abc123")
# El job respetará job.cancelled() y parará limpiamente
```

### Limpiar tareas de prueba

```python
# En la shell de Python o un script
from src.modules.system.taskqueue import TaskQueue

tq = TaskQueue.get_instance()

# Cancelar todas las tareas
tq.cancel_all()

# Limpiar el historial manualmente
tq._history._trim()
```

---

## Modelo de Worker (Multiplataforma)

El worker corre en **hilos dentro del mismo proceso**, no en procesos separados con `fork`. Esto es crítico para **Windows**:

```bash
# Arrancar el worker con 4 threads
python -m src.modules.system.taskqueue.worker --workers 4

# O integrado en la API (con --with-worker)
python API/run.py --with-worker
```

**Por qué threads y no fork:**
- `fork()` no existe en Windows; `multiprocessing` en modo `spawn` es lento y proclive a deadlocks.
- Los threads comparten el mismo proceso → una sola app Flask, una sola BD, una sola conexión Redis.
- Funciona idénticamente en Windows y Linux.
- Las tareas pueden usar el contexto Flask (`g`, sesiones, etc.) sin problemas.

---

## Configuración

En `SecOpsConfig.json`:

```json
{
  "general": {
    "taskqueue": {
      "redis": {
        "host": "localhost",
        "port": 6379,
        "db": 0
      },
      "max_workers": 4,
      "history_max_items": 200,
      "history_ttl_seconds": 3600
    }
  }
}
```

---

## Resumen Rápido

| Tarea | Dónde | Cómo |
|-------|-------|------|
| **Crear tarea** | `managers.py` | `@staticmethod` entry point + método interno con `job_context()` |
| **Registrar cola** | `modules/__init__.py` | `QueueRegistry.register("cat.subcat")` |
| **Manager** | `managers.py` | Extiende `TaskTrackingMixin`, inyecta `ITaskQueue` |
| **Enviar** | `manager.submit_*()` | Usa `self._tq.submit(...)` |
| **Monitorear** | API/tests | Lee `task_status_of()`, `task_progress_of()` |
| **Cancelar** | `manager.cancel_*()` | Usa `self.find_task()` + `self._tq.cancel()` |

---

## Recursos Adicionales

- **`interfaces.py`** — Contrato `ITaskQueue`.
- **`stores.py`** — Implementaciones de almacenamiento.
- **`job_context.py`** — Helper de jobs.
- **`tracking.py`** — Mixin para managers.
- **Tests** — `API/tests/test_taskqueue.py` (ejemplos sin Redis).

---

**Última actualización**: 2026-06-14
**Versión**: RQ 2.9.1 + Redis (compatible con Windows y Linux)
