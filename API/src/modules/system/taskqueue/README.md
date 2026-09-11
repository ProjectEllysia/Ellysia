# TaskQueue — referencia de componentes

Cola de trabajos en segundo plano sobre **Redis + RQ**. Los jobs persisten en Redis (sobreviven a
reinicios de la API) y los ejecuta un **proceso worker separado de la API**. Dentro de ese proceso,
cada job ocupa uno de los `max_workers` hilos: es un `SimpleWorker` de RQ, sin `fork`, y
`worker.py` explica por qué.

**Cómo se crea una tarea nueva, cuándo usar la outbox y cuándo `submit()` directo, y qué reglas
cumplen los jobs:** [`CONVENCIONES.md` § 7](../../../../../CONVENCIONES.md#7-trabajo-en-segundo-plano-taskqueue-outbox-y-dispatcher).
Este fichero solo describe las piezas.

## Piezas

| Fichero | Qué contiene |
|---|---|
| `queue.py` | `TaskQueue` (singleton, `get_instance()`), el protocolo `ITaskQueue` que reciben los managers por inyección, `QueueRegistry` (categorías que cada módulo da de alta en su `__init__.py`) y `DEFAULT_QUEUE` |
| `task.py` | dataclass `Task` y enum `TaskStatus`, el único del repositorio |
| `connection.py` | `RedisConnectionFactory` y `ping_redis()` |
| `stores.py` | `ExternalIdStore` (`external_id` ↔ job_id), `CancellationStore` (`taskqueue:cancel:{job_id}`), `HistoryStore` (snapshots de tareas terminadas) y `ProgressStore` (`job.meta["progress"]`) |
| `job_context.py` | `job_context()` / `JobHandle`: progreso, cancelación cooperativa y liberación de la sesión al terminar el job |
| `tracking.py` | `TaskTrackingMixin`: `external_id_for`, `find_task`, `task_status_of`, `task_progress_of` |
| `outbox.py` | modelo `TaskDispatch` (intención de encolar, persistida en la misma transacción que la entidad), `build_dispatch`, `encode_func` / `decode_func` |
| `outbox_repository.py` | `TaskDispatchRepository` |
| `dispatcher.py` | `OutboxDispatcher`: `dispatch(id)` publica una fila; `dispatch_pending()` barre las pendientes |
| `scheduling.py` | `TaskDispatchScheduler`: barrido periódico de la outbox (`outbox_sweep_interval_seconds`) |
| `deadline.py` | `JobDeadlineExceeded` y la política de timeout que el job no puede tragarse |
| `worker.py` | entrada del worker: `python -m src.modules.system.taskqueue.worker` |

## Configuración

En `SecOpsConfig.json` → `infrastructure.taskqueue`, leída con `CR.taskqueue_config()`:

| Clave | Qué controla |
|---|---|
| `max_workers` | hilos del worker; solo se lee al arrancarlo |
| `history_max_items`, `history_ttl_seconds` | tamaño y vida del historial de tareas terminadas |
| `outbox_sweep_interval_seconds` | cada cuánto se reintentan las filas `TaskDispatch` pendientes |

La conexión a Redis sale de `infrastructure.redis` y de las variables de entorno.

## Depuración en Redis

```bash
redis-cli KEYS 'rq:queue:*'                 # colas activas
redis-cli LRANGE 'rq:queue:default' 0 -1    # jobs encolados en una cola
redis-cli HGETALL 'taskqueue:external_ids'  # external_id → job_id
redis-cli HGETALL 'taskqueue:history:snap'  # snapshots del historial
```

Superficie REST de administración: `/system/tasks/*`.
