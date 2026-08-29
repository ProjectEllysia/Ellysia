import logging
import sys

import psutil

from flask_smorest import Blueprint as SmorestBlueprint
from flask import jsonify, request

from src.modules.users.services.permissions import Role
from src.modules.shared._endpoints import limiter, current_actor
from src.modules.shared._exceptions import (
    handle_exceptions,
    IllegalStateError,
    ValidationError,
)
from src.modules.shared.schemas import ErrorSchema
from src.modules.users import require_oauth_token, require_role
from src.modules.system.taskqueue import TaskQueue, Task, TaskStatus
from .schemas import (
    HelloResponseSchema,
    SystemInfoSchema,
    SystemStatusSchema,
    TaskSchema,
    TaskListResponseSchema,
    TaskQueueStatusSchema,
    TaskQueueConfigSchema,
    TaskPaginationQuerySchema,
    LogQuerySchema,
    SystemLogsResponseSchema,
)
from .exceptions import (
    LogNotFoundError,
    LogQueryError,
    LogSnapshotChangedError,
)
from .services import (
    read_logs,
)

import src.modules.system.config_reading as CR


system_blp = SmorestBlueprint(
    "system", __name__,
    description="Estado, configuración y health check del sistema"
)
logger = logging.getLogger(__name__)


@system_blp.get("/say-hello")
@system_blp.response(200, HelloResponseSchema, description="Health check")
@limiter.limit("60 per minute")
def hello():
    """Health check del servicio"""
    logger.info("GET /say-hello")
    return {
        "message": "You did it! You reached an endpoint!",
        "status":  "ok",
        "version": CR.get_app_version(),
    }


@system_blp.get("/info")
@system_blp.response(200, SystemInfoSchema, description="System information")
@system_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@system_blp.alt_response(403, schema=ErrorSchema, description="Insufficient role")
@limiter.limit("60 per minute")
@require_oauth_token
@require_role(minimum_role=Role.ADMIN)
def system_info():
    """Metainformacion de la aplicacion: version, entorno, etc."""
    return {
        "name": "Ellysia",
        "version": CR.get_app_version(),
        "environment": "development" if CR.is_development() else "production",
        "pythonVersion": sys.version,
    }


@system_blp.get("/status")
@system_blp.response(200, SystemStatusSchema, description="System metrics")
@system_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@system_blp.alt_response(403, schema=ErrorSchema, description="Insufficient role")
@limiter.limit("30 per hour; 100 per day")
@require_oauth_token
@require_role(minimum_role=Role.ADMIN)
def status():
    """Métricas en tiempo real del servidor (CPU, memoria, disco)"""
    logger.info("GET /status")

    cpu_percent = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')

    return {
        "cpu": {"percent": cpu_percent},
        "memory": {
            "total": memory.total,
            "available": memory.available,
            "percent": memory.percent,
            "used": memory.used,
            "free": memory.free,
        },
        "disk": {
            "total": disk.total,
            "used": disk.used,
            "free": disk.free,
            "percent": disk.percent,
        },
        "status": "ok",
    }


@system_blp.get("/logs")
@system_blp.arguments(LogQuerySchema, location="query")
@system_blp.response(200, SystemLogsResponseSchema, description="Paginated system log")
@system_blp.alt_response(400, schema=ErrorSchema, description="Invalid log query")
@system_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@system_blp.alt_response(403, schema=ErrorSchema, description="Insufficient role")
@system_blp.alt_response(404, schema=ErrorSchema, description="Log file not found")
@system_blp.alt_response(409, schema=ErrorSchema, description="Log changed during pagination")
@limiter.limit("30 per hour; 100 per day")
@require_oauth_token
@require_role(minimum_role=Role.ADMIN)
def system_logs(query_args):
    """Devuelve una página filtrada del log central de la aplicación."""
    try:
        return read_logs(query_args)
    except LogNotFoundError:
        return jsonify({
            "error": "log_not_found",
            "error_description": "No hay ningún log disponible en este momento.",
        }), 404
    except LogSnapshotChangedError:
        return jsonify({
            "error": "log_changed",
            "error_description": "El log cambió durante la consulta. Inicia una nueva lectura.",
        }), 409
    except LogQueryError as exc:
        return jsonify({
            "error": "invalid_log_query",
            "error_description": str(exc),
        }), 400


@system_blp.get("")
@system_blp.response(200, description="Full SecOps configuration")
@system_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@system_blp.alt_response(403, schema=ErrorSchema, description="Insufficient role")
@limiter.limit("30 per hour; 100 per day")
@require_oauth_token
# S7: root, no admin — expone toda la config, incluida la política anti-SSRF
# (areLocalIpsAllowed) y los parámetros de Argon2.
@require_role(minimum_role=Role.ROOT)
@handle_exceptions(default_exception=IllegalStateError, logger=logger)
def get_config():
    """Obtiene toda la configuración de SecOpsConfig.json"""
    config = CR.get_full_config()
    # C9: ETag de contenido — el cliente debe reenviarlo vía If-Match en el
    # PUT para que el servidor detecte si otra sesión guardó primero.
    return config, 200, {"ETag": CR.get_config_version()}


@system_blp.put("")
@system_blp.response(200, description="Updated configuration")
@system_blp.alt_response(400, schema=ErrorSchema, description="Invalid body")
@system_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@system_blp.alt_response(403, schema=ErrorSchema, description="Insufficient role")
@system_blp.alt_response(409, schema=ErrorSchema, description="Config changed since last read")
@limiter.limit("10 per hour; 20 per day")
@require_oauth_token
# S7: root, no admin — un admin no debería poder bajar general.security.argon2 o
# reactivar areLocalIpsAllowed (reabriría el SSRF cerrado en S1/S2).
@require_role(minimum_role=Role.ROOT)
@handle_exceptions(default_exception=IllegalStateError, logger=logger)
def update_config():
    """Actualiza la configuración de SecOpsConfig.json"""
    if not request.is_json:
        raise ValidationError("Content-Type must be application/json")

    new_config = request.get_json(silent=True)
    if not new_config:
        raise ValidationError("Request body must be JSON")

    # C9: If-Match obligatorio — sin él, dos sesiones root guardando a la
    # vez se pisan sin avisar (last-write-wins silencioso).
    if_match = request.headers.get("If-Match")
    if not if_match:
        raise ValidationError(
            "Falta la cabecera If-Match: recarga la configuración antes de guardar."
        )

    config = CR.save_full_config(new_config, expected_version=if_match)
    logger.info("Configuracion actualizada correctamente | user=%s", current_actor())
    return config, 200, {"ETag": CR.get_config_version()}


# =============================================================================
# TASKQUEUE ENDPOINTS
# =============================================================================


@system_blp.get("/tasks/status")
@system_blp.response(200, TaskQueueStatusSchema, description="Task queue status")
@system_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@system_blp.alt_response(403, schema=ErrorSchema, description="Insufficient role")
@limiter.limit("60 per minute")
@require_oauth_token
@require_role(minimum_role=Role.ADMIN)
def taskqueue_status():
    """Devuelve el estado global de la cola de tareas en segundo plano."""
    return TaskQueue.get_instance().get_status()


@system_blp.get("/tasks")
@system_blp.arguments(TaskPaginationQuerySchema, location="query")
@system_blp.response(200, TaskListResponseSchema, description="Task list")
@system_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@system_blp.alt_response(403, schema=ErrorSchema, description="Insufficient role")
@limiter.limit("60 per minute")
@require_oauth_token
@require_role(minimum_role=Role.ADMIN)
def taskqueue_tasks(query_args):
    """Lista las tareas de la cola con paginacion y filtros opcionales."""
    task_queue = TaskQueue.get_instance()
    category = query_args.get("category")
    status = query_args.get("status")
    page = query_args.get("page", 1)
    per_page = query_args.get("per_page", 20)

    if status == "pending":
        tasks = task_queue.get_pending(category=category)
    elif status == "running":
        tasks = task_queue.get_running(category=category)
    elif status == "history":
        # "history" no es un estado de tarea sino el conjunto de tareas
        # terminadas (completed/failed/cancelled). Devolver el historial entero.
        tasks = task_queue.get_history(category=category)
    elif status is not None:
        # Filtro fino por un estado concreto dentro del historial.
        history = task_queue.get_history(category=category)
        tasks = [history_entry for history_entry in history if history_entry.get("status") == status]
    else:
        pending = task_queue.get_pending(category=category)
        running = task_queue.get_running(category=category)
        history = task_queue.get_history(category=category)
        tasks = pending + running + history

    total_count = len(tasks)
    start = (page - 1) * per_page
    end = start + per_page
    return {"tasks": tasks[start:end], "totalCount": total_count}


@system_blp.get("/tasks/<string:task_id>")
@system_blp.response(200, TaskSchema, description="Task detail")
@system_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@system_blp.alt_response(403, schema=ErrorSchema, description="Insufficient role")
@system_blp.alt_response(404, schema=ErrorSchema, description="Task not found")
@limiter.limit("60 per minute")
@require_oauth_token
@require_role(minimum_role=Role.ADMIN)
def taskqueue_task_detail(task_id):
    """Obtiene el detalle de una tarea especifica por su ID."""
    task = TaskQueue.get_instance().get_task(task_id)
    if task is None:
        return {"error": "not_found", "error_description": "Task not found"}, 404
    return task.to_dict()


@system_blp.post("/tasks/<string:task_id>/cancel")
@system_blp.response(200, TaskSchema, description="Task cancelled")
@system_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@system_blp.alt_response(403, schema=ErrorSchema, description="Insufficient role")
@system_blp.alt_response(404, schema=ErrorSchema, description="Task not found")
@limiter.limit("30 per minute")
@require_oauth_token
@require_role(minimum_role=Role.ADMIN)
def taskqueue_cancel_task(task_id):
    """Cancela una tarea, estando en espera o en ejecucion."""
    task_queue = TaskQueue.get_instance()
    was_cancelled = task_queue.cancel(task_id)
    if not was_cancelled:
        return {"error": "not_found", "error_description": "Task not found or already finished"}, 404
    task = task_queue.get_task(task_id)
    return (task or Task(id=task_id)).to_dict()


@system_blp.put("/tasks/config")
@system_blp.arguments(TaskQueueConfigSchema, location="json")
@system_blp.response(200, TaskQueueStatusSchema, description="Updated task queue config")
@system_blp.alt_response(400, schema=ErrorSchema, description="Invalid body")
@system_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@system_blp.alt_response(403, schema=ErrorSchema, description="Insufficient role")
@limiter.limit("10 per hour; 20 per day")
@require_oauth_token
@require_role(minimum_role=Role.ADMIN)
def taskqueue_update_config(json_data):
    """Modifica el numero maximo de workers de la cola via config.

    NOTA: esto solo afecta a **nuevos** procesos worker. El worker actual sigue
    usando el valor que leyó al arrancar. Para aplicar el cambio hay que
    reiniciar el proceso worker (p. ej. el contenedor `seq-worker` en Docker,
    o `python -m src.modules.system.taskqueue.worker` en desarrollo).
    """
    max_workers = json_data.get("max_workers")
    if not isinstance(max_workers, int) or max_workers < 1:
        raise ValidationError("max_workers must be a positive integer")

    config = CR.get_full_config()
    config.setdefault("infrastructure", {}).setdefault("taskqueue", {})["max_workers"] = max_workers
    CR.save_full_config(config)
    CR.reload()
    TaskQueue._reset_instance()
    return TaskQueue.get_instance().get_status()
