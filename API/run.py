"""
run.py — Punto de entrada de la API Ellysia
═══════════════════════════════════════
Responsabilidades de este fiche:
    1. Crear la aplicación Flask.
    2. Configurar CORS y rate limiting.
    3. Registrar los blueprints.
    4. Instalar manejadores de error globales.
    5. Gestionar el apagado graceful.
    6. Arrancar el servidor de desarrollo si se ejecuta directamente.

En producción, Nginx sirve el frontend Vue. En desarrollo, Vite sirve
el frontend con proxy inverso al backend. La API no sirve contenido
estático.
"""

import json
import os
import re
import signal
import logging
import subprocess
import sys
import threading
import time
import warnings

from flask                  import Flask, jsonify, request
from flask_cors             import CORS
from flask_smorest          import Api as FlaskSmorestApi
from sqlalchemy             import create_engine, text
from urllib.parse           import quote_plus

from dotenv                 import load_dotenv

from src.modules.shared     import limiter
from src.modules.infrastructure import unit_of_work
from src.modules.shared._exceptions import (
    MissingParameterError,
    MissingJsonBodyError,
    EllysiaException,
    create_error_response
)
from src.modules.system     import configure_logging, config_reading, system_blp, ping_redis
from src.modules.users      import (
    UserManager,
    oauth_blp,
    users_blp
)
from src.modules.users.services.secrets import hash_password as _hash_password
from src.modules.features.themis   import themis_blp
from src.modules.features.acheron    import acheron_blp
from src.modules.features.aegis      import aegis_blp
from src.modules.features.iris       import iris_blp
from src.modules.features.hygeia     import hygeia_blp

import src.modules.system.config_reading as CR


APP_CONTEXT = CR.get_app_context()
_IS_SHUTTING_DOWN = False
_WORKER = {"proc": None}
# Tope duro de apagado: pase lo que pase con la limpieza (Redis lento, scheduler
# bloqueado, subproceso colgado), el proceso SIEMPRE sale antes de este límite.
_SHUTDOWN_DEADLINE_S = 6

_logger = logging.getLogger(__name__)

warnings.filterwarnings("ignore", message="Multiple schemas resolved to the name")

load_dotenv()  # Carga variables de entorno desde .env (solo en desarrollo)

def _kill_worker_tree() -> None:
    """Mata el subproceso worker y TODOS sus descendientes (nmap, nikto…).

    ``Popen.terminate()`` solo mata el worker; sus subprocesos de escaneo
    quedarían huérfanos. Con ``psutil`` se recorre el árbol completo y nunca se
    bloquea sin límite (``wait_procs`` con timeout).
    """
    proc = _WORKER["proc"]
    if proc is None:
        return
    try:
        import psutil
        try:
            parent = psutil.Process(proc.pid)
        except psutil.NoSuchProcess:
            return
        targets = parent.children(recursive=True) + [parent]
        for p in targets:
            try:
                p.terminate()
            except psutil.NoSuchProcess:
                pass
        _, alive = psutil.wait_procs(targets, timeout=3)
        for p in alive:
            try:
                p.kill()
            except psutil.NoSuchProcess:
                pass
    except Exception as e:
        _logger.warning(f"Error matando el árbol del worker: {e}")
        try:
            proc.kill()
        except Exception:
            pass
    finally:
        _WORKER["proc"] = None


def _run_shutdown_cleanup() -> None:
    """Limpieza de apagado. Se ejecuta en un hilo daemon con deadline.

    Cada paso va aislado en su propio try/except: un fallo o bloqueo de uno no
    impide intentar los siguientes, y el hilo daemon garantiza que el proceso
    pueda salir aunque alguno se quede colgado.
    """
    _logger.info("Deteniendo worker...")
    try:
        _kill_worker_tree()
    except Exception as e:
        _logger.error(f"Error deteniendo worker: {e}")

    try:
        from src.modules.system.taskqueue import TaskQueue
        _logger.info("Cancelando tareas en segundo plano...")
        TaskQueue.get_instance().cancel_all()
        _logger.info("Tareas canceladas.")
    except Exception as e:
        _logger.error(f"Error cancelando tareas: {e}")

    _logger.info("[Shutdown] Deteniendo scheduler...")
    try:
        from src.modules.features.themis.services.scheduling import ThemisScheduler
        ThemisScheduler.stop()
    except Exception as e:
        _logger.error(f"Error deteniendo scheduler: {e}")

    _logger.info("[Shutdown] Deteniendo scheduler de Hygeia...")
    try:
        from src.modules.features.hygeia.services.scheduling import HygeiaScheduler
        HygeiaScheduler.stop()
    except Exception as e:
        _logger.error(f"Error deteniendo scheduler de Hygeia: {e}")

    _logger.info("[Shutdown] Deteniendo scheduler de buzones de Iris...")
    try:
        from src.modules.features.iris.services.mailbox.scheduling import IrisMailboxScheduler
        IrisMailboxScheduler.stop()
    except Exception as e:
        _logger.error(f"Error deteniendo scheduler de buzones de Iris: {e}")

    _logger.info("[Shutdown] Cerrando sesiones de base de datos...")
    try:
        unit_of_work.close_all()
    except Exception as e:
        _logger.error(f"Error cerrando sesiones de BD: {e}")


def _graceful_shutdown(signum, *args) -> None:
    """
    Manejador de señales para shutdown graceful de la aplicación.

    Clave: la limpieza (que puede bloquearse en Redis, el scheduler o un
    subproceso) se ejecuta en un **hilo daemon acotado por un deadline**, de
    modo que el handler NUNCA se queda atascado en una llamada bloqueante. Si lo
    hiciera, el hilo principal dejaría de estar en un punto seguro del bucle de
    bytecode y los CTRL+C siguientes no se procesarían ("CTRL+C no funciona").
    Pase lo que pase, ``os._exit`` se alcanza en <= ``_SHUTDOWN_DEADLINE_S`` s.

    Args:
        signum: Número de señal recibida (SIGTERM o SIGINT).
        *args: Argumentos adicionales (compatibilidad con Werkzeug reloader).
    """
    global _IS_SHUTTING_DOWN

    if _IS_SHUTTING_DOWN:
        # Segundo CTRL+C: salida inmediata sin esperar a la limpieza.
        os._exit(1)

    _IS_SHUTTING_DOWN = True

    sig_name = "SIGTERM" if signum == signal.SIGTERM else "SIGINT"
    _logger.info(f"{sig_name} recibido — iniciando apagado graceful...")

    cleanup = threading.Thread(target=_run_shutdown_cleanup, name="shutdown", daemon=True)
    cleanup.start()
    cleanup.join(timeout=_SHUTDOWN_DEADLINE_S)
    if cleanup.is_alive():
        _logger.warning(
            "Limpieza de apagado excedió %ss — forzando salida.", _SHUTDOWN_DEADLINE_S
        )
    os._exit(0)


def _build_cors(app: Flask) -> None:
    _logger.info("Inicializando CORS...")

    raw     = os.environ.get("ALLOWED_ORIGINS", "http://localhost:5173")
    origins = [o.strip() for o in raw.split(",") if o.strip()]
    if config_reading.is_development():
        origins.append("http://127.0.0.1:5173")
    CORS(app, origins=origins, supports_credentials=True)


def _register_blueprints(app: Flask) -> None:
    _logger.info("Añadiendo endpoints...")
    flask_smorest_api = FlaskSmorestApi(app)
    flask_smorest_api.register_blueprint(system_blp,    url_prefix="/system")
    flask_smorest_api.register_blueprint(oauth_blp,     url_prefix="/oauth")
    flask_smorest_api.register_blueprint(users_blp,     url_prefix="/users")
    flask_smorest_api.register_blueprint(themis_blp,    url_prefix="/themis")
    flask_smorest_api.register_blueprint(acheron_blp,   url_prefix="/acheron")
    flask_smorest_api.register_blueprint(aegis_blp,     url_prefix="/aegis")
    flask_smorest_api.register_blueprint(iris_blp,      url_prefix="/iris")
    flask_smorest_api.register_blueprint(hygeia_blp,    url_prefix="/hygeia")


def _register_error_handlers(app: Flask) -> None:
    """
    Registra manejadores de errores HTTP globales para la aplicación.

    Configura respuestas JSON consistentes para los códigos de estado
    más comunes, incluyendo logging de advertencias para debugging.

    Args:
        app: Instancia de la aplicación Flask.

    Handlers:
        - 404 Not Found: Rutas que no coinciden con ningún blueprint.
        - 405 Method Not Allowed: Métodos HTTP no permitidos.
        - 429 Too Many Requests: Rate limit superado.
        - 500 Internal Server Error: Errores inesperados.
    """
    _logger.info("Registrando manejadores de error globales...")

    @app.errorhandler(404)
    def not_found(error):
        _logger.warning(f"Ruta no encontrada: {request.method} {request.url}")
        return jsonify({
            "error": "not_found",
            "error_description": "La ruta solicitada no existe",
            "path": request.path,
        }), 404

    @app.errorhandler(405)
    def method_not_allowed(error):
        _logger.warning(
            f"Método no permitido: {request.method} {request.url}"
        )
        return jsonify({
            "error": "method_not_allowed",
            "error_description": f"El método {request.method} no está permitido en esta ruta",
            "allowedMethods": list(error.valid_methods) if hasattr(error, "valid_methods") else [],
        }), 405

    @app.errorhandler(429)
    def too_many_requests(error):
        # T4: Flask siempre llama al handler con la excepción como argumento
        # posicional — esta firma sin parámetros nunca se había ejercitado
        # porque el rate limiter estaba desactivado en toda la suite; un 429
        # real en producción habría lanzado TypeError en vez de la respuesta
        # JSON esperada.
        _logger.warning("Rate limit superado: %s", request.remote_addr)
        return jsonify({
            "error": "too_many_requests",
            "error_description": "Has superado el límite de peticiones. Espera un momento e inténtalo de nuevo.",
        }), 429

    @app.errorhandler(EllysiaException)
    def handle_secops_exception(error):
        if error.traceback:
            _logger.error(f"[{error.code.name}] {error.message}\n{error.traceback}")
        else:
            _logger.error(f"[{error.code.name}] {error.message}")
        include_debug = config_reading.is_development()
        err, code = create_error_response(error, include_debug_info=include_debug)
        return jsonify(err), code

    @app.errorhandler(MissingParameterError)
    def handle_missing_parameter(error):
        _logger.warning(f"Parámetro faltante: {error}")
        return jsonify({
            "error": "missing_parameter",
            "error_description": str(error),
        }), 400

    @app.errorhandler(MissingJsonBodyError)
    def handle_missing_json_body(error):
        _logger.warning(f"Body JSON inválido: {error}")
        return jsonify({
            "error": "invalid_json",
            "error_description": str(error),
        }), 400

    @app.errorhandler(500)
    def internal_error(error):
        _logger.error(
            f"Error interno del servidor: {error}",
            exc_info=True
        )
        return jsonify({
            "error": "internal_server_error",
            "error_description": "Ha ocurrido un error inesperado en el servidor.",
        }), 500


def _register_request_audit(app: Flask) -> None:
    """
    Registra la auditoría de acceso de la API.

    Un único par de hooks ``before_request`` / ``after_request`` garantiza que
    TODA petición a cualquier endpoint deje una línea de log con: método, ruta,
    código de estado, usuario que la realizó, IP de origen y duración.

    El usuario se lee de ``request.current_username`` / ``request.current_user_id``,
    que ``@require_oauth_token`` inyecta durante el dispatch de la vista; por eso
    el log se emite en ``after_request`` (cuando esos atributos ya existen) y no
    en ``before_request``. Las peticiones anónimas se registran como ``anonymous``.

    Args:
        app: Instancia de la aplicación Flask.
    """
    _logger.info("Registrando auditoría de peticiones...")
    audit_logger = logging.getLogger("ellysia.audit")

    @app.before_request
    def _audit_start():
        request._audit_start = time.perf_counter()  # type: ignore[attr-defined]

    @app.after_request
    def _audit_access(response):
        # Ignora el preflight CORS y los assets de la documentación OpenAPI.
        if request.method == "OPTIONS" or request.path.startswith("/api-docs"):
            return response

        username = getattr(request, "current_username", None) or "anonymous"
        user_id  = getattr(request, "current_user_id", None)
        start    = getattr(request, "_audit_start", None)
        duration_ms = (time.perf_counter() - start) * 1000 if start else -1.0

        audit_logger.info(
            "%s %s -> %s | user=%s(id=%s) ip=%s %.1fms",
            request.method,
            request.path,
            response.status_code,
            username,
            user_id,
            request.remote_addr,
            duration_ms,
        )
        return response


def _configure_scheduling() -> None:
    from src.modules.features.themis.services.scheduling import ThemisScheduler
    from src.modules.features.hygeia.services.scheduling import HygeiaScheduler
    from src.modules.features.iris.services.mailbox.scheduling import IrisMailboxScheduler

    _logger.info("Reconciliando escaneos huérfanos...")
    try:
        from src.modules.features.themis.managers import ScanManager
        fixed = ScanManager.reconcile_orphaned_scans()
        if fixed:
            _logger.info("Se marcaron %d escaneo(s) huérfano(s) como FAILED", fixed)
    except Exception as e:
        _logger.warning("No se pudo reconciliar escaneos huérfanos: %s", e)

    _logger.info("Reconciliando análisis Iris huérfanos...")
    try:
        from src.modules.features.iris.managers import IrisManager
        fixed_iris = IrisManager.reconcile_orphaned_analyses()
        if fixed_iris:
            _logger.info("Se marcaron %d análisis Iris huérfano(s) como failed", fixed_iris)
    except Exception as e:
        _logger.warning("No se pudo reconciliar análisis Iris huérfanos: %s", e)

    _logger.info("Arrancando scheduler de tareas programadas...")
    ThemisScheduler.start()

    _logger.info("Arrancando scheduler de Hygeia...")
    HygeiaScheduler.start()

    _logger.info("Arrancando scheduler de buzones de Iris...")
    IrisMailboxScheduler.start()


def _run_migrations() -> None:
    """
    Run all pending Alembic migrations against the database.

    Safe to call on every startup: if the schema is already up to date,
    this is a no-op. Replaces the legacy ``Base.metadata.create_all()``
    which could not handle schema evolution (alter column, add table, etc.).

    Only the main API process (``python run.py``) calls this — RQ workers
    and tests pass ``run_migrations=False`` to ``create_app()``.
    """
    import os as _os
    from alembic.config import Config
    from alembic import command

    cfg = Config(_os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "alembic.ini"))
    command.upgrade(cfg, "head")


def _init_db() -> None:
    """
    Inicializa la base de datos completa de Ellysia desde cero.

    Este proceso destructivo elimina cualquier base de datos existente
    y la recrea con la estructura y datos iniciales:

    1. Conexión a PostgreSQL con AUTOCOMMIT.
    2. Eliminación de conexiones activas a la DB.
    3. DROP DATABASE IF EXISTS + CREATE DATABASE.
    4. Aplica migraciones Alembic (crea todas las tablas).
    5. Inserción de usuario root por defecto.
    6. Inserción de temas iniciales de concienciación (Topics).

    Warning:
        Esta función elimina TODOS los datos existentes. Usar solo en
        desarrollo o cuando se requiera un reset completo.

    Raises:
        SQLAlchemy Error: Si falla la conexión o ejecución de SQL.

    Example:
    >>> from run import create_app
    >>> app = create_app(fresh_db_init=True)  # Crea DB limpia
    """
    db_creds = CR.get_db_credentials()

    username = db_creds["username"]
    password = db_creds["password"]
    host = db_creds["host"]
    dbname = db_creds["dbname"]
    dialect = db_creds["dialect"]
    port = db_creds["port"]

    default_db_url = f"{dialect}://{username}:{quote_plus(password)}@{host}:{port}/postgres"
    engine_postgres = create_engine(default_db_url, isolation_level="AUTOCOMMIT")

    _SAFE_IDENTIFIER = re.compile(r'^[A-Za-z0-9_]+$')
    if not _SAFE_IDENTIFIER.match(dbname):
        raise ValueError(f"Nombre de base de datos inválido: {dbname!r}")

    with engine_postgres.connect() as conn:
        conn.execute(
            text(
                "SELECT pg_terminate_backend(pg_stat_activity.pid) "
                "FROM pg_stat_activity "
                "WHERE pg_stat_activity.datname = :dbname "
                "AND pid <> pg_backend_pid();"
            ),
            {"dbname": dbname},
        )

        # DDL identifiers cannot use bind params; dbname is validated above.
        conn.execute(text(f'DROP DATABASE IF EXISTS "{dbname}";'))
        conn.execute(text(f'CREATE DATABASE "{dbname}";'))

    engine_postgres.dispose()

    _run_migrations()

    database_url = f"{dialect}://{username}:{quote_plus(password)}@{host}:{port}/{dbname}"
    engine = create_engine(database_url)

    root_password = "root"
    root_password_hash = _hash_password(root_password)
    with engine.connect() as conn:
        conn.execute(
            text(
                'INSERT INTO "User" '
                "(username, first_name, last_name, password_hash, password_salt, email, created_at, role) "
                "VALUES ('root', 'Gabe', 'Joe', :pwdhash, '', 'gjoe@ellysia.com', CURRENT_DATE, 'role_root');"
            ),
            {"pwdhash": root_password_hash},
        )

        root_attributes = UserManager.get_all_available_attributes()
        for attr in root_attributes:
            conn.execute(
                text('INSERT INTO "UserAttribute" (user_id, attribute_name) VALUES (1, :attr);'),
                {"attr": attr},
            )

        topics_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "resources", "topics_seed.json")
        with open(topics_path, encoding="utf-8") as f:
            topics_by_category = json.load(f)
        topic_titles = [title for titles in topics_by_category.values() for title in titles]
        conn.execute(
            text('INSERT INTO "Topic" (title) VALUES (:title);'),
            [{"title": title} for title in topic_titles],
        )
        conn.commit()

    _logger.warning(
        "=" * 70 + "\n"
        "Usuario root creado:\n"
        "  usuario:    root\n"
        f"  contraseña: {root_password}\n"
        + "=" * 70
    )


def _run_workers() -> None:
    popen_kwargs = {
        "cwd": os.path.dirname(os.path.abspath(__file__)),
        "start_new_session": True,
    }

    command = [sys.executable, "-m", "src.modules.system.taskqueue.worker"]
    _WORKER["proc"] = subprocess.Popen(
        command,
        **popen_kwargs,
    )
    _logger.info("Worker iniciado como subproceso (PID %d)", _WORKER["proc"].pid)


def create_app(fresh_db_init: bool = False, start_scheduler: bool = True, run_migrations: bool = True) -> Flask:
    """
    Factory de la aplicación Flask Ellysia.

    Configura todos los componentes necesarios para servir la API REST.

    Args:
        fresh_db_init: Si ``True``, reinicializa la base de datos completamente
                        (destructivo). Por defecto ``False``.
        start_scheduler: Si ``True``, arranca los schedulers de tareas programadas. Por defecto ``True``
        run_migrations: Si ``True``, aplica migraciones pendientes de Alembic.

    Returns:
        Flask: Aplicación completamente configurada y lista para servir.
    """
    from werkzeug.middleware.proxy_fix import ProxyFix

    configure_logging()

    app = Flask(__name__)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1) # type: ignore

    _logger.info("Inicializando la aplicación Ellysia...")
    _build_cors(app)
    _logger.info("Inicializando rate limiting...")

    storage_uri = os.environ.get("RATELIMIT_STORAGE_URI")
    if not storage_uri:
        redis_cfg = CR.redis_config()
        redis_auth = f":{quote_plus(redis_cfg.password)}@" if redis_cfg.password else ""
        storage_uri = f"redis://{redis_auth}{redis_cfg.host}:{redis_cfg.port}/{redis_cfg.db}"
    app.config["RATELIMIT_STORAGE_URI"] = storage_uri
    limiter.init_app(app)

    _logger.info("Inicializando documentación OpenAPI...")
    app.config["API_TITLE"]             = "Ellysia API"
    app.config["API_VERSION"]           = CR.get_app_version()
    app.config["OPENAPI_VERSION"]       = "3.0.3"
    app.config["OPENAPI_URL_PREFIX"]    = "/api-docs"
    app.config["OPENAPI_SWAGGER_UI_PATH"] = "/swagger"
    app.config["OPENAPI_SWAGGER_UI_URL"] = "https://cdn.jsdelivr.net/npm/swagger-ui-dist/"

    _register_blueprints(app)
    _register_error_handlers(app)
    _register_request_audit(app)

    if fresh_db_init:
        _init_db()
    elif run_migrations:
        _run_migrations()

    _logger.info("Inicializando base de datos...")
    unit_of_work.initialize()
    unit_of_work.warmup()

    _logger.info("Configurando sesión por-request...")
    from src.modules.infrastructure.session import (
        init_request_session,
        shutdown_request_session,
    )

    app.before_request(init_request_session)
    app.teardown_request(shutdown_request_session)

    if start_scheduler:
        _configure_scheduling()

    _logger.info("Verificando conexion a Redis...")
    ping_redis()
    _logger.info("Aplicación Ellysia iniciada correctamente")
    return app



if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Ellysia API server")
    parser.add_argument("--with-worker", action="store_true", help="Start RQ worker as subprocess")
    _args, _ = parser.parse_known_args()

    signal.signal(
        signalnum   = signal.SIGTERM,
        handler     = _graceful_shutdown
    )
    signal.signal(
        signalnum   = signal.SIGINT,
        handler     = _graceful_shutdown
    )

    app = create_app(
        fresh_db_init = APP_CONTEXT.create_database
    )

    if _args.with_worker:
        _run_workers()

    try:
        app.run(
            debug           = APP_CONTEXT.debug,
            host            = APP_CONTEXT.host,
            port            = APP_CONTEXT.port,
            use_reloader    = False
        )
    except KeyboardInterrupt:
        _logger.info("KeyboardInterrupt caught, initiating shutdown...")
        _graceful_shutdown(signal.SIGINT)
