"""
config_reading.py
Módulo de lectura de configuración SecOps.
Carga lazy (solo al primer acceso) desde SecOpsConfig.json o variables de entorno.
"""

import json
import logging
import os

from enum import Enum
from functools import wraps
from pathlib import Path
from dotenv import load_dotenv
from dataclasses import dataclass

from typing import Optional

from src.modules.shared._exceptions import IllegalStateError

load_dotenv()

logger = logging.getLogger(__name__)

# =============================================================================
# ESTADO DEL MÓDULO
# =============================================================================

_configs: dict | None = None
_configs_path: Path | None = None

# =============================================================================
# ENUMERACIONES ÚTILES
# =============================================================================

class DirectoryType(Enum):
    """Enumeración de tipos de directorios disponibles"""
    TEMP               = "tempdir"
    LOG                = "logdir"

    STACK_AEGIS        = "aegis.stack"
    OUTPUT_AEGIS       = "aegis.output"

    OUTPUT_THEMIS    = "themis.output"
    CSV_THEMIS       = "themis.csv"
    RESOURCES_THEMIS = "themis.resources"

    OUTPUT_IRIS        = "iris.output"


# =============================================================================
# CLASES ÚTILES
# =============================================================================

@dataclass(frozen=True)
class AppContext():
    shutdown_time: int
    create_database: bool
    debug: bool
    host: str
    port: int


# =============================================================================
# DECORADOR LAZY LOAD
# =============================================================================

def _lazy_load(func):
    """Decorador que carga la configuración antes de ejecutar la función."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        global _configs, _configs_path
        if _configs is None:
            if _configs_path is None:
                this_file = Path(__file__).resolve()
                candidates = (
                    parent / name
                    for parent in reversed(this_file.parents[:4])
                    for name in ("SecOpsConfig.json", "SecConfig.json")
                )
                _configs_path = next((c for c in candidates if c.exists()), None)
                if _configs_path is None:
                    raise FileNotFoundError("No se encontró ningún archivo de configuración.")
            with open(_configs_path, "r", encoding="utf-8") as f:
                _configs = json.load(f)
        return func(*args, **kwargs)
    return wrapper


# =============================================================================
# UTILIDADES
# =============================================================================

def reload() -> None:
    """Fuerza la recarga de la configuración desde el archivo."""
    global _configs, _configs_path
    _configs = None
    _configs_path = None


def _require_configs() -> dict:
    """Devuelve la configuración cargada o lanza si aún no lo está.

    Centraliza el guard ``_configs is None`` que comparten los getters, de modo
    que cada uno se reduzca a una sola línea de lectura.
    """
    if _configs is None:
        raise IllegalStateError("'_configs' detectado como nulo")
    return _configs


def _cfg(path: str, default=None, cast=None):
    """Lee un valor anidado de la config por ruta con puntos.

    ``_cfg("themis.traceroute.cacheHours", 24, float)`` es el equivalente de
    ``_require_configs().get("themis", {}).get("traceroute", {}).get("cacheHours", 24)``
    convertido a ``float``. Requiere llamarse desde una función decorada con
    ``@_lazy_load`` (o después de que la config ya esté cargada).
    """
    node = _require_configs()
    for key in path.split("."):
        if not isinstance(node, dict) or key not in node:
            return default
        node = node[key]
    return cast(node) if cast else node


# =============================================================================
# CONFIGURACIÓN DE ENTORNO
# =============================================================================

def get_ollama_environment() -> tuple[str, str]:
    """Solo variables de entorno."""
    host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
    model = os.getenv("OLLAMA_MODEL", "llama3.2")
    return host, model


def get_openai_environment() -> dict[str, str]:
    """Credenciales de OpenAI desde variables de entorno.

    Returns:
        dict con 'api_key', 'model' y 'base_url' (este último opcional, "").

    Raises:
        ValueError: Si falta OPENAI_API_KEY.
    """
    api_key = os.getenv("OPENAI_API_KEY")
    model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    base_url = os.getenv("OPENAI_BASE_URL", "")

    if not api_key:
        logger.error("Falta la variable de entorno OPENAI_API_KEY")
        raise ValueError(
            "Falta la variable de entorno OPENAI_API_KEY. "
            "Defínela en el archivo .env junto a las credenciales de Ollama."
        )

    return {"api_key": api_key, "model": model, "base_url": base_url}


def get_google_environment() -> dict[str, str]:
    """Credenciales de Google Gemini desde variables de entorno.

    Returns:
        dict con 'api_key' y 'model'.

    Raises:
        ValueError: Si falta GOOGLE_API_KEY.
    """
    api_key = os.getenv("GOOGLE_API_KEY")
    model = os.getenv("GOOGLE_MODEL", "gemini-2.0-flash")

    if not api_key:
        logger.error("Falta la variable de entorno GOOGLE_API_KEY")
        raise ValueError(
            "Falta la variable de entorno GOOGLE_API_KEY. "
            "Defínela en el archivo .env junto a las credenciales de OpenAI."
        )

    return {"api_key": api_key, "model": model}


_ALLOWED_JWT_ALGORITHMS = frozenset({"HS256", "HS384", "HS512"})


@_lazy_load
def get_oauth_config() -> tuple[float, float, Optional[str], Optional[str]]:
    """Configuración OAuth/JWT.

    El secreto (``JWT_SECRET_KEY``) vive exclusivamente en .env.
    ``algorithm``, ``access_token_expiry_minutes`` y
    ``refresh_token_expiry_days`` provienen de ``security.jwt`` en
    SecOpsConfig.json; las env vars ``JWT_ALGORITHM``,
    ``ACCESS_TOKEN_EXPIRY_MINUTES`` y ``REFRESH_TOKEN_EXPIRY_DAYS``
    sobreescriben la config si están presentes (override útil para
    contenedores / 12-factor).
    """
    secret = os.getenv("JWT_SECRET_KEY")
    if not secret:
        logger.error("Falta la variable de entorno JWT_SECRET_KEY")
        raise ValueError(
            "Falta la variable de entorno JWT_SECRET_KEY. "
            "Defínela en el archivo .env (es un secreto, no va en "
            "SecOpsConfig.json)."
        )

    jwt_cfg = _require_configs().get("security", {}).get("jwt", {})
    algorithm = os.getenv("JWT_ALGORITHM") or str(jwt_cfg.get("algorithm", "HS256"))
    # S8: JWT_ALGORITHM es override por entorno sin validar — un typo o un
    # despliegue mal configurado con "none" (o un algoritmo asimétrico que
    # necesita un par de claves, no un secreto simétrico) rompería la
    # verificación de tokens en producción. Firmamos con un único secreto
    # simétrico, así que solo la familia HS* tiene sentido aquí.
    if algorithm not in _ALLOWED_JWT_ALGORITHMS:
        raise ValueError(
            f"JWT_ALGORITHM '{algorithm}' no permitido. "
            f"Debe ser uno de: {', '.join(sorted(_ALLOWED_JWT_ALGORITHMS))}."
        )
    access    = os.getenv("ACCESS_TOKEN_EXPIRY_MINUTES") or jwt_cfg.get("access_token_expiry_minutes", 30)
    refresh   = os.getenv("REFRESH_TOKEN_EXPIRY_DAYS") or jwt_cfg.get("refresh_token_expiry_days", 7)

    return (float(access), float(refresh), secret, algorithm)


@_lazy_load
def get_mfa_config() -> dict:
    """Configuración de MFA (TOTP + códigos de recuperación).

    ``MFA_ENCRYPTION_KEY`` (clave Fernet para cifrar en reposo el secreto TOTP)
    vive exclusivamente en .env, igual que ``JWT_SECRET_KEY`` — a diferencia del
    resto de secretos de Acheron, el servidor SÍ necesita poder leer este valor
    para poder calcular el código TOTP vigente y verificarlo. El resto de
    parámetros provienen de ``security.mfa`` en SecOpsConfig.json.
    """
    encryption_key = os.getenv("MFA_ENCRYPTION_KEY")
    if not encryption_key:
        logger.error("Falta la variable de entorno MFA_ENCRYPTION_KEY")
        raise ValueError(
            "Falta la variable de entorno MFA_ENCRYPTION_KEY. "
            "Defínela en el archivo .env (clave Fernet: "
            "python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\")."
        )

    mfa_cfg = _require_configs().get("security", {}).get("mfa", {})
    return {
        "encryption_key": encryption_key,
        "issuer": str(mfa_cfg.get("issuer", "Ellysia")),
        "challenge_expiry_minutes": int(mfa_cfg.get("challenge_expiry_minutes", 5)),
        "max_challenge_attempts": int(mfa_cfg.get("max_challenge_attempts", 5)),
        "recovery_codes_count": int(mfa_cfg.get("recovery_codes_count", 10)),
    }


def get_openvas_environment() -> dict[str, str]:
    """Solo variables de entorno."""
    hostname    = os.getenv("OPENVAS_HOST")
    port        = os.getenv("OPENVAS_PORT")
    user        = os.getenv("OPENVAS_USERNAME")
    password    = os.getenv("OPENVAS_PASSWORD")

    if all([hostname, port, user, password]):
        return {
            "hostname": hostname,
            "port": port,
            "username": user,
            "password": password
        } # type: ignore

    raise ValueError("Faltan variables de entorno para OpenVAS. "
                "Asegúrate de definir OPENVAS_HOST, OPENVAS_PORT, "
                "OPENVAS_USERNAME y OPENVAS_PASSWORD.")


def _as_bool(value: str | bool | None, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes")


def get_app_context() -> AppContext:
    shutdown_time   = os.getenv("SHUTDOWN_TIMEOUT", "30")
    create_database = os.getenv("CREATE_DATABASE", "false")
    debug           = os.getenv("DEBUG", "false")
    host            = os.getenv("HOST", "0.0.0.0")
    port            = os.getenv("PORT", "5000")

    return AppContext(
        shutdown_time   = int(shutdown_time),
        create_database = _as_bool(create_database),
        debug           = _as_bool(debug),
        host            = host,
        port            = int(port),
    )

# =============================================================================
# CONFIGURACIÓN DE BASE DE DATOS
# =============================================================================

def get_db_credentials() -> dict:
    """Devuelve credenciales de BD desde variables de entorno (.env).

    Todas las credenciales son secretos y viven exclusivamente en .env:
    POSTGRES_USER, POSTGRES_PASSWORD, POSTGRES_HOST, POSTGRES_DB, POSTGRES_PORT,
    POSTGRES_DIALECT.
    """
    user     = os.getenv("POSTGRES_USER")
    password = os.getenv("POSTGRES_PASSWORD")
    host     = os.getenv("POSTGRES_HOST", "postgres")
    database = os.getenv("POSTGRES_DB")
    port     = os.getenv("POSTGRES_PORT", "5432")
    dialect  = os.getenv("POSTGRES_DIALECT", "postgresql+psycopg2")

    if not all([user, password, database]):
        raise EnvironmentError(
            "Variables de entorno requeridas no encontradas: "
            "POSTGRES_USER, POSTGRES_PASSWORD, POSTGRES_DB"
        )

    return {
        "dialect":  dialect,
        "username": user,
        "password": password,
        "host":     host,
        "port":     port,
        "dbname":   database,
    }


# =============================================================================
# CONFIGURACIÓN DE DIRECTORIOS
# =============================================================================

def verify_directory(directory: DirectoryType) -> Path:
    dir_name = get_directory_of(directory)
    dir_path = Path(dir_name).resolve()
    dir_path.mkdir(parents=True, exist_ok=True)

    return dir_path

_DIRECTORY_ENV_MAPPING = {
    "tempdir": "TEMP_DIR",
    "logdir": "LOG_DIR",
    "output": "OUTPUT_DIR",
    "stack": "OUTPUT_DIR",
    "themis.csv": "CSV_THEMIS_DIR",
}


def _normalize_dir_key(directory_type) -> str:
    """Acepta un ``DirectoryType`` (enum) o un string y devuelve la clave plana."""
    return directory_type.value if hasattr(directory_type, "value") else directory_type


def _env_override_for(dir_key: str) -> Optional[str]:
    """Devuelve el valor de la variable de entorno que sobreescribe ``dir_key``, si existe."""
    env_var = _DIRECTORY_ENV_MAPPING.get(dir_key)
    if env_var:
        return os.getenv(env_var) or None
    return None


def _lookup_raw_path(cfg: dict, dir_key: str) -> str:
    """Resuelve la ruta cruda en la config: rama anidada ``module.subkey`` o plana ``general``."""
    if "." in dir_key:
        module_key, sub_key = dir_key.split(".")
        if module_key not in cfg:
            raise ValueError(f"Módulo '{module_key}' no encontrado en la configuración.")
        module_config = cfg[module_key]
        if "directories" not in module_config:
            raise ValueError(f"Directorio '{dir_key}' no encontrado en la configuración.")
        directories = module_config["directories"]
        if sub_key not in directories:
            raise ValueError(f"Directorio '{sub_key}' no encontrado en la configuración.")
        return directories[sub_key]

    if dir_key not in cfg.get("general", {}).get("directories", {}):
        raise ValueError(f"Directorio '{dir_key}' no encontrado en la configuración.")
    return cfg["general"]["directories"][dir_key]


def _to_absolute(raw_path: str) -> str:
    """Convierte una ruta relativa en absoluta respecto al raíz de la app."""
    path = Path(raw_path)
    if not path.is_absolute():
        app_root = Path(__file__).resolve().parent.parent.parent
        path = app_root / path
    return str(path)


@_lazy_load
def get_directory_of(directory_type) -> str:
    dir_key = _normalize_dir_key(directory_type)

    override = _env_override_for(dir_key)
    if override:
        return override

    raw_path = _lookup_raw_path(_require_configs(), dir_key)
    return _to_absolute(raw_path)


# =============================================================================
# CONFIGURACIÓN DE AEGIS
# =============================================================================

@_lazy_load
def get_aegis_config() -> dict:
    return _cfg("aegis", {})

@_lazy_load
def get_aegis_tips_amount() -> int:
    return _cfg("aegis.tipsAmount", 7, int)

@_lazy_load
def get_aegis_vulnerabilities_antiquity() -> int:
    return _cfg("aegis.vulnerabilitiesAntiquity", 5, int)

@_lazy_load
def get_aegis_brands() -> list[dict]:
    return _cfg("aegis.brands", [], list)

@_lazy_load
def get_aegis_prompts() -> dict:
    return _cfg("aegis.prompts", {})


# =============================================================================
# CONFIGURACIÓN DE IA (scribe)
# =============================================================================

@_lazy_load
def get_ai_config() -> dict:
    """Devuelve el bloque 'ai' de SecOpsConfig.json (puede estar vacío)."""
    return _cfg("ai", {})


@_lazy_load
def get_ai_strategy_for(module: str | None = None) -> str:
    """Resuelve la estrategia de IA para un módulo.

    Busca primero un override por módulo en ``ai.modules.<module>`` y, si no
    existe, devuelve ``ai.defaultStrategy`` (o 'ollama' como último recurso).

    Args:
        module: Nombre del módulo consumidor ('aegis', 'themis', …).

    Returns:
        Nombre de la estrategia ('ollama' | 'openai' | …).
    """
    ai_cfg = get_ai_config()
    default = ai_cfg.get("defaultStrategy", "ollama")
    if module:
        return ai_cfg.get("modules", {}).get(module, default)
    return default


# =============================================================================
# CONFIGURACIÓN DE CORREO (herald)
# =============================================================================

@_lazy_load
def get_email_config() -> dict:
    """Devuelve el bloque 'email' de SecOpsConfig.json (puede estar vacío)."""
    return _cfg("email", {})


@_lazy_load
def get_email_strategy_for(module: str | None = None) -> str:
    """Resuelve la estrategia de correo para un módulo.

    Busca primero un override por módulo en ``email.modules.<module>`` y, si
    no existe, devuelve ``email.defaultStrategy`` (o 'smtp' como último
    recurso). Espejo de ``get_ai_strategy_for``.

    Args:
        module: Nombre del módulo consumidor ('aegis', …).

    Returns:
        Nombre de la estrategia ('smtp' | …).
    """
    email_cfg = get_email_config()
    default = email_cfg.get("defaultStrategy", "smtp")
    if module:
        return email_cfg.get("modules", {}).get(module, default)
    return default


def get_smtp_environment() -> dict[str, str]:
    """Credenciales SMTP desde variables de entorno.

    Returns:
        dict con 'username' y 'password'.

    Raises:
        ValueError: Si falta alguna de las dos.
    """
    username = os.getenv("SMTP_USERNAME")
    password = os.getenv("SMTP_PASSWORD")

    if not username or not password:
        raise ValueError(
            "Faltan las variables de entorno SMTP_USERNAME / SMTP_PASSWORD. "
            "Defínelas en el archivo .env junto a las demás credenciales."
        )

    return {"username": username, "password": password}


# =============================================================================
# CONFIGURACIÓN DE THEMIS
# =============================================================================

@_lazy_load
def get_themis_config() -> dict:
    return _cfg("themis", {})

@_lazy_load
def get_prompts_config() -> dict:
    themis = _require_configs().get("themis", {})

    return {
        "nmap": themis.get("nmap", {}).get("prompts", {}),
        "nikto": themis.get("nikto", {}).get("prompts", {}),
        "openvas": themis.get("openvas", {}).get("prompts", {}),
        "lybra": themis.get("lybra", {}).get("prompts", {}),
    }

@_lazy_load
def get_tool_prompts(tool: str) -> dict:
    prompts = get_prompts_config()
    return prompts.get(tool, {})

@_lazy_load
def get_tool_color_palette(tool) -> dict:
    themis = _require_configs().get("themis", {})

    # Accepts a ThemisTool enum member or a plain string; without this, a
    # dict lookup with an Enum instance against string keys always misses
    # and silently returns {} (bug: every caller has been getting the
    # hardcoded per-strategy fallback colors instead of SecOpsConfig's).
    tool_key = tool.value if hasattr(tool, "value") else tool
    if tool_key not in themis:
        return {}

    tool_config = themis[tool_key]
    return tool_config.get("colorPalette", {})

@_lazy_load
def are_local_ips_allowed() -> bool:
    return _as_bool(_cfg("themis.areLocalIpsAllowed", False))

@_lazy_load
def get_openvas_scan_configs() -> dict[str, str]:
    configs = get_themis_config()
    return configs["openvas"]["toolConfigs"]["scanConfigs"]

@_lazy_load
def get_openvas_port_list() -> dict[str, str]:
    configs = get_themis_config()
    return configs["openvas"]["toolConfigs"]["portList"]

@_lazy_load
def is_host_reachability_check_enabled() -> bool:
    return _as_bool(_cfg("themis.hostReachabilityCheck.enabled", True))

@_lazy_load
def get_host_reachability_check_timeout() -> float:
    return _cfg("themis.hostReachabilityCheck.timeout", 3.0, float)

@_lazy_load
def get_host_reachability_check_port() -> int:
    return _cfg("themis.hostReachabilityCheck.port", 80, int)

@_lazy_load
def get_themis_csv_dir() -> str:
    return get_directory_of(DirectoryType.CSV_THEMIS)


# --- Lybra knowledge base (local NVD/KEV/EPSS mirror) ---

@_lazy_load
def is_kb_sync_enabled() -> bool:
    return _as_bool(_cfg("themis.kb.enabled", False))

@_lazy_load
def get_kb_sources() -> dict:
    return _cfg("themis.kb.sources", {})

@_lazy_load
def get_kb_sync_cron() -> str:
    return _cfg("themis.kb.syncCron", "0 3 * * *")

@_lazy_load
def get_kb_nvd_window_days() -> int:
    return _cfg("themis.kb.nvdWindowDays", 8, int)

@_lazy_load
def get_kb_nvd_api_key():
    # Secret → prefer the environment, per the config convention.
    import os
    return os.environ.get("NVD_API_KEY") or (_cfg("themis.kb.nvdApiKey", "") or None)


# --- Lybra active detection checks (Fase R) ---

@_lazy_load
def is_lybra_active_checks_enabled() -> bool:
    # Global switch, on by default: active checks touch the target, but the
    # per-user authorized-targets register (roadmap §6, AuthorizedTargetManager)
    # is the real gate — LybraEngineManager only runs these against a target the
    # caller has explicitly authorized, regardless of this flag. This exists as
    # an operator-level kill switch to disable the whole feature deployment-wide.
    return _as_bool(_cfg("themis.lybra.activeChecks", True))


# --- Lybra own fingerprinting (Fase F) ---

@_lazy_load
def is_lybra_fingerprinting_enabled() -> bool:
    # Same story as active checks: on by default now that the authorized-targets
    # register (roadmap §6) gates it per-target; this flag is just the
    # operator-level kill switch.
    return _as_bool(_cfg("themis.lybra.fingerprintingEnabled", True))


@_lazy_load
def get_themis_default_folder_name() -> str:
    """Devuelve el nombre mostrado para la carpeta virtual de escaneos sueltos."""
    return _cfg("themis.folders.defaultFolderName", "Sin carpeta")


@_lazy_load
def get_themis_history_size() -> int:
    """Número de escaneos recientes a considerar en las estadísticas históricas."""
    return _cfg("themis.history.maxScans", 5, int)


@_lazy_load
def get_themis_traceroute_cache_hours() -> float:
    """Horas que una ruta cacheada se considera válida antes de recalcularse."""
    return _cfg("themis.traceroute.cacheHours", 24, float)


@_lazy_load
def get_themis_traceroute_max_hops() -> int:
    """Número máximo de saltos a sondear (``-m`` en traceroute)."""
    return _cfg("themis.traceroute.maxHops", 30, int)


@_lazy_load
def get_themis_traceroute_timeout() -> float:
    """Tiempo máximo total (segundos) para el comando traceroute."""
    return _cfg("themis.traceroute.timeout", 60, float)


@_lazy_load
def get_themis_traceroute_retry_failed_minutes() -> float:
    """Minutos que una ruta fallida (sin saltos) se cachea antes de reintentar.

    Mucho más corto que ``cacheHours``: evita re-sondear un host inalcanzable en
    cada apertura del detalle, pero permite reintentar pronto (o de inmediato con
    el botón de refresco)."""
    return _cfg("themis.traceroute.retryFailedMinutes", 15, float)


# =============================================================================
# CONFIGURACIÓN COMPLETA (GET/SET)
# =============================================================================

@_lazy_load
def get_full_config() -> dict:
    """Devuelve toda la configuración."""
    return _require_configs().copy()

def save_full_config(new_config: dict) -> dict:
    """Guarda la configuración completa."""
    global _configs
    if _configs_path is None:
        raise FileNotFoundError("No se encontró ningún archivo de configuración.")
    with open(_configs_path, "w", encoding="utf-8") as f:
        json.dump(new_config, f, indent=2, ensure_ascii=False)
    _configs = new_config
    return new_config


# =============================================================================
# CONFIGURACIÓN DE TASKQUEUE
# =============================================================================

@_lazy_load
def get_redis_config() -> dict:
    """Devuelve la configuración de conexión Redis.

    Valores no secretos (host, port, db, socket_connect_timeout) provienen de
    SecOpsConfig.json. El password (secreto) proviene de la variable de entorno
    REDIS_PASSWORD. Las env vars REDIS_HOST/PORT/DB sobreescriben la config si
    están presentes (útil en contenedores).
    """
    cfg = _cfg("redis", {})
    host    = os.getenv("REDIS_HOST", str(cfg.get("host", "localhost")))
    port    = int(os.getenv("REDIS_PORT", str(cfg.get("port", 6379))))
    db      = int(os.getenv("REDIS_DB",   str(cfg.get("db", 0))))
    timeout = int(cfg.get("socket_connect_timeout", 2))
    password = os.getenv("REDIS_PASSWORD", "")

    return {
        "host":                  host,
        "port":                  port,
        "db":                    db,
        "socket_connect_timeout": timeout,
        "password":              password or None,
    }

@_lazy_load
def get_taskqueue_config() -> dict:
    cfg = _cfg("general.taskqueue", {})
    max_workers_env = os.getenv("TASKQUEUE_MAX_WORKERS")
    if max_workers_env is not None:
        cfg["max_workers"] = int(max_workers_env)

    return cfg


@_lazy_load
def get_public_web_url() -> str:
    """Base URL pública del frontend (SPA), usada para construir enlaces
    en emails salientes (p. ej. el enlace del quiz de una campaña Aegis).

    ``PUBLIC_WEB_URL`` en .env tiene prioridad sobre ``general.publicUrl``
    en SecOpsConfig.json; sin ninguno de los dos, cae al valor de desarrollo
    de Vite. Sin barra final.
    """
    env_override = os.getenv("PUBLIC_WEB_URL")
    if env_override:
        return env_override.rstrip("/")

    return _cfg("general.publicUrl", "http://localhost:5173", str).rstrip("/")

# =============================================================================
# CONFIGURACIÓN DE IRIS
# =============================================================================

@_lazy_load
def get_iris_config() -> dict:
    return _cfg("iris", {})

@_lazy_load
def get_iris_legitimate_threshold() -> float:
    # 0–100 subtractive scale: >= 80 is Legitimate (see IrisManager._aggregate_score).
    return _cfg("iris.legitimate_threshold", 80, float)

@_lazy_load
def get_iris_suspicious_threshold() -> float:
    # 0–100 subtractive scale: >= 55 is Suspicious, below is Phishing.
    return _cfg("iris.suspicious_threshold", 55, float)

@_lazy_load
def get_iris_min_headers() -> int:
    return _cfg("iris.min_headers", 2, int)

@_lazy_load
def get_iris_data(key: str):
    """Dataset de detección de Iris desde ``iris.data.<key>`` (o None si falta).

    Los datasets (marcas, dominios, keywords, extensiones…) viven en el bloque
    ``iris.data`` de SecOpsConfig.json; los defaults de respaldo están en
    ``src/modules/features/iris/services/shared.py``, que es el único consumidor previsto.
    """
    return _cfg(f"iris.data.{key}")

@_lazy_load
def get_iris_prompts() -> dict:
    """Prompts de IrisAIWriter (IA1) desde ``iris.prompts.<key>``.

    Espejo de ``get_prompts_config()`` (que solo mira el bloque ``themis``)
    para el módulo Iris: ``iris.prompts.summary.{system,userTemplate}``.
    """
    return _cfg("iris.prompts", {})


# =============================================================================
# VERSIÓN DE LA APLICACIÓN
# =============================================================================

@_lazy_load
def get_app_version() -> str:
    """Versión de la aplicación desde SecOpsConfig.json."""
    return _cfg("appVersion", "0.0.0", str)


# =============================================================================
# CONFIGURACIÓN DE BASE DE DATOS (no secretos)
# =============================================================================

@_lazy_load
def get_db_isolation_level() -> str:
    """Devuelve el isolation level de SQLAlchemy desde SecOpsConfig.json."""
    return _cfg("database.isolation_level", "READ COMMITTED")


@_lazy_load
def get_db_pool_config() -> dict:
    """Devuelve la configuración del pool de conexiones desde SecOpsConfig.json.

    Claves: pool_size, max_overflow, pool_timeout. Aplica defaults sensatos si
    faltan, de modo que el sistema arranca aunque el bloque no esté completo.
    """
    return {
        "pool_size": _cfg("database.pool_size", 10, int),
        "max_overflow": _cfg("database.max_overflow", 20, int),
        "pool_timeout": _cfg("database.pool_timeout", 30, int),
    }


# =============================================================================
# CONFIGURACIÓN DE SEGURIDAD
# =============================================================================

@_lazy_load
def get_argon2_config() -> dict:
    """Devuelve los parámetros de Argon2id para hashing de contraseñas."""
    defaults = {"time_cost": 3, "memory_cost": 65536, "parallelism": 4}
    return {**defaults, **_cfg("security.argon2", {})}


# =============================================================================
# ENTORNO
# =============================================================================

def is_development() -> bool:
    """Indica si la aplicación está en modo desarrollo."""
    return os.environ.get("FLASK_ENV", "production") == "development"