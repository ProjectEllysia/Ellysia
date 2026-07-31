"""
config_reading.py
Módulo de lectura de configuración SecOps.
Carga lazy (solo al primer acceso) desde SecOpsConfig.json o variables de entorno.
"""

import hashlib
import json
import logging
import os

from enum import Enum
from functools import wraps
from pathlib import Path
from dotenv import load_dotenv
from dataclasses import dataclass, field, fields, is_dataclass

from typing import Optional, TypeVar, get_origin

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

    ``_cfg("features.themis.traceroute.cacheHours", 24, float)`` es el equivalente de
    ``_require_configs().get("features", {}).get("themis", {}).get("traceroute", {})
    .get("cacheHours", 24)`` convertido a ``float``. Requiere llamarse desde una
    función decorada con ``@_lazy_load`` (o después de que la config ya esté cargada).
    """
    node = _require_configs()
    for key in path.split("."):
        if not isinstance(node, dict) or key not in node:
            return default
        node = node[key]
    return cast(node) if cast else node


# =============================================================================
# BLOQUES DE CONFIGURACIÓN
# =============================================================================
#
# Un "bloque" es una dataclass ``frozen`` atada a una rama del JSON: declara sus
# campos con el tipo y el valor por defecto, y ``config_block`` se encarga de
# leerlos. Sustituye al patrón de un getter por valor, que tenía dos problemas
# concretos:
#
#   - El default se escribía dos veces (en el getter y en SecOpsConfig.json) y
#     acababa divergiendo sin que nadie lo notara, porque el del fichero gana.
#     Aquí se declara una sola vez, en el campo.
#   - Sin tipos, cada consumidor tenía que recordar qué devolvía cada getter.
#
# Los bloques son planos a propósito: no hay un ``ThemisConfig`` que contenga a
# los demás. Ningún consumidor quiere "todo Themis" — quiere Nuclei, o quiere
# traceroute — y un árbol obligaría a construir las ramas que nadie ha pedido.

_ConfigBlock = TypeVar("_ConfigBlock")

# El bloque construido, junto al dict del que salió. Se compara por identidad
# (``is``) en vez de invalidar a mano: así reload(), save_full_config() y un
# ``_configs`` monkeypatcheado en un test invalidan la caché solos, sin que
# ninguno de los tres tenga que acordarse de avisar.
_block_cache: dict[type, tuple[dict, object]] = {}


def _to_camel_case(snake_case_name: str) -> str:
    """``max_body_bytes`` → ``maxBodyBytes``, la convención de claves del JSON."""
    head, *tail = snake_case_name.split("_")
    return head + "".join(word.capitalize() for word in tail)


def config_block(path: str):
    """Ata una dataclass ``frozen`` a la rama ``path`` de SecOpsConfig.json.

    Cada campo se lee de ``<path>.<campoEnCamelCase>``; si la clave no está, se
    queda con el valor por defecto declarado en el campo. Para las claves que no
    siguen la convención (las que se pasan tal cual como kwargs a una librería,
    como ``isolation_level``) se indica el nombre explícito::

        pool_size: int = field(default=10, metadata={"key": "pool_size"})
    """
    def decorator(block_type):
        if not is_dataclass(block_type):
            raise TypeError(f"{block_type.__name__} debe ser una dataclass")
        block_type.__config_path__ = path
        return block_type
    return decorator


def _coerce(field_type, raw_value):
    """Convierte el valor del JSON al tipo declarado en el campo.

    ``bool`` primero: en Python ``bool`` es subclase de ``int``, y sin este
    orden un ``"true"`` acabaría en ``int("true")``.
    """
    origin_type = get_origin(field_type) or field_type
    if origin_type is bool:
        return _as_bool(raw_value)
    if origin_type in (int, float, str):
        return origin_type(raw_value)
    return raw_value


@_lazy_load
def load_block(block_type: type[_ConfigBlock]) -> _ConfigBlock:
    """Devuelve la instancia (cacheada) del bloque, leída de la config actual."""
    source, cached = _block_cache.get(block_type, (None, None))
    if source is _configs:
        return cached  # type: ignore[return-value]

    branch = _cfg(block_type.__config_path__, {})  # type: ignore[attr-defined]
    values = {}
    for field_info in fields(block_type):  # type: ignore[arg-type]
        key = field_info.metadata.get("key") or _to_camel_case(field_info.name)
        if isinstance(branch, dict) and key in branch:
            values[field_info.name] = _coerce(field_info.type, branch[key])

    built = block_type(**values)
    _block_cache[block_type] = (_configs, built)
    return built


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
    ``refresh_token_expiry_days`` provienen de ``general.security.jwt`` en
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

    jwt_cfg = _cfg("general.security.jwt", {})
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
    parámetros provienen de ``general.security.mfa`` en SecOpsConfig.json.
    """
    encryption_key = os.getenv("MFA_ENCRYPTION_KEY")
    if not encryption_key:
        logger.error("Falta la variable de entorno MFA_ENCRYPTION_KEY")
        raise ValueError(
            "Falta la variable de entorno MFA_ENCRYPTION_KEY. "
            "Defínela en el archivo .env (clave Fernet: "
            "python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\")."
        )

    mfa_cfg = _cfg("general.security.mfa", {})
    return {
        "encryption_key": encryption_key,
        "issuer": str(mfa_cfg.get("issuer", "Ellysia")),
        "challenge_expiry_minutes": int(mfa_cfg.get("challenge_expiry_minutes", 5)),
        "max_challenge_attempts": int(mfa_cfg.get("max_challenge_attempts", 5)),
        "recovery_codes_count": int(mfa_cfg.get("recovery_codes_count", 10)),
    }


def get_encryption_key(purpose: str) -> str:
    """Clave Fernet de cifrado en reposo para un ``purpose`` dado (``shared._crypto``).

    Convención de nombre, no dato configurable: el env var es
    ``f"{purpose.upper()}_ENCRYPTION_KEY"`` — ``purpose="mfa"`` da
    ``MFA_ENCRYPTION_KEY`` (la que ya usaba ``users/services/secrets.py``
    directamente), ``purpose="iris_mailbox"`` da
    ``IRIS_MAILBOX_ENCRYPTION_KEY``. Siempre en ``.env``, nunca en
    ``SecOpsConfig.json`` — es un secreto.

    Raises:
        ValueError: Si falta la variable de entorno correspondiente.
    """
    env_var = f"{purpose.upper()}_ENCRYPTION_KEY"
    key = os.getenv(env_var)
    if not key:
        logger.error(f"Falta la variable de entorno {env_var}")
        raise ValueError(
            f"Falta la variable de entorno {env_var}. "
            "Defínela en el archivo .env (clave Fernet: "
            "python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\")."
        )
    return key


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
    """Resuelve la ruta cruda en la config.

    Un ``dir_key`` con punto (``themis.csv``) es el directorio de un módulo y
    vive en ``features.<módulo>.directories.<sub_key>``; uno plano
    (``tempdir``) es transversal y vive en ``general.directories``. Ojo: el
    ``dir_key`` **no** es una ruta del árbol de configuración, sino la clave
    del enum ``DirectoryType`` — de ahí que se traduzca aquí y no en ``_cfg``.
    """
    if "." in dir_key:
        module_key, sub_key = dir_key.split(".")
        module_config = cfg.get("features", {}).get(module_key)
        if module_config is None:
            raise ValueError(f"Módulo '{module_key}' no encontrado en la configuración.")
        directories = module_config.get("directories")
        if directories is None:
            raise ValueError(f"Directorio '{dir_key}' no encontrado en la configuración.")
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
    return _cfg("features.aegis", {})

@_lazy_load
def get_aegis_tips_amount() -> int:
    return _cfg("features.aegis.tipsAmount", 7, int)

@_lazy_load
def get_aegis_vulnerabilities_antiquity() -> int:
    return _cfg("features.aegis.vulnerabilitiesAntiquity", 5, int)

@_lazy_load
def get_aegis_brands() -> list[dict]:
    return _cfg("features.aegis.brands", [], list)

@_lazy_load
def get_aegis_prompts() -> dict:
    return _cfg("features.aegis.prompts", {})


# =============================================================================
# CONFIGURACIÓN DE IA (scribe)
# =============================================================================

@_lazy_load
def get_ai_config() -> dict:
    """Devuelve el bloque 'ai' de SecOpsConfig.json (puede estar vacío)."""
    return _cfg("tools.scribe", {})


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
    return _cfg("tools.herald", {})


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
    return _cfg("features.themis", {})

# Los cinco escáneres de Themis, cada uno con su propio bloque bajo
# ``features.themis.scanners``: mismos ``prompts`` y ``colorPalette``, más los
# ajustes que cada herramienta necesite.
THEMIS_SCANNERS = ("nmap", "nikto", "openvas", "lybra", "nuclei")


@_lazy_load
def get_prompts_config() -> dict:
    return {
        scanner: _cfg(f"features.themis.scanners.{scanner}.prompts", {})
        for scanner in THEMIS_SCANNERS
    }

@_lazy_load
def get_tool_prompts(tool: str) -> dict:
    prompts = get_prompts_config()
    return prompts.get(tool, {})

@_lazy_load
def get_tool_color_palette(tool) -> dict:
    # Accepts a ThemisTool enum member or a plain string; without this, a
    # dict lookup with an Enum instance against string keys always misses
    # and silently returns {} (bug: every caller has been getting the
    # hardcoded per-strategy fallback colors instead of SecOpsConfig's).
    tool_key = tool.value if hasattr(tool, "value") else tool
    return _cfg(f"features.themis.scanners.{tool_key}.colorPalette", {})

@_lazy_load
def are_local_ips_allowed() -> bool:
    return _as_bool(_cfg("features.themis.areLocalIpsAllowed", False))

@_lazy_load
def get_openvas_scan_configs() -> dict[str, str]:
    return _cfg("features.themis.scanners.openvas.toolConfigs.scanConfigs", {})

@_lazy_load
def get_openvas_port_list() -> dict[str, str]:
    return _cfg("features.themis.scanners.openvas.toolConfigs.portList", {})

@_lazy_load
def is_host_reachability_check_enabled() -> bool:
    return _as_bool(_cfg("features.themis.hostReachabilityCheck.enabled", True))

@_lazy_load
def get_host_reachability_check_timeout() -> float:
    return _cfg("features.themis.hostReachabilityCheck.timeout", 3.0, float)

@_lazy_load
def get_host_reachability_check_port() -> int:
    return _cfg("features.themis.hostReachabilityCheck.port", 80, int)

@_lazy_load
def get_themis_csv_dir() -> str:
    return get_directory_of(DirectoryType.CSV_THEMIS)


# --- Task timeouts (Q2: números mágicos movidos desde themis/services/tasks.py) ---

@_lazy_load
def get_themis_task_default_timeout() -> float:
    """Timeout (s) de ``_Task`` cuando el caller no especifica uno explícito."""
    return _cfg("features.themis.taskDefaults.timeout", 200000, float)

@_lazy_load
def get_openvas_task_timeout() -> float:
    """Timeout (s) por defecto de ``OpenVASTask`` — también usado como timeout
    del job en ``OpenVASScanManager.run_scan`` (deben coincidir: si el job de
    RQ expira antes que el escaneo interno, se mata a mitad de sondeo)."""
    return _cfg("features.themis.scanners.openvas.timeout", 14400, float)

@_lazy_load
def get_openvas_max_wait_timeout() -> float:
    """Techo aplicado en ``OpenVASTask.wait()`` al timeout recibido."""
    return _cfg("features.themis.scanners.openvas.maxWaitTimeout", 28800, float)


# --- Lybra knowledge base (local NVD/KEV/EPSS mirror) ---

@_lazy_load
def is_kb_sync_enabled() -> bool:
    return _as_bool(_cfg("features.themis.kb.enabled", False))

@_lazy_load
def get_kb_sources() -> dict:
    return _cfg("features.themis.kb.sources", {})

@_lazy_load
def get_kb_sync_cron() -> str:
    return _cfg("features.themis.kb.syncCron", "0 3 * * *")

@_lazy_load
def get_kb_nvd_window_days() -> int:
    return _cfg("features.themis.kb.nvdWindowDays", 8, int)

@_lazy_load
def get_kb_nvd_api_key():
    # Secret → prefer the environment, per the config convention.
    import os
    return os.environ.get("NVD_API_KEY") or (_cfg("features.themis.kb.nvdApiKey", "") or None)


# --- Lybra active detection checks (Fase R) ---

@_lazy_load
def is_lybra_active_checks_enabled() -> bool:
    # Global switch, on by default: active checks touch the target, but the
    # per-user authorized-targets register (roadmap §6, AuthorizedTargetManager)
    # is the real gate — LybraEngineManager only runs these against a target the
    # caller has explicitly authorized, regardless of this flag. This exists as
    # an operator-level kill switch to disable the whole feature deployment-wide.
    return _as_bool(_cfg("features.themis.scanners.lybra.activeChecks", True))


# --- Lybra own fingerprinting (Fase F) ---

# --- Ingesta de plantillas de Nuclei al runtime propio (Fase R) ---

@_lazy_load
def is_lybra_template_ingest_enabled() -> bool:
    """Si Lybra ingiere plantillas de Nuclei a su propio runtime.

    **Por defecto desactivado, y a conciencia.** El código está construido y
    probado, pero la decisión de si la ingesta merece la pena la toma el número
    del censo de la Fase U4 (`tools/nuclei_template_census.py`), que solo puede
    medirse en una máquina con el feed instalado. Hasta que ese número exista,
    el interruptor existe pero no se activa: el flag decide la *activación*, no
    la existencia del código.
    """
    return _as_bool(_cfg("features.themis.scanners.lybra.ingest.enabled", False))


@_lazy_load
def get_lybra_ingest_min_severity() -> str:
    """Severidad mínima de una plantilla ingerida para llegar a ejecutarse."""
    return _cfg("features.themis.scanners.lybra.ingest.minSeverity", "MEDIUM", str)


@_lazy_load
def get_lybra_ingest_max_checks() -> int:
    """Tope duro de checks ingeridos por escaneo (la red de seguridad final)."""
    return _cfg("features.themis.scanners.lybra.ingest.maxChecks", 300, int)


@_lazy_load
def is_lybra_fingerprinting_enabled() -> bool:
    # Same story as active checks: on by default now that the authorized-targets
    # register (roadmap §6) gates it per-target; this flag is just the
    # operator-level kill switch.
    return _as_bool(_cfg("features.themis.scanners.lybra.fingerprintingEnabled", True))


# --- Nuclei (Fase U1) ---

@_lazy_load
def get_nuclei_binary_path() -> str:
    """Ruta o nombre del binario ``nuclei`` (resuelto vía PATH por defecto)."""
    return _cfg("features.themis.scanners.nuclei.binaryPath", "nuclei")

def _nuclei_default_template_locations() -> tuple[Path, ...]:
    """Ubicaciones por defecto de Nuclei, resueltas en el momento de llamar.

    Se calculan aquí y no en una constante de módulo a propósito: ``Path.home()``
    en una constante se congelaría al importar, y entonces ni un test podría
    simular otro ``HOME`` ni un worker heredaría un entorno distinto al del
    proceso que lo importó. En la imagen Docker esto resuelve a
    ``/root/.local/nuclei-templates``, que es donde el ``nuclei -update-templates``
    del Dockerfile las deja.
    """
    home = Path.home()
    return (home / ".local" / "nuclei-templates", home / "nuclei-templates")


@_lazy_load
def get_nuclei_templates_dir() -> Optional[Path]:
    """Directorio efectivo del **único** árbol de plantillas de Nuclei de Themis.

    Themis tiene una sola copia de las plantillas, y este getter es quien dice
    dónde está. Tres consumidores dependen de esa respuesta y ninguno debe
    resolverla por su cuenta: ``NucleiScanTask`` (que se la pasa al binario por
    ``-templates``), la ingesta de plantillas al runtime propio y el censo de
    ingestibilidad (roadmap Fases R y U4).

    Prioridad, de más explícito a más implícito — mismo estilo de cadena que
    ``get_nuclei_templates_version()``, su getter hermano:
    1) ``themis.nuclei.templatesDir`` en SecOpsConfig.json, 2) la variable de
    entorno ``NUCLEI_TEMPLATES_DIR``, 3) las ubicaciones por defecto de Nuclei.

    Returns:
        La ruta al árbol, o ``None`` si ninguna candidata existe en disco.
        Nunca una ruta inventada: quien pasa el flag al binario omite
        ``-templates`` y deja que decida él, y quien necesita *leer* las
        plantillas no puede hacer nada y debe poder saberlo.
    """
    configured = (_cfg("features.themis.scanners.nuclei.templatesDir", "") or "").strip()
    if configured:
        path = Path(configured)
        if path.is_dir():
            return path
        # Una ruta configurada que no existe es un error de despliegue, no algo
        # que deba degradarse en silencio a otra ubicación: se avisa y se sigue
        # buscando, para no dejar un escaneo sin plantillas sin explicación.
        logger.warning(
            "themis.nuclei.templatesDir apunta a '%s', que no existe; "
            "se buscarán las ubicaciones por defecto de Nuclei", configured
        )

    from_environment = (os.environ.get("NUCLEI_TEMPLATES_DIR") or "").strip()
    if from_environment and Path(from_environment).is_dir():
        return Path(from_environment)

    return next((c for c in _nuclei_default_template_locations() if c.is_dir()), None)

@_lazy_load
def get_nuclei_default_severities() -> list:
    """Perfil acotado por defecto cuando el caller no especifica severidades.

    Excluye ``info`` a propósito (roadmap Fase U1, punto 1): son miles de
    plantillas de tech-detect, y al ser ``confirmed=True`` sin CVSS el suelo
    de ``score_finding`` las subiría todas a MEDIO. Activarlas es una elección
    explícita del usuario en el formulario, no un default.
    """
    return _cfg("features.themis.scanners.nuclei.defaultSeverities", ["critical", "high", "medium"])

@_lazy_load
def get_nuclei_rate_limit() -> int:
    """Peticiones/segundo máximas por defecto."""
    return _cfg("features.themis.scanners.nuclei.rateLimit", 150, int)

@_lazy_load
def get_nuclei_request_timeout() -> int:
    """Timeout por petición HTTP individual (segundos)."""
    return _cfg("features.themis.scanners.nuclei.requestTimeout", 10, int)

@_lazy_load
def get_nuclei_task_timeout() -> float:
    """Timeout (s) por defecto del escaneo completo cuando el caller no
    especifica uno explícito — también usado como timeout del job en
    ``NucleiScanManager.run_scan``."""
    return _cfg("features.themis.scanners.nuclei.timeout", 1800, float)

@_lazy_load
def get_nuclei_templates_version() -> str:
    """Versión de plantillas usada como fallback hasta que ``NucleiScanTask``
    capture la versión real del banner de arranque del binario (ver
    ``NucleiScanManager._execute_scan``, que corrige el ``feed_version`` de
    cada ``Finding`` post-hoc con ese dato más fiable).

    Prioridad: 1) el fichero que el Dockerfile vuelca al hornear las
    plantillas en build (``/app/resources/nuclei_templates_version.txt`` —
    más fiable que un valor de configuración estático porque refleja lo que
    de verdad se sincronizó en esa imagen), 2) ``themis.nuclei.templatesVersion``
    en ``SecOpsConfig.json``, 3) un marcador explícito de "desconocido".
    """
    version_file = Path(get_directory_of(DirectoryType.RESOURCES_THEMIS)).parent / "nuclei_templates_version.txt"
    try:
        from_file = version_file.read_text(encoding="utf-8").strip()
        if from_file:
            return f"nuclei-templates-{from_file}"
    except (OSError, IOError):
        pass
    configured = _cfg("features.themis.scanners.nuclei.templatesVersion", "")
    return f"nuclei-templates-{configured}" if configured else "nuclei-templates-unknown"


@_lazy_load
def get_themis_default_folder_name() -> str:
    """Devuelve el nombre mostrado para la carpeta virtual de escaneos sueltos."""
    return _cfg("features.themis.folders.defaultFolderName", "Sin carpeta")


@_lazy_load
def get_themis_history_size() -> int:
    """Número de escaneos recientes a considerar en las estadísticas históricas."""
    return _cfg("features.themis.history.maxScans", 5, int)


@_lazy_load
def get_themis_traceroute_cache_hours() -> float:
    """Horas que una ruta cacheada se considera válida antes de recalcularse."""
    return _cfg("features.themis.traceroute.cacheHours", 24, float)


@_lazy_load
def get_themis_traceroute_max_hops() -> int:
    """Número máximo de saltos a sondear (``-m`` en traceroute)."""
    return _cfg("features.themis.traceroute.maxHops", 30, int)


@_lazy_load
def get_themis_traceroute_timeout() -> float:
    """Tiempo máximo total (segundos) para el comando traceroute."""
    return _cfg("features.themis.traceroute.timeout", 60, float)


@_lazy_load
def get_themis_traceroute_retry_failed_minutes() -> float:
    """Minutos que una ruta fallida (sin saltos) se cachea antes de reintentar.

    Mucho más corto que ``cacheHours``: evita re-sondear un host inalcanzable en
    cada apertura del detalle, pero permite reintentar pronto (o de inmediato con
    el botón de refresco)."""
    return _cfg("features.themis.traceroute.retryFailedMinutes", 15, float)


# =============================================================================
# CONFIGURACIÓN COMPLETA (GET/SET)
# =============================================================================

@_lazy_load
def get_full_config() -> dict:
    """Devuelve toda la configuración."""
    return _require_configs().copy()


def _compute_config_version(configs: dict) -> str:
    """Hash de contenido de una config — usado como ETag (C9)."""
    canonical = json.dumps(configs, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()[:16]


@_lazy_load
def get_config_version() -> str:
    """ETag de la config actual: detecta escrituras concurrentes en PUT
    /system (C9) — dos admin/pestañas guardando a la vez pisaban el config
    del otro sin avisar. El cliente debe reenviar este valor vía cabecera
    ``If-Match`` en el PUT; si no coincide con la versión actual, se rechaza."""
    return _compute_config_version(_require_configs())


def save_full_config(new_config: dict, expected_version: Optional[str] = None) -> dict:
    """Guarda la configuración completa.

    Si ``expected_version`` se indica y no coincide con la versión actual
    (ETag de ``get_config_version()``), lanza ``IllegalStateError`` (409) en
    vez de sobrescribir — evita el last-write-wins silencioso de C9.
    """
    global _configs
    if _configs_path is None:
        raise FileNotFoundError("No se encontró ningún archivo de configuración.")
    if expected_version is not None:
        current_version = get_config_version()
        if expected_version != current_version:
            friendly = (
                "La configuración cambió desde que la cargaste. Recárgala "
                "antes de guardar para no sobrescribir cambios ajenos."
            )
            # user_message explícito: IllegalStateError autogenera uno
            # genérico a partir de expected_state/current_state si no se
            # pasa, y el texto de arriba nunca llegaría al cliente.
            raise IllegalStateError(
                friendly,
                expected_state=expected_version,
                current_state=current_version,
                user_message=friendly,
            )
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
    cfg = _cfg("infrastructure.redis", {})
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
    cfg = _cfg("infrastructure.taskqueue", {})
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
# CONFIGURACIÓN DE HYGEIA
# =============================================================================

@config_block("features.hygeia.limits")
@dataclass(frozen=True)
class HygeiaLimits:
    """Topes defensivos sobre lo que un agente puede mandar en un heartbeat.

    No son ajustes de comodidad: cada uno acota un recurso que un agente
    comprometido —o simplemente mal configurado— podría agotar (§16).
    """

    max_body_bytes: int = 1048576
    """Tamaño máximo (comprimido) del cuerpo de un heartbeat, en bytes (§16.1)."""

    max_decompressed_bytes: int = 4194304
    """Tope de descompresión de un heartbeat gzip (defensa anti gzip-bomb, §16.1)."""

    max_processes: int = 20
    """Máximo de procesos en topCpu/topMem por heartbeat (§16.1)."""

    max_disk_mounts: int = 64
    """Máximo de puntos de montaje reportados por heartbeat (§16.1)."""

    max_net_interfaces: int = 64
    """Máximo de interfaces de red reportadas por heartbeat (§16.1)."""

    max_inventory_items: int = 2000
    """Máximo de aplicaciones en un escaneo de inventario de software (§16.1)."""

    max_series_points: int = 1000
    """Máximo de puntos devueltos por la serie temporal de un activo (§5)."""

    min_interval_sec: int = 5
    """Suelo de cadencia entre heartbeats de una misma clave, en segundos (§16.2)."""

    clock_skew_sec: int = 300
    """Ventana de cordura (± segundos) para el ``collectedAt`` del agente (§16.3)."""

    max_assets_per_user: int = 500
    """Cuota de activos monitorizados que puede dar de alta un usuario (§16.4)."""


@config_block("features.hygeia")
@dataclass(frozen=True)
class HygeiaConfig:
    """Cadencia y retención del monitor de activos."""

    heartbeat_interval_sec: int = 15
    """Intervalo de heartbeat esperado del agente, en segundos."""

    offline_after_missed: int = 4
    """Heartbeats perdidos (sobre el intervalo efectivo) para pasar de stale a offline."""

    retention_days: int = 30
    """Antigüedad máxima de un AssetSnapshot antes de podarlo (§7.3)."""

    retention_cron: str = "0 4 * * *"
    """Expresión cron del job diario de poda de snapshots."""

    thresholds: dict[str, dict[str, int]] = field(default_factory=dict)
    """Umbrales globales por defecto; cada activo puede pisarlos desde la DB.

    Mapa libre de métrica (``cpuPct``, ``memPct``…) a sus cortes, así que se
    queda como dict: las claves las decide la configuración, no este módulo.
    """


def hygeia_config() -> HygeiaConfig:
    return load_block(HygeiaConfig)


def hygeia_limits() -> HygeiaLimits:
    return load_block(HygeiaLimits)


# =============================================================================
# CONFIGURACIÓN DE IRIS
# =============================================================================

@_lazy_load
def get_iris_config() -> dict:
    return _cfg("features.iris", {})

@_lazy_load
def get_iris_legitimate_threshold() -> float:
    # 0–100 subtractive scale: >= 80 is Legitimate (see IrisManager._aggregate_score).
    return _cfg("features.iris.legitimateThreshold", 80, float)

@_lazy_load
def get_iris_suspicious_threshold() -> float:
    # 0–100 subtractive scale: >= 55 is Suspicious, below is Phishing.
    return _cfg("features.iris.suspiciousThreshold", 55, float)

@_lazy_load
def get_iris_min_headers() -> int:
    return _cfg("features.iris.minHeaders", 2, int)

@_lazy_load
def get_iris_max_message_bytes() -> int:
    # C4: AnalyzeRequestSchema had no upper bound at all — a multi-MB .eml
    # (attachments included) was accepted whole into a Text column and
    # re-parsed, base64 decoding included, on every subsequent read
    # (get_analysis_results/path/iocs). 10 MB comfortably covers a real
    # email with attachments while capping the re-parse cost.
    return _cfg("features.iris.maxMessageBytes", 10 * 1024 * 1024, int)

@_lazy_load
def get_iris_data(key: str):
    """Dataset de detección de Iris desde ``iris.data.<key>`` (o None si falta).

    Los datasets (marcas, dominios, keywords, extensiones…) viven en el bloque
    ``iris.data`` de SecOpsConfig.json; los defaults de respaldo están en
    ``src/modules/features/iris/services/shared.py``, que es el único consumidor previsto.
    """
    return _cfg(f"features.iris.data.{key}")

@_lazy_load
def get_iris_prompts() -> dict:
    """Prompts de IrisAIWriter (IA1) desde ``iris.prompts.<key>``.

    Espejo de ``get_prompts_config()`` (que solo mira el bloque ``themis``)
    para el módulo Iris: ``iris.prompts.summary.{system,userTemplate}``.
    """
    return _cfg("features.iris.prompts", {})

@_lazy_load
def get_iris_scoring_weight(weight_key: str, default: float) -> float:
    """Peso de scoring configurable de una regla de Iris (recalibración §19/S6).

    ``iris.scoring.<weight_key>`` en SecOpsConfig.json puede pisar la
    magnitud de penalización que una regla define en código sin necesidad de
    redeploy -- el propio ``default`` que cada llamada pasa (el valor
    calibrado por el consejo, ver STUDY.md) es el que se usa si la clave no
    está presente en la config, así que el comportamiento no cambia hasta
    que alguien la añade explícitamente.
    """
    return _cfg(f"features.iris.scoring.{weight_key}", default, float)


# =============================================================================
# CONECTOR DE BUZÓN DE IRIS (Fase 3-4 del plan mailbox-connector)
# =============================================================================

@_lazy_load
def get_iris_max_connections_per_user() -> int:
    """Máximo de cuentas de correo que un usuario puede conectar a la vez."""
    return _cfg("features.iris.maxConnectionsPerUser", 5, int)


@_lazy_load
def get_iris_poll_interval_minutes() -> int:
    """Intervalo (minutos) del scheduler que sondea las conexiones activas."""
    return _cfg("features.iris.pollIntervalMinutes", 5, int)


@_lazy_load
def get_iris_max_ingested_per_day() -> int:
    """Tope diario de análisis auto-ingeridos, por conexión (no global).

    Una conexión mal configurada (carpeta ruidosa, bucle de reenvíos) no
    debe poder generar analisis sin límite — ver roadmap-ellysia.md §8.1.
    """
    return _cfg("features.iris.maxIngestedPerDay", 200, int)


def get_gmail_environment() -> dict[str, str]:
    """Credenciales OAuth de la app de Gmail desde variables de entorno.

    Returns:
        dict con 'client_id' y 'client_secret'.

    Raises:
        ValueError: Si falta alguna de las dos.
    """
    client_id = os.getenv("GMAIL_CLIENT_ID")
    client_secret = os.getenv("GMAIL_CLIENT_SECRET")
    if not client_id or not client_secret:
        raise ValueError(
            "Faltan GMAIL_CLIENT_ID/GMAIL_CLIENT_SECRET en el archivo .env. "
            "Regístralos en Google Cloud Console (OAuth client, tipo 'Web "
            "application') antes de conectar una cuenta Gmail."
        )
    return {"client_id": client_id, "client_secret": client_secret}


def get_graph_environment() -> dict[str, str]:
    """Credenciales OAuth de la app registrada en Microsoft Entra ID.

    Returns:
        dict con 'client_id', 'client_secret' y 'tenant' (por defecto
        "common": cuentas personales y de cualquier organización).

    Raises:
        ValueError: Si falta client_id o client_secret.
    """
    client_id = os.getenv("GRAPH_CLIENT_ID")
    client_secret = os.getenv("GRAPH_CLIENT_SECRET")
    tenant = os.getenv("GRAPH_TENANT_ID", "common")
    if not client_id or not client_secret:
        raise ValueError(
            "Faltan GRAPH_CLIENT_ID/GRAPH_CLIENT_SECRET en el archivo .env. "
            "Regístralos como app registration en Microsoft Entra ID (Azure "
            "AD) antes de conectar una cuenta Microsoft 365."
        )
    return {"client_id": client_id, "client_secret": client_secret, "tenant": tenant}


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
    return _cfg("infrastructure.database.isolation_level", "READ COMMITTED")


@_lazy_load
def get_db_pool_config() -> dict:
    """Devuelve la configuración del pool de conexiones desde SecOpsConfig.json.

    Claves: pool_size, max_overflow, pool_timeout. Aplica defaults sensatos si
    faltan, de modo que el sistema arranca aunque el bloque no esté completo.
    """
    return {
        "pool_size": _cfg("infrastructure.database.pool_size", 10, int),
        "max_overflow": _cfg("infrastructure.database.max_overflow", 20, int),
        "pool_timeout": _cfg("infrastructure.database.pool_timeout", 30, int),
    }


# =============================================================================
# CONFIGURACIÓN DE SEGURIDAD
# =============================================================================

@_lazy_load
def get_argon2_config() -> dict:
    """Devuelve los parámetros de Argon2id para hashing de contraseñas."""
    defaults = {"time_cost": 3, "memory_cost": 65536, "parallelism": 4}
    return {**defaults, **_cfg("general.security.argon2", {})}


# =============================================================================
# ENTORNO
# =============================================================================

def is_development() -> bool:
    """Indica si la aplicación está en modo desarrollo."""
    return os.environ.get("FLASK_ENV", "production") == "development"