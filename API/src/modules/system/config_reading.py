"""
config_reading.py
Módulo de lectura de configuración SecOps.
Carga lazy (solo al primer acceso) desde SecOpsConfig.json o variables de entorno.
"""

import hashlib
import json
import logging
import os

from dataclasses import dataclass, field, fields, is_dataclass
from enum import Enum
from functools import wraps
from pathlib import Path
from typing import Optional, TypeVar, get_origin

from dotenv import load_dotenv

from src.modules.shared._exceptions import IllegalStateError

logger = logging.getLogger(__name__)

load_dotenv()

# =============================================================================
# ESTADO DEL MÓDULO
# =============================================================================

_configs: dict | None = None
_configs_path: Path | None = None

# mtime del fichero en el momento de la última lectura. Solo lo usa
# ``reload_if_changed()`` para no releer en cada job del worker.
_configs_mtime: float = 0.0

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
        global _configs, _configs_path, _configs_mtime
        if _configs is None:
            if _configs_path is None:
                this_file = Path(__file__).resolve()
                candidates = (
                    parent / name
                    for parent in reversed(this_file.parents[:4])
                    for name in ("SecOpsConfig.json", "SecConfig.json")
                )
                _configs_path = next((candidate for candidate in candidates if candidate.exists()), None)
                if _configs_path is None:
                    raise FileNotFoundError("No se encontró ningún archivo de configuración.")
            _configs_mtime = _read_mtime(_configs_path)
            with open(_configs_path, "r", encoding="utf-8") as f:
                _configs = json.load(f)
        return func(*args, **kwargs)
    return wrapper


# =============================================================================
# UTILIDADES
# =============================================================================

#: Contador que avanza cada vez que la configuración cargada es sustituida.
#: Ver ``config_version``.
_configs_generation = 0


def config_version() -> tuple[int, int]:
    """Identifica el árbol de configuración vigente ahora mismo.

    Sirve para cachear cosas **derivadas** de la configuración sin que se
    queden viejas: se mete como parte de la clave de caché, y al cambiar la
    configuración las entradas antiguas dejan de ser alcanzables solas. Es lo
    mismo que ya hacía ``load_block`` comparando la identidad de ``_configs``,
    expuesto para quien no puede usar ``@config_block`` — el caso son los
    datasets de Iris, que se cachean por nombre y no por campo.

    Son dos números y no uno a propósito:

    - El **contador** avanza en cada sustitución hecha por este módulo
      (``reload``, ``reload_if_changed``, ``save_full_config``).
    - La **identidad** del diccionario cubre lo que el contador no ve: un test
      que monkeypatchee ``_configs`` directamente, que es como se prueba media
      suite. Sin ella, un caché seguiría devolviendo los datos de la
      configuración real bajo una config falsa.

    Ninguno de los dos basta por su cuenta: la identidad se puede reutilizar
    cuando el recolector libera el diccionario anterior, y el contador no ve
    las escrituras que no pasan por aquí.
    """
    return (_configs_generation, id(_configs))


def _bump_config_generation() -> None:
    global _configs_generation
    _configs_generation += 1


def reload() -> None:
    """Fuerza la recarga de la configuración desde el archivo."""
    global _configs, _configs_path
    _configs = None
    _configs_path = None
    _bump_config_generation()


def _read_mtime(path: Path) -> float:
    """mtime del fichero, o 0.0 si no se puede leer (no es motivo para fallar)."""
    try:
        return path.stat().st_mtime
    except OSError:
        return 0.0


def reload_if_changed() -> bool:
    """Relee la configuración solo si el fichero cambió en disco.

    Existe por los procesos de vida larga que no ven un ``PUT /system``: el
    proceso API refresca ``_configs`` en memoria al guardar, pero el worker de
    RQ es otro proceso (sin ``fork``, ver ``taskqueue/worker.py``) y se quedaría
    con la config que leyó al arrancar hasta que se le reinicie.

    A diferencia de ``reload()`` no pasa por ``_configs = None``: lee a una
    variable local y sustituye el diccionario entero de golpe. Varios hilos de
    worker leen la config a la vez, y el hueco en el que ``_configs`` vale
    ``None`` haría reventar al de al lado con ``IllegalStateError``.

    Returns:
        True si hubo recarga. La caché de bloques se invalida sola: compara por
        identidad contra ``_configs`` (ver ``load_block``).
    """
    global _configs, _configs_mtime
    if _configs is None or _configs_path is None:
        return False  # aún no se ha cargado nada: ya lo hará _lazy_load

    mtime = _read_mtime(_configs_path)
    if mtime == _configs_mtime:
        return False

    try:
        with open(_configs_path, "r", encoding="utf-8") as f:
            new_configs = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        # Un fichero a medio escribir o ilegible no puede tumbar un job: se
        # sigue con la config anterior y se reintenta en el siguiente.
        logger.warning("No se pudo recargar la configuración (%s): %s", _configs_path, exc)
        return False

    _configs = new_configs
    _configs_mtime = mtime
    _bump_config_generation()
    logger.info("Configuración recargada desde disco (%s)", _configs_path)
    return True


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
    "themis.output": "OUTPUT_DIR",
    "themis.csv": "CSV_THEMIS_DIR",
    "aegis.output": "OUTPUT_DIR",
    "aegis.stack": "OUTPUT_DIR",
    "iris.output": "OUTPUT_DIR",
}


def _normalize_dir_key(directory_type) -> str:
    """Acepta un ``DirectoryType`` (enum) o un string y devuelve la clave plana."""
    return directory_type.value if hasattr(directory_type, "value") else directory_type


def _env_override_for(dir_key: str) -> Optional[str]:
    """Devuelve el valor de la variable de entorno que sobreescribe ``dir_key``, si existe.

    Varios módulos (themis, aegis, iris) comparten la misma variable
    (``OUTPUT_DIR``) para que sus datos vivan bajo un único volumen montado
    en despliegues con contenedores separados para API y worker — sin esto,
    cada contenedor resuelve la ruta relativa del JSON contra su propia capa
    de filesystem, invisible para el otro (causa real de 409 al descargar
    documentos: el worker genera el PDF, pero el proceso que sirve la
    descarga nunca lo ve). El subdirectorio propio de cada ``dir_key`` se
    mantiene bajo esa raíz para que no colisionen entre sí nombres de
    fichero de módulos distintos.
    """
    env_var = _DIRECTORY_ENV_MAPPING.get(dir_key)
    if not env_var:
        return None
    base = os.getenv(env_var) or None
    if not base:
        return None
    if "." in dir_key:
        return os.path.join(base, *dir_key.split("."))
    return base


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

@config_block("features.aegis")
@dataclass(frozen=True)
class AegisConfig:
    """Generación de píldoras de concienciación y campañas."""

    enabled: bool = True

    tips_amount: int = 7
    """Consejos que se le piden a la IA por píldora."""

    questions_amount: int = 5
    """Preguntas de test que se le piden a la IA, y tope de las que se aceptan."""

    options_amount: int = 4
    """Opciones por pregunta que se le piden a la IA, y tope de las que se aceptan."""

    vulnerabilities_antiquity: int = 5
    """Antigüedad máxima (años) de una alerta para seguir considerándola vigente."""

    # ``brands`` (catálogo fijo de 19 fabricantes con su equivalencia en CIRCL)
    # se retiró: los productos vigilados son ahora de cada usuario y salen del
    # índice CPE del espejo local de NVD (``AegisOrgProfile.tracked_products``,
    # poblado vía ``GET /aegis/products``), no de la configuración global.

    prompts: dict = field(default_factory=dict)
    """Par ``system`` / ``userTemplate`` que se le pasa a Scribe."""


def aegis_config() -> AegisConfig:
    return load_block(AegisConfig)


# =============================================================================
# CONFIGURACIÓN DE LAS HERRAMIENTAS (scribe / herald)
# =============================================================================
#
# Scribe (generación con IA) y Herald (envío de correo) comparten la misma
# forma: una estrategia por defecto, un override por módulo consumidor y unos
# ajustes por estrategia. De ahí la clase base común — no es abstracción
# preventiva, son dos bloques que ya existen y ya son idénticos.

@dataclass(frozen=True)
class _StrategySelection:
    """Selección de estrategia de una herramienta enchufable."""

    default_strategy: str = ""
    """Estrategia usada cuando el módulo no tiene override propio."""

    modules: dict[str, str] = field(default_factory=dict)
    """Override por módulo consumidor: ``{"aegis": "openai", …}``."""

    strategies: dict[str, dict] = field(default_factory=dict)
    """Ajustes propios de cada estrategia (modelo, host SMTP, remitente…)."""

    def strategy_for(self, module: Optional[str] = None) -> str:
        """Estrategia que le toca a ``module``, o la de por defecto."""
        if module:
            return self.modules.get(module, self.default_strategy)
        return self.default_strategy

    def options_for(self, strategy_name: str) -> dict:
        """Ajustes declarados para ``strategy_name`` (vacío si no hay)."""
        return self.strategies.get(strategy_name, {})


@config_block("tools.scribe")
@dataclass(frozen=True)
class ScribeConfig(_StrategySelection):
    """Capa de generación con IA (Ollama / OpenAI / Google)."""

    default_strategy: str = "ollama"

    max_input_tokens: int = 24000
    """Tope de tokens estimados del prompt (system + examples + user) que
    ``AIGenerator.digest`` deja pasar antes de invocar la estrategia (Issue
    #118).

    Sin esto, un writer de dominio (p.ej. ``LybraAIWriter`` con un scan de
    muchos hallazgos) podía generar un payload que OpenAI rechazaba con un
    429 'Request too large' — tras haber quemado ``max_retries`` reintentos
    con backoff, porque el mismo prompt sobredimensionado vuelve a fallar en
    cada intento. 24000 deja margen bajo el límite TPM de 30000 observado en
    el error original, incluso en la organización más ajustada; se aplica al
    total estimado (no solo al último mensaje) e independientemente del
    backend, ya que un contexto local también tiene un tope real."""

    def timeout_for(self, strategy_name: str, default: int) -> int:
        """Timeout de cliente declarado para ``strategy_name``, o ``default``.

        Vive aquí y no en cada estrategia porque el valor está en la misma
        rama que el modelo (``strategies.<proveedor>.timeout``) y se resuelve
        igual: lo que diga el fichero gana, y si no dice nada se usa el que la
        estrategia considere razonable para su backend — un modelo local tarda
        mucho más que una API en la nube, así que no hay un único default
        sensato para los tres."""
        configured = self.options_for(strategy_name).get("timeout")
        return int(configured) if configured else default


@config_block("tools.scribe.resilience")
@dataclass(frozen=True)
class ScribeResilienceConfig:
    """Lo que ``AIGenerator`` hace cuando el proveedor de IA falla.

    Eran cuatro constantes en la firma de ``AIGenerator.__init__`` que la
    factory nunca sobreescribía, así que los valores del código eran los
    únicos que existían: ajustar la tolerancia a un proveedor lento o
    inestable obligaba a tocar el código y redesplegar.
    """

    max_retries: int = 3
    """Intentos totales de una misma generación antes de rendirse."""

    retry_base_seconds: float = 1.5
    """Base de la espera exponencial entre intentos: el intento ``n`` espera
    ``base ** n`` segundos. Con 1.5 son 1 s y 1,5 s antes del tercero."""

    breaker_threshold: int = 3
    """Fallos seguidos que abren el *circuit breaker*. Abierto, las llamadas
    se rechazan al instante en vez de encadenar timeouts contra un backend
    que ya se sabe caído."""

    breaker_timeout_seconds: int = 60
    """Segundos que el breaker permanece abierto antes de dejar pasar una
    llamada de prueba."""


@config_block("tools.herald")
@dataclass(frozen=True)
class HeraldConfig(_StrategySelection):
    """Capa de envío de correo (relay SMTP)."""

    default_strategy: str = "smtp"

    branding: dict = field(default_factory=dict)
    """Marca que pintan las plantillas: ``productName``, ``accentColor``,
    ``logoUrl``, ``supportEmail``, ``footerNote``. Lo que no se declare aquí
    lo rellena ``herald.branding.DEFAULT_BRAND``."""

    templates_dir: str = ""
    """Directorio externo con plantillas que pisan a las del paquete. Vacío
    (lo normal) = solo se usan las de ``herald/templates/``."""


def scribe_config() -> ScribeConfig: # type: ignore
    return load_block(ScribeConfig) # type: ignore


def scribe_resilience_config() -> ScribeResilienceConfig: # type: ignore
    return load_block(ScribeResilienceConfig) # type: ignore


def herald_config() -> HeraldConfig: # type: ignore
    return load_block(HeraldConfig) # type: ignore

def get_smtp_environment() -> dict[str, str]:
    """Credenciales SMTP desde variables de entorno.

    Returns:
        dict con 'username' y 'password'.

    Raises:
        ValueError: Si falta alguna de las dos.
    """
    username = os.getenv("SMTP_USERNAME")
    password = os.getenv("SMTP_PASSWORD")

    if not username:
        raise ValueError(
            "Falta la variable de entorno SMTP_USERNAME."
        )

    if not password:
        raise ValueError(
            "Falta la variable de entorno SMTP_PASSWORD."
        )

    return {"username": username, "password": password}


# =============================================================================
# CONFIGURACIÓN DE THEMIS
# =============================================================================

# Los cuatro escáneres de Themis, cada uno con su propio bloque bajo
# ``features.themis.scanners``: mismos ``prompts`` y ``colorPalette``, más los
# ajustes que cada herramienta necesite. OpenVAS salió de esta lista al
# retirarse (roadmap §7/§6.3, Ronda 2 — E2).
#
# Derivado de ScanType (A1) en vez de repetido a mano: un escáner nuevo que
# se registre en el enum aparece aquí solo, en vez de quedarse fuera hasta
# que alguien se acuerde de tocar esta tupla también. Import perezoso
# (dentro de la función, no a nivel de módulo): config_reading.py lo importa
# casi todo el proyecto muy pronto, y no debe depender en su superficie
# global de un modelo de un módulo de features concreto.
def _themis_scanner_values() -> tuple:
    from src.modules.features.themis.model import ScanType
    return tuple(scan_type.value for scan_type in ScanType)


THEMIS_SCANNERS = _themis_scanner_values()


@config_block("features.themis")
@dataclass(frozen=True)
class ThemisConfig:
    """Ajustes generales del módulo de escaneo."""

    enabled: bool = True

    are_local_ips_allowed: bool = False
    """Si se permite escanear IPs privadas/loopback.

    Es la defensa anti-SSRF del módulo: con ``True`` un usuario puede apuntar un
    escaneo a la red interna del servidor o al endpoint de metadatos del cloud.
    Se pone a ``True`` solo para desarrollo local contra IPs privadas.
    """

    accepted_risk_days: int = 365
    """Cuántos días vale un "acepto este riesgo" antes de volver a revisión.

    Vive aquí y no en el bloque del motor porque ``Finding`` es la tabla
    compartida —Lybra y Nuclei escriben en ella— y esto es política sobre
    hallazgos, no un dial de red del motor propio.

    Un riesgo asumido hace un año se asumió en unas circunstancias que quizá ya
    no son las mismas, así que caduca y el hallazgo vuelve a ``open``. Un falso
    positivo **no** usa este plazo: el motor no se equivoca más por ser más
    tarde, y lo que sí invalida un desmentido es que el motor cambie —
    ``apply_lifecycle`` lo detecta comparando ``check_id`` y ``feed_version``.
    """


@config_block("features.themis.folders")
@dataclass(frozen=True)
class ThemisFolders:
    default_folder_name: str = "Sin carpeta"
    """Nombre mostrado para la carpeta virtual de escaneos sin agrupar."""


@config_block("features.themis.history")
@dataclass(frozen=True)
class ThemisHistory:
    max_scans: int = 5
    """Escaneos recientes que se promedian en las estadísticas históricas."""


@config_block("features.themis.taskDefaults")
@dataclass(frozen=True)
class ThemisTaskDefaults:
    timeout: float = 200000
    """Timeout (s) de ``_Task`` cuando el caller no especifica uno explícito."""


@config_block("features.themis.hostReachabilityCheck")
@dataclass(frozen=True)
class HostReachabilityCheck:
    """Sondeo previo que evita lanzar un escaneo largo contra un host caído."""

    enabled: bool = True
    timeout: float = 3.0
    port: int = 80


@config_block("features.themis.traceroute")
@dataclass(frozen=True)
class TracerouteConfig:
    cache_hours: float = 24
    """Horas que una ruta cacheada se considera válida antes de recalcularse."""

    max_hops: int = 30
    """Número máximo de saltos a sondear (``-m`` en traceroute)."""

    timeout: float = 60
    """Tiempo máximo total (segundos) para el comando traceroute."""

    retry_failed_minutes: float = 15
    """Minutos que una ruta fallida (sin saltos) se cachea antes de reintentar.

    Mucho más corto que ``cache_hours``: evita re-sondear un host inalcanzable
    en cada apertura del detalle, pero permite reintentar pronto (o de inmediato
    con el botón de refresco).
    """


@config_block("features.themis.kb")
@dataclass(frozen=True)
class KnowledgeBaseConfig:
    """Espejo local de NVD/KEV/EPSS que alimenta a Lybra."""

    enabled: bool = False
    sources: dict = field(default_factory=dict)
    sync_cron: str = "0 3 * * *"
    nvd_window_days: int = 8

    max_age_days: dict = field(
        default_factory=lambda: {"nvd": 3, "kev": 7, "epss": 7}
    )
    """A partir de cuántos días sin sincronizar con éxito se considera vieja
    cada fuente.

    Los tres números no son el mismo por una razón: NVD publica CVEs a diario y
    tres días de retraso ya son detección que falta; KEV y EPSS cambian más
    despacio y una semana es tolerable. Son de operador porque dependen de la
    red y de la cuota de API de cada despliegue, no de la lógica del motor.
    """

    configured_nvd_api_key: str = field(
        default="", metadata={"key": "nvdApiKey", "optional": True}
    )
    """Respaldo en fichero de la API key de NVD. Ver ``nvd_api_key``."""

    @property
    def nvd_api_key(self) -> Optional[str]:
        """La API key efectiva, o ``None`` si no hay ninguna.

        Es un secreto, así que ``NVD_API_KEY`` en el entorno manda; la clave del
        fichero existe solo como respaldo y no está en SecOpsConfig.json a
        propósito (los secretos no se versionan).
        """
        return os.environ.get("NVD_API_KEY") or (self.configured_nvd_api_key or None)


@config_block("features.themis.scanners.lybra")
@dataclass(frozen=True)
class LybraConfig:
    """Interruptores de operador del motor propio.

    Ambos van a ``True`` por defecto: el registro de objetivos autorizados por
    usuario (roadmap §6, ``AuthorizedTargetManager``) es la verdadera puerta —
    Lybra solo toca un objetivo que el llamante haya autorizado explícitamente,
    valga lo que valga este flag. Existen como interruptor de emergencia para
    desactivar la funcionalidad en todo el despliegue.

    Los **parámetros de red** —timeouts, concurrencia, ritmo, presupuestos—
    viven aparte, en :class:`LybraEngineConfig` (L39): un interruptor de
    despliegue y un dial de afinado son cosas distintas, y mezclarlos haría el
    bloque ilegible en cuanto pasara de dos campos.
    """

    active_checks: bool = True
    fingerprinting_enabled: bool = True


@config_block("features.themis.scanners.lybra.engine")
@dataclass(frozen=True)
class LybraEngineConfig:  # pylint: disable=too-many-instance-attributes
    """Los diales de red del motor: cuánto tarda, cuánta carga mete y qué mira.

    Hasta L39 cada uno de estos valores era un literal en la firma de un
    constructor —``concurrency=200``, ``timeout=2.0``, ``min_interval=0.2``— y
    el manager instanciaba las sondas sin argumentos, así que no había forma de
    tocarlos sin editar código. OpenVAS lleva veinte años teniendo *scan
    configs* por una razón: un escaneo contra un enlace lento, contra un
    appliance frágil o contra un rango grande necesita otros números, y quien
    opera el escáner es quien sabe cuáles.

    **Los valores por defecto son exactamente los que estaban a fuego**, así
    que el cambio es invisible hasta que alguien mueve un dial. Cada campo tiene
    un consumidor real en ``managers/lybra/engine.py`` — no hay ningún dial que
    no llegue a una sonda, porque un parámetro que nadie lee es peor que uno a
    fuego: parece configurable y no lo es.
    """

    # --- Descubrimiento TCP (transport.AsyncConnectScanner / scan_ports_sync)
    tcp_concurrency: int = 200
    """Conexiones TCP en vuelo a la vez durante el barrido de puertos."""

    tcp_timeout: float = 2.0
    """Plazo por puerto TCP, en segundos."""

    # --- Descubrimiento UDP (transport.scan_udp_ports_sync)
    udp_timeout: float = 2.0
    """Plazo por sonda UDP, en segundos."""

    udp_retries: int = 1
    """Reintentos tras un primer silencio UDP. No es 0 a propósito: un
    datagrama perdido (no un puerto cerrado) haría oscilar el puerto entre
    abierto y cerrado entre escaneos, y el ciclo de vida lo leería como
    ``fixed``/``regressed`` falsos."""

    udp_budget_seconds: float = 20.0
    """Plazo total del barrido UDP. En UDP el silencio no significa
    "cerrado" sino "no lo sabemos", así que cada sonda paga su plazo entero
    contra un host que no tenga ese servicio; con siete filas eso se acumula.
    Agotarlo **no** marca nada como cerrado: los puertos que no han contestado
    se dan por no observados, que es lo que ya eran."""

    # --- Ritmo por host (checks.HostRateLimiter) y paralelismo (L23)
    rate_limit_interval: float = 0.2
    """Intervalo mínimo, en segundos, entre dos peticiones al mismo
    host. Es la cortesía con el objetivo, y manda por encima del pool."""

    host_pool_size: int = 8
    """Cuántos servicios del **mismo host** se sondan a la vez. El
    fingerprinting y los checks activos son espera de red casi entera, y en fila
    india un servicio mudo retrasa a los que vienen detrás. Va acotado por host
    y no es grande a propósito: el límite es la cortesía con el objetivo, no la
    máquina que escanea."""

    # --- Sondas HTTP (checks.HttpProbe)
    http_timeout: int = 8
    """Plazo por petición HTTP, en segundos."""

    http_max_body_bytes: int = 131072
    """Cuerpo máximo de respuesta que una sonda HTTP lee (128 KiB)."""

    http_user_agent: str = "Lybra/1.0"
    """El ``User-Agent`` con el que el motor se presenta. Configurable
    porque a veces hay que declararse ante un WAF, y a veces conviene no
    hacerlo."""

    # --- Sondas de red cruda (checks.NetworkProbe)
    network_timeout: float = 5.0
    """Plazo de conexión de una sesión de red cruda, en segundos."""

    # --- Cascada de identificación (fingerprinting/cascade.py)
    banner_timeout: float = 2.0
    """Plazo de la lectura del saludo que la cascada hace contra un
    servicio que ningún dissector reclama. Corto a propósito: un servicio que no
    saluda lo agota entero, una vez por puerto desconocido."""

    max_blind_probes: int = 2
    """Sondas activas máximas contra un servicio que no dijo nada. El
    presupuesto que separa "prueba lo que ya sabes leer" de un escaneo de
    servicios completo. A cero, la cascada se queda sólo en el saludo."""

    # --- DSL de checks: payloads/fuzzing (checks.CheckRuntime)
    max_payload_expansions: int = 25
    """Tope duro de peticiones que un check con ``payloads`` puede expandir
    (L30). Un payload es una lista de valores —veinte nombres de fichero de
    copia de seguridad, pongamos— que se sustituyen en la petición, y sin un
    tope el producto cartesiano de varias listas convierte un check en un
    barrido de fuerza bruta de horas. El motor corta en cuanto alcanza este
    número, así que es la diferencia entre "prueba unas cuantas variaciones" y
    "prueba el diccionario entero"."""


@config_block("features.themis.scanners.lybra.ingest")
@dataclass(frozen=True)
class LybraIngestConfig:
    """Ingesta de plantillas de Nuclei al runtime propio de Lybra (Fase R)."""

    enabled: bool = False
    """**Por defecto desactivado, y a conciencia.** El código está construido y
    probado, pero la decisión de si la ingesta merece la pena la toma el número
    del censo de la Fase U4 (``tools/nuclei_template_census.py``), que solo puede
    medirse en una máquina con el feed instalado. Hasta que ese número exista, el
    interruptor existe pero no se activa: el flag decide la *activación*, no la
    existencia del código."""

    min_severity: str = "MEDIUM"
    """Severidad mínima de una plantilla ingerida para llegar a ejecutarse."""

    max_checks: int = 300
    """Tope duro de checks ingeridos por escaneo (la red de seguridad final)."""


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


@config_block("features.themis.scanners.nuclei")
@dataclass(frozen=True)
class NucleiConfig:
    binary_path: str = "nuclei"
    """Ruta o nombre del binario ``nuclei`` (resuelto vía PATH por defecto)."""

    default_severities: list = field(
        default_factory=lambda: ["critical", "high", "medium"]
    )
    """Perfil acotado por defecto cuando el caller no especifica severidades.

    Excluye ``info`` a propósito (roadmap Fase U1, punto 1): son miles de
    plantillas de tech-detect, y al ser ``confirmed=True`` sin CVSS el suelo de
    ``score_finding`` las subiría todas a MEDIO. Activarlas es una elección
    explícita del usuario en el formulario, no un default.
    """

    rate_limit: int = 150
    """Peticiones/segundo máximas por defecto."""

    request_timeout: int = 10
    """Timeout por petición HTTP individual (segundos)."""

    timeout: float = 1800
    """Timeout (s) del escaneo completo cuando el caller no especifica uno —
    también usado como timeout del job en ``NucleiScanManager.run_scan``."""

    configured_templates_dir: str = field(default="", metadata={"key": "templatesDir"})
    """Respaldo en fichero del árbol de plantillas. Ver ``templates_dir``."""

    configured_templates_version: str = field(
        default="", metadata={"key": "templatesVersion"}
    )
    """Respaldo en fichero de la versión del feed. Ver ``templates_version``."""

    @property
    def templates_dir(self) -> Optional[Path]:
        """Directorio efectivo del **único** árbol de plantillas de Themis.

        Themis tiene una sola copia de las plantillas, y esta propiedad es quien
        dice dónde está. Tres consumidores dependen de esa respuesta y ninguno
        debe resolverla por su cuenta: ``NucleiScanTask`` (que se la pasa al
        binario por ``-templates``), la ingesta de plantillas al runtime propio y
        el censo de ingestibilidad (roadmap Fases R y U4).

        Prioridad, de más explícito a más implícito: 1) ``templatesDir`` en
        SecOpsConfig.json, 2) ``NUCLEI_TEMPLATES_DIR`` en el entorno, 3) las
        ubicaciones por defecto de Nuclei.

        Returns:
            La ruta al árbol, o ``None`` si ninguna candidata existe en disco.
            Nunca una ruta inventada: quien pasa el flag al binario omite
            ``-templates`` y deja que decida él, y quien necesita *leer* las
            plantillas no puede hacer nada y debe poder saberlo.
        """
        configured = self.configured_templates_dir.strip()
        if configured:
            path = Path(configured)
            if path.is_dir():
                return path
            # Una ruta configurada que no existe es un error de despliegue, no
            # algo que deba degradarse en silencio a otra ubicación: se avisa y
            # se sigue buscando, para no dejar un escaneo sin plantillas sin
            # explicación.
            logger.warning(
                "features.themis.scanners.nuclei.templatesDir apunta a '%s', que "
                "no existe; se buscarán las ubicaciones por defecto de Nuclei",
                configured,
            )

        from_environment = (os.environ.get("NUCLEI_TEMPLATES_DIR") or "").strip()
        if from_environment and Path(from_environment).is_dir():
            return Path(from_environment)

        return next((template_location for template_location in _nuclei_default_template_locations() if template_location.is_dir()), None)

    @property
    def templates_version(self) -> str:
        """Versión del feed, usada como respaldo hasta que ``NucleiScanTask``
        capture la real del banner de arranque del binario (ver
        ``NucleiScanManager._execute_scan``, que corrige el ``feed_version`` de
        cada ``Finding`` post-hoc con ese dato, más fiable).

        Prioridad: 1) el fichero que el Dockerfile vuelca al hornear las
        plantillas en build (``/app/resources/nuclei_templates_version.txt``, más
        fiable que un valor estático porque refleja lo que de verdad se
        sincronizó en esa imagen), 2) ``templatesVersion`` en SecOpsConfig.json,
        3) un marcador explícito de "desconocido".
        """
        version_file = (
            Path(get_directory_of(DirectoryType.RESOURCES_THEMIS)).parent
            / "nuclei_templates_version.txt"
        )
        try:
            from_file = version_file.read_text(encoding="utf-8").strip()
            if from_file:
                return f"nuclei-templates-{from_file}"
        except (OSError, IOError):
            pass
        configured = self.configured_templates_version
        return f"nuclei-templates-{configured}" if configured else "nuclei-templates-unknown"


def themis_config() -> ThemisConfig:
    return load_block(ThemisConfig)


def themis_folders() -> ThemisFolders:
    return load_block(ThemisFolders)


def themis_history() -> ThemisHistory:
    return load_block(ThemisHistory)


def themis_task_defaults() -> ThemisTaskDefaults:
    return load_block(ThemisTaskDefaults)


def host_reachability_check() -> HostReachabilityCheck:
    return load_block(HostReachabilityCheck)


def traceroute_config() -> TracerouteConfig:
    return load_block(TracerouteConfig)


def knowledge_base_config() -> KnowledgeBaseConfig:
    return load_block(KnowledgeBaseConfig)


def lybra_config() -> LybraConfig:
    return load_block(LybraConfig)


def lybra_engine_config() -> LybraEngineConfig:
    return load_block(LybraEngineConfig)


@config_block("features.themis.scanners.lybra.evidence")
@dataclass(frozen=True)
class LybraEvidenceConfig:
    """La captura de evidencia cruda por hallazgo (Fase E, L44).

    Un hallazgo dice qué encontró y con qué regla, pero ``feed_version`` +
    ``check_id`` dan reproducibilidad lógica, no guardan lo que el objetivo
    respondió. Esta captura sí: la respuesta HTTP que provocó el hallazgo,
    redactada, con su hash y su fecha, para poder defenderla ante un cliente.
    """

    enabled: bool = True
    """Si se guarda la evidencia de los hallazgos confirmados."""

    max_body_bytes: int = 8192
    """Tope del cuerpo de respuesta que se guarda como evidencia (8
    KiB). Una respuesta más larga se trunca, dejando constancia de cuántos
    bytes se recortaron."""

    retention_days: int = 90
    """Días que se conserva la evidencia antes de purgarla. La
    evidencia crece rápido —KiB por hallazgo, por escaneo, por activo— y necesita
    caducidad desde el primer día. A 0 o menos, retención indefinida (el caso de
    auditoría que exige conservarlo todo)."""


def lybra_evidence_config() -> LybraEvidenceConfig:
    return load_block(LybraEvidenceConfig)


def lybra_ingest_config() -> LybraIngestConfig:
    return load_block(LybraIngestConfig)


@config_block("features.themis.scanners.lybra.credentials")
@dataclass(frozen=True)
class LybraCredentialsConfig:
    """El presupuesto del motor de credenciales por defecto (Fase D, L31).

    Es la única fase del motor que **escribe** en el objetivo — cada intento es
    un login real —, así que el único dial que expone es el que evita que se
    convierta en un ataque de fuerza bruta: cuántas contraseñas se prueban
    contra una misma cuenta antes de rendirse con ella. No hay ``enabled``:
    el motor entero está detrás de la doble puerta de :func:`aggressive
    mode <>` — objetivo autorizado y petición explícita del usuario (L40) —,
    así que un interruptor aparte sería una tercera puerta redundante.
    """

    max_attempts: int = 3
    """Intentos máximos **por cuenta** (no por servicio): tres contraseñas
    distintas contra ``admin`` cuentan tres, no las que además se prueben
    contra ``root`` en el mismo servicio. Es la cuenta, no el servicio, la que
    un proveedor bloquea tras demasiados fallos."""


def lybra_credentials_config() -> LybraCredentialsConfig:
    return load_block(LybraCredentialsConfig)


def nuclei_config() -> NucleiConfig:
    return load_block(NucleiConfig)


# --- Prompts y paletas: parametrizados por herramienta, no por bloque --------
#
# Los cinco escáneres comparten la misma forma (``prompts`` + ``colorPalette``)
# y los consumidores los piden por herramienta, no por nombre fijo: una
# dataclass por escáner solo para esto serían cinco clases idénticas.

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
    # Accepts a ScanType enum member or a plain string; without this, a
    # dict lookup with an Enum instance against string keys always misses
    # and silently returns {} (bug: every caller has been getting the
    # hardcoded per-strategy fallback colors instead of SecOpsConfig's).
    tool_key = tool.value if hasattr(tool, "value") else tool
    return _cfg(f"features.themis.scanners.{tool_key}.colorPalette", {})


@_lazy_load
def get_hygeia_color_palette() -> dict:
    """Paleta del informe de inventario de Hygeia.

    Vive fuera de ``get_tool_color_palette`` porque aquella está parametrizada
    por escáner de Themis y esto no es un escáner. El consumidor conserva sus
    colores de respaldo, así que un JSON sin este bloque imprime igual, solo
    que sin poder retocarse desde la configuración.
    """
    return _cfg("features.hygeia.colorPalette", {})


@_lazy_load
def get_themis_csv_dir() -> str:
    return get_directory_of(DirectoryType.CSV_THEMIS)


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
    global _configs, _configs_mtime
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
    _configs_mtime = _read_mtime(_configs_path)
    _bump_config_generation()
    return new_config


# =============================================================================
# CONFIGURACIÓN GENERAL
# =============================================================================

@config_block("general")
@dataclass(frozen=True)
class GeneralConfig:
    @property
    def public_url(self) -> str:
        """Base URL pública del SPA, usada para construir enlaces en los correos
        salientes (p. ej. el del quiz de una campaña de Aegis).

        Vive exclusivamente en ``PUBLIC_WEB_URL`` (.env) — a propósito no tiene
        respaldo en SecOpsConfig.json, para que la URL pública de un despliegue
        no se pueda fijar editando el fichero versionado. Sin la env var, cae
        al valor de desarrollo de Vite. Siempre sin barra final.
        """
        return os.getenv("PUBLIC_WEB_URL", "http://localhost:5173").rstrip("/")


def general_config() -> GeneralConfig:
    return load_block(GeneralConfig)


@config_block("general.registration")
@dataclass(frozen=True)
class RegistrationConfig:
    """Alta pública de cuentas (§7 de planes-y-organizaciones.md).

    Es de las pocas cosas de la capa comercial que sí son configuración de
    instancia y no de negocio: los planes y sus topes viven en base de datos
    porque los edita el equipo sin desplegar, pero *si esta instalación acepta
    registros de desconocidos* es una decisión del despliegue — un Ellysia
    on-premise dentro de una empresa quiere el grifo cerrado.
    """

    enabled: bool = True
    """Si ``POST /users/register`` acepta altas. Con False responde 403."""

    verification_ttl_hours: int = 48
    """Vigencia del enlace de verificación de correo."""

    invitation_ttl_hours: int = 168
    """Vigencia del enlace de invitación a una organización (una semana)."""

    password_reset_ttl_minutes: int = 30
    """Vigencia del enlace de recuperación de contraseña (media hora).

    Más corto que el de verificación a propósito: es un enlace capaz de
    cambiar una credencial, no solo de confirmar una dirección.
    """


def registration_config() -> RegistrationConfig:
    return load_block(RegistrationConfig)


# =============================================================================
# CONFIGURACIÓN DE SEGURIDAD
# =============================================================================
#
# Las tres ramas de ``general.security`` usan snake_case en el JSON, no la
# convención camelCase del resto: sus claves se pasan tal cual como kwargs a
# argon2 y a PyJWT, y traducirlas solo añadiría una capa que se puede
# desincronizar. De ahí el ``metadata={"key": ...}`` en cada campo.

@config_block("general.security.argon2")
@dataclass(frozen=True)
class Argon2Config:
    """Parámetros de Argon2id para el hash de contraseñas."""

    time_cost: int = field(default=3, metadata={"key": "time_cost"})
    memory_cost: int = field(default=65536, metadata={"key": "memory_cost"})
    parallelism: int = field(default=4, metadata={"key": "parallelism"})

    def as_kwargs(self) -> dict[str, int]:
        """Los tres parámetros tal como los espera ``argon2.PasswordHasher``."""
        return {
            "time_cost": self.time_cost,
            "memory_cost": self.memory_cost,
            "parallelism": self.parallelism,
        }

# TODO: Sería interesante que este campo estuviera en la configuración
_ALLOWED_JWT_ALGORITHMS = frozenset({"HS256", "HS384", "HS512"})


@config_block("general.security.jwt")
@dataclass(frozen=True)
class JwtConfig:
    """Firma y caducidad de los tokens OAuth.

    Los tres valores del fichero son pisables por entorno (útil en contenedores
    / 12-factor); el secreto no está en el fichero en absoluto.
    """

    configured_algorithm: str = field(default="HS256", metadata={"key": "algorithm"})
    configured_access_token_expiry_minutes: float = field(
        default=30, metadata={"key": "access_token_expiry_minutes"}
    )
    configured_refresh_token_expiry_days: float = field(
        default=7, metadata={"key": "refresh_token_expiry_days"}
    )

    @property
    def secret(self) -> str:
        """``JWT_SECRET_KEY``, que vive exclusivamente en .env.

        Raises:
            ValueError: Si falta. Es una propiedad y no un campo justo por esto:
                arrancar sin secreto debe fallar cuando alguien va a firmar un
                token, no al construir el bloque.
        """
        secret = os.getenv("JWT_SECRET_KEY")
        if not secret:
            logger.error("Falta la variable de entorno JWT_SECRET_KEY")
            raise ValueError(
                "Falta la variable de entorno JWT_SECRET_KEY. "
                "Defínela en el archivo .env (es un secreto, no va en "
                "SecOpsConfig.json)."
            )
        return secret

    @property
    def algorithm(self) -> str:
        """Algoritmo de firma, validado contra la familia HS*.

        S8: ``JWT_ALGORITHM`` era un override de entorno sin validar — un typo, o
        un despliegue mal configurado con "none" (o con un algoritmo asimétrico,
        que necesita un par de claves y no un secreto simétrico), rompería la
        verificación de tokens en producción. Firmamos con un único secreto
        simétrico, así que solo HS* tiene sentido aquí.
        """
        algorithm = os.getenv("JWT_ALGORITHM") or self.configured_algorithm
        if algorithm not in _ALLOWED_JWT_ALGORITHMS:
            raise ValueError(
                f"JWT_ALGORITHM '{algorithm}' no permitido. "
                f"Debe ser uno de: {', '.join(sorted(_ALLOWED_JWT_ALGORITHMS))}."
            )
        return algorithm

    @property
    def access_token_expiry_minutes(self) -> float:
        return float(
            os.getenv("ACCESS_TOKEN_EXPIRY_MINUTES")
            or self.configured_access_token_expiry_minutes
        )

    @property
    def refresh_token_expiry_days(self) -> float:
        return float(
            os.getenv("REFRESH_TOKEN_EXPIRY_DAYS")
            or self.configured_refresh_token_expiry_days
        )


@config_block("general.security.mfa")
@dataclass(frozen=True)
class MfaConfig:
    """Segundo factor: TOTP y códigos de recuperación."""

    issuer: str = "Ellysia"
    """Nombre que muestra la app de autenticación."""

    challenge_expiry_minutes: int = field(
        default=5, metadata={"key": "challenge_expiry_minutes"}
    )
    max_challenge_attempts: int = field(
        default=5, metadata={"key": "max_challenge_attempts"}
    )
    recovery_codes_count: int = field(
        default=10, metadata={"key": "recovery_codes_count"}
    )
    notice_interval_days: int = field(
        default=30, metadata={"key": "notice_interval_days"}
    )

    @property
    def encryption_key(self) -> str:
        """Clave Fernet con la que se cifra en reposo el secreto TOTP.

        Vive solo en .env, igual que ``JWT_SECRET_KEY``: a diferencia del resto
        de secretos de Acheron, el servidor sí necesita poder leer este valor
        para calcular el TOTP vigente y verificarlo.
        """
        return get_encryption_key("mfa")


def argon2_config() -> Argon2Config:
    return load_block(Argon2Config)


def jwt_config() -> JwtConfig:
    return load_block(JwtConfig)


def mfa_config() -> MfaConfig:
    return load_block(MfaConfig)


# =============================================================================
# CONFIGURACIÓN DE INFRAESTRUCTURA
# =============================================================================
#
# Igual que en seguridad, estas claves son snake_case en el JSON porque se pasan
# tal cual a SQLAlchemy y a redis-py.

@config_block("infrastructure.database")
@dataclass(frozen=True)
class DatabaseConfig:
    """Ajustes no secretos de SQLAlchemy. Las credenciales van en .env."""

    isolation_level: str = field(
        default="READ COMMITTED", metadata={"key": "isolation_level"}
    )
    pool_size: int = field(default=10, metadata={"key": "pool_size"})
    max_overflow: int = field(default=20, metadata={"key": "max_overflow"})
    pool_timeout: int = field(default=30, metadata={"key": "pool_timeout"})

    def pool_kwargs(self) -> dict[str, int]:
        """El pool tal como lo espera ``create_engine``."""
        return {
            "pool_size": self.pool_size,
            "max_overflow": self.max_overflow,
            "pool_timeout": self.pool_timeout,
        }


@config_block("infrastructure.redis")
@dataclass(frozen=True)
class RedisConfig:
    """Conexión a Redis: lo no secreto del fichero, el resto del entorno."""

    configured_host: str = field(default="localhost", metadata={"key": "host"})
    configured_port: int = field(default=6379, metadata={"key": "port"})
    configured_db: int = field(default=0, metadata={"key": "db"})

    socket_connect_timeout: int = field(
        default=2, metadata={"key": "socket_connect_timeout"}
    )

    @property
    def host(self) -> str:
        return os.getenv("REDIS_HOST", self.configured_host)

    @property
    def port(self) -> int:
        return int(os.getenv("REDIS_PORT", str(self.configured_port)))

    @property
    def db(self) -> int:
        return int(os.getenv("REDIS_DB", str(self.configured_db)))

    @property
    def password(self) -> Optional[str]:
        """``REDIS_PASSWORD``, o ``None`` si la instancia no lleva contraseña."""
        return os.getenv("REDIS_PASSWORD", "") or None

    def connection_kwargs(self) -> dict:
        """La conexión tal como la esperan ``redis.Redis`` y RQ."""
        return {
            "host": self.host,
            "port": self.port,
            "db": self.db,
            "socket_connect_timeout": self.socket_connect_timeout,
            "password": self.password,
        }


@config_block("infrastructure.taskqueue")
@dataclass(frozen=True)
class TaskQueueConfig:
    """Cola de trabajos sobre RQ."""

    configured_max_workers: int = field(default=4, metadata={"key": "max_workers"})

    history_ttl_seconds: int = field(
        default=3600, metadata={"key": "history_ttl_seconds"}
    )
    history_max_items: int = field(default=200, metadata={"key": "history_max_items"})

    @property
    def max_workers(self) -> int:
        """Procesos worker a levantar.

        ``TASKQUEUE_MAX_WORKERS`` manda sobre el fichero. Antes esto se resolvía
        escribiendo el valor del entorno *dentro* del dict cacheado de la
        configuración, con lo que se colaba en la respuesta de ``GET /system`` y
        acababa persistido en el fichero al primer guardado desde el SPA.
        """
        return int(os.getenv("TASKQUEUE_MAX_WORKERS") or self.configured_max_workers)


def database_config() -> DatabaseConfig:
    return load_block(DatabaseConfig)


def redis_config() -> RedisConfig:
    return load_block(RedisConfig)


def taskqueue_config() -> TaskQueueConfig:
    return load_block(TaskQueueConfig)


# =============================================================================
# CONFIGURACIÓN DE HYGEIA
# =============================================================================

@config_block("features.hygeia.limits")
@dataclass(frozen=True)
class HygeiaLimits:  # pylint: disable=too-many-instance-attributes
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
    """Cuánto puede ADELANTARSE el ``collectedAt`` del agente al reloj del servidor (§16.3).

    Solo acota el futuro. Un heartbeat fechado por delante del servidor no
    tiene explicación legítima —ningún retardo de red produce eso— así que un
    margen corto sigue detectando un reloj mal puesto en vez de tragárselo en
    silencio. Para el pasado manda ``max_backfill_sec``, que es otra cosa.
    """

    max_backfill_sec: int = 86400
    """Cuánto puede ATRASARSE el ``collectedAt`` respecto al servidor (§16.3).

    Un heartbeat viejo sí tiene explicación legítima, y es la razón de ser del
    buffer en disco del agente: si el backend estuvo caído, el agente guarda
    los heartbeats y los entrega al recuperar la conexión. Con la ventana
    simétrica de 300 s anterior ese buffer era decorativo — el agente retiene
    horas de histórico y el servidor rechazaba todo lo de más de cinco
    minutos, así que una caída larga se perdía entera pese a estar guardada.

    Ampliarlo no reabre el riesgo del §16.3 (una clave robada inyectando
    snapshots que envenenen el orden de la serie o tapen un hueco de
    presencia): tanto el histórico como el detector de presencia se ordenan
    por ``received_at``, el reloj del SERVIDOR, nunca por este campo.
    """

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

    energy_price_per_kwh: float = 0.15
    """Precio de la electricidad usado para convertir kWh en coste (Fase 3).

    Clave global y no por activo ni por agente: el precio depende del país,
    el contrato y la hora del día, no de la máquina que se mide, así que
    meterlo en el agente obligaría a reconfigurar cada host del parque para
    cambiar una tarifa. Cubre el caso real de una única instalación con una
    tarifa; un ámbito por organización, si hiciera falta, se resolvería
    consultando la organización y cayendo a este valor cuando no tenga uno
    propio, sin tocar esta clave.
    """

    energy_price_currency: str = "EUR"
    """Moneda de ``energy_price_per_kwh``.

    Un número de euros sin decir que son euros es exactamente el tipo de
    dato que se malinterpreta en la primera instalación fuera de la zona
    euro.
    """

    min_agent_version: str = "0.0.0"
    """Versión mínima de agente que no se marca como desactualizada en la SPA.

    Es un aviso, no una política de compatibilidad: un agente por debajo de
    este suelo sigue latiendo con normalidad, solo se marca en la lista de
    activos. El formato exigido es estrictamente ``X.Y.Z...`` (enteros
    separados por puntos, ver ``services/agent_freshness.py``); tanto este
    valor como el ``agent_version`` de cada activo que no encajen en ese
    formato se resuelven a "no se sabe" y no producen ningún aviso, nunca un
    falso "desactualizado".

    El valor por defecto (``"0.0.0"``) no marca ningún agente real: la
    funcionalidad no tiene efecto hasta que un operador fija un suelo de
    verdad, igual que el resto de umbrales de Hygeia no sorprenden a un
    despliegue nuevo con avisos que nadie pidió.
    """


def hygeia_config() -> HygeiaConfig:
    return load_block(HygeiaConfig)


def hygeia_limits() -> HygeiaLimits:
    return load_block(HygeiaLimits)


# =============================================================================
# CONFIGURACIÓN DE IRIS
# =============================================================================

@config_block("features.iris")
@dataclass(frozen=True)
class IrisConfig:  # pylint: disable=too-many-instance-attributes
    """Análisis anti-phishing de correo."""

    legitimate_threshold: float = 80
    """Escala sustractiva 0–100: a partir de aquí el veredicto es Legítimo
    (ver ``IrisManager._aggregate_score``)."""

    suspicious_threshold: float = 55
    """Por debajo de ``legitimate_threshold`` y a partir de aquí, Sospechoso;
    por debajo de aquí, Phishing."""

    min_headers: int = 2
    """Cabeceras mínimas para considerar analizable un mensaje."""

    max_message_bytes: int = 10 * 1024 * 1024
    """Tamaño máximo de un ``.eml`` aceptado (C4).

    ``AnalyzeRequestSchema`` no tenía ningún tope: un correo de varios MB con
    adjuntos entraba entero en una columna Text y se re-parseaba —decodificando
    base64 incluido— en cada lectura posterior (``get_analysis_results``,
    ``path``, ``iocs``). 10 MB cubre de sobra un correo real con adjuntos y a la
    vez acota el coste de ese re-parseo.
    """

    max_connections_per_user: int = 5
    """Máximo de cuentas de correo que un usuario puede conectar a la vez."""

    poll_interval_minutes: int = 5
    """Intervalo (minutos) del scheduler que sondea las conexiones activas."""

    max_ingested_per_day: int = 200
    """Tope diario de análisis auto-ingeridos, **por conexión** (no global).

    Una conexión mal configurada (carpeta ruidosa, bucle de reenvíos) no debe
    poder generar análisis sin límite — ver roadmap-ellysia.md §8.1.
    """

    prompts: dict = field(default_factory=dict)
    """Prompts de ``IrisAIWriter`` (IA1): ``summary.{system,userTemplate}``."""


def iris_config() -> IrisConfig:
    return load_block(IrisConfig)


# --- Datasets y pesos: buscados por clave, no por campo ---------------------
#
# Ninguno de los dos encaja en un bloque: los datasets son dos docenas de listas
# que solo ``iris/services/shared.py`` consume, y los pesos de scoring son un
# mapa abierto donde cada regla trae su propio default calibrado. En ambos casos
# el consumidor sabe qué clave quiere, y declararlas como campos obligaría a
# tocar este módulo cada vez que se añade una regla.

@_lazy_load
def get_iris_data(key: str):
    """Dataset de detección desde ``features.iris.data.<key>`` (o None si falta).

    Los datasets (marcas, dominios, keywords, extensiones…) viven en el bloque
    ``features.iris.data``; los defaults de respaldo están en
    ``src/modules/features/iris/services/shared.py``, que es el único consumidor
    previsto.
    """
    return _cfg(f"features.iris.data.{key}")


@_lazy_load
def get_iris_scoring_weight(weight_key: str, default: float) -> float:
    """Peso de scoring configurable de una regla de Iris (recalibración §19/S6).

    ``features.iris.scoring.<weight_key>`` puede pisar la magnitud de
    penalización que una regla define en código sin necesidad de redeploy. El
    propio ``default`` que cada llamada pasa (el valor calibrado por el consejo,
    ver STUDY.md) es el que se usa si la clave no está en la config, así que el
    comportamiento no cambia hasta que alguien la añade explícitamente.
    """
    return _cfg(f"features.iris.scoring.{weight_key}", default, float)


# =============================================================================
# CONECTOR DE BUZÓN DE IRIS (Fase 3-4 del plan mailbox-connector)
# =============================================================================
# Los ajustes del conector (cuotas, cadencia de sondeo) viven en ``IrisConfig``;
# aquí solo quedan las credenciales OAuth de las apps, que son secretos de .env.

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
# ENTORNO
# =============================================================================

def is_development() -> bool:
    """Indica si la aplicación está en modo desarrollo."""
    return os.environ.get("FLASK_ENV", "production") == "development"
