"""Tests de la *forma* de SecOpsConfig.json.

Existen por un modo de fallo concreto y silencioso: ``_cfg()`` devuelve el
default cuando la ruta no resuelve, así que un prefijo mal escrito tras mover
una clave no rompe nada — simplemente hace que toda la configuración del
bloque deje de aplicarse, en silencio y en producción.

Dos capas, y las dos hacen falta:

1. ``test_root_layout`` / ``test_second_level_layout`` fijan el árbol. Si
   alguien añade un bloque nuevo en la raíz, este test le obliga a decidir
   conscientemente en qué rama va.
2. ``test_getter_reads_its_documented_path`` ata cada getter a su ruta del
   JSON. No compara el valor leído contra el fichero: eso no sirve, porque
   cuando el default del código coincide con el valor configurado (pasa en la
   mitad de los getters — ``nuclei.rateLimit`` es 150 en los dos sitios) una
   ruta rota devuelve el default y la comparación pasa igualmente. En vez de
   eso inyecta un valor centinela **en esa ruta concreta** y comprueba que el
   getter se entera: si el getter mira a otro sitio, no lo ve y el test cae.
"""

import copy
import dataclasses
import json
from pathlib import Path

import pytest

import src.modules.system.config_reading as CR

pytestmark = pytest.mark.unit


@pytest.fixture(scope="module")
def raw_config() -> dict:
    """El SecOpsConfig.json real del repo, leído sin pasar por el módulo."""
    config_path = Path(__file__).resolve().parents[2] / "SecOpsConfig.json"
    return json.loads(config_path.read_text(encoding="utf-8"))


def _value_at(config: dict, dotted_path: str):
    """Lee una ruta con puntos, fallando si algún tramo no existe."""
    node = config
    for key in dotted_path.split("."):
        assert isinstance(node, dict) and key in node, (
            f"la ruta '{dotted_path}' no existe en SecOpsConfig.json"
        )
        node = node[key]
    return node


# =============================================================================
# EL ÁRBOL
# =============================================================================

def test_root_layout(raw_config):
    """La raíz tiene exactamente cinco entradas, y ni una más."""
    assert set(raw_config) == {
        "appVersion", "general", "infrastructure", "tools", "features",
    }


@pytest.mark.parametrize("branch, expected_children", [
    ("general",        {"publicUrl", "directories", "security"}),
    ("general.security", {"argon2", "jwt", "mfa"}),
    ("infrastructure", {"database", "redis", "taskqueue"}),
    ("tools",          {"scribe", "herald"}),
    ("features",       {"themis", "aegis", "iris", "hygeia"}),
])
def test_second_level_layout(raw_config, branch, expected_children):
    assert set(_value_at(raw_config, branch)) == expected_children


def test_every_scanner_has_its_own_block(raw_config):
    """``THEMIS_SCANNERS`` y el JSON no pueden divergir: si divergen,
    ``get_prompts_config`` devuelve ``{}`` para el que falte y el informe sale
    con los colores y prompts de respaldo sin que nadie se entere."""
    scanners = _value_at(raw_config, "features.themis.scanners")
    assert set(scanners) == set(CR.THEMIS_SCANNERS)
    for name, block in scanners.items():
        assert "prompts" in block, f"al escáner '{name}' le falta 'prompts'"
        assert "colorPalette" in block, f"al escáner '{name}' le falta 'colorPalette'"


# =============================================================================
# GETTERS ↔ RUTAS
# =============================================================================

# Un caso por rama del árbol: si una rama entera se mueve sin actualizar los
# getters, al menos uno de estos casos cae.
GETTERS_AND_PATHS = [
    (CR.get_app_version,                    "appVersion"),
    (CR.get_public_web_url,                 "general.publicUrl"),
    (CR.get_argon2_config,                  "general.security.argon2"),
    (CR.get_db_isolation_level,             "infrastructure.database.isolation_level"),
    (CR.get_redis_config,                   "infrastructure.redis.socket_connect_timeout"),
]


def _distinguishable_from(value):
    """Un valor del mismo tipo que ``value`` pero imposible de confundir con él."""
    if isinstance(value, bool):
        return not value
    if isinstance(value, int):
        return value + 7
    if isinstance(value, float):
        return value + 7.0
    if isinstance(value, str):
        return value + "-centinela"
    if isinstance(value, list):
        return value + ["centinela"]
    if isinstance(value, dict):
        return {**value, "centinela": "centinela"}
    raise AssertionError(f"tipo sin centinela definido: {type(value)}")


def _with_sentinel_at(config: dict, dotted_path: str):
    """Copia de ``config`` con un centinela plantado en ``dotted_path``."""
    probed = copy.deepcopy(config)
    *branch_keys, leaf_key = dotted_path.split(".")
    node = probed
    for key in branch_keys:
        node = node[key]
    node[leaf_key] = _distinguishable_from(node[leaf_key])
    return probed


# Getters con override por entorno: con la env var puesta (y ``PUBLIC_WEB_URL``
# lo está en cualquier .env real) el fichero no se llega a leer, así que el
# centinela sería invisible y el test fallaría sin que nada esté roto.
ENV_OVERRIDES = {
    "get_public_web_url": ("PUBLIC_WEB_URL",),
    "get_redis_config":   ("REDIS_HOST", "REDIS_PORT", "REDIS_DB"),
}


@pytest.mark.parametrize(
    "getter, dotted_path", GETTERS_AND_PATHS, ids=[g.__name__ for g, _ in GETTERS_AND_PATHS]
)
def test_getter_reads_its_documented_path(raw_config, getter, dotted_path, monkeypatch):
    for env_var in ENV_OVERRIDES.get(getter.__name__, ()):
        monkeypatch.delenv(env_var, raising=False)
    baseline = getter()
    monkeypatch.setattr(CR, "_configs", _with_sentinel_at(raw_config, dotted_path))

    assert getter() != baseline, (
        f"{getter.__name__} no reaccionó a un cambio en '{dotted_path}': "
        "está leyendo otra ruta (y devolviendo su valor por defecto)"
    )


@pytest.mark.parametrize("tool_accessor, dotted_path", [
    (CR.scribe_config, "tools.scribe.modules.themis"),
    (CR.herald_config, "tools.herald.modules.aegis"),
])
def test_strategy_resolution_reads_the_tools_branch(
    raw_config, tool_accessor, dotted_path, monkeypatch
):
    """``strategy_for`` resuelve el override por módulo desde la rama correcta."""
    module_name = dotted_path.rsplit(".", 1)[1]
    baseline = tool_accessor().strategy_for(module_name)
    monkeypatch.setattr(CR, "_configs", _with_sentinel_at(raw_config, dotted_path))

    assert tool_accessor().strategy_for(module_name) != baseline


# =============================================================================
# BLOQUES (dataclasses)
# =============================================================================

# Cada bloque registrado, con el accesor por el que lo piden los consumidores.
CONFIG_BLOCKS = [
    (CR.HygeiaConfig, CR.hygeia_config),
    (CR.HygeiaLimits, CR.hygeia_limits),
    (CR.ThemisConfig, CR.themis_config),
    (CR.ThemisFolders, CR.themis_folders),
    (CR.ThemisHistory, CR.themis_history),
    (CR.ThemisTaskDefaults, CR.themis_task_defaults),
    (CR.HostReachabilityCheck, CR.host_reachability_check),
    (CR.TracerouteConfig, CR.traceroute_config),
    (CR.KnowledgeBaseConfig, CR.knowledge_base_config),
    (CR.OpenVASConfig, CR.openvas_config),
    (CR.OpenVASToolConfigs, CR.openvas_tool_configs),
    (CR.LybraConfig, CR.lybra_config),
    (CR.LybraIngestConfig, CR.lybra_ingest_config),
    (CR.NucleiConfig, CR.nuclei_config),
    (CR.AegisConfig, CR.aegis_config),
    (CR.IrisConfig, CR.iris_config),
    (CR.ScribeConfig, CR.scribe_config),
    (CR.HeraldConfig, CR.herald_config),
]


def expected_key(field_info) -> str:
    """La clave del JSON que le corresponde a un campo del bloque."""
    return field_info.metadata.get("key") or CR._to_camel_case(field_info.name)


@pytest.mark.parametrize(
    "block_type, _accessor", CONFIG_BLOCKS, ids=[b.__name__ for b, _ in CONFIG_BLOCKS]
)
def test_block_covers_its_branch_exactly(raw_config, block_type, _accessor):
    """Los campos del bloque y las claves de su rama son el mismo conjunto.

    Cierra el hueco que el test de centinela no puede cerrar solo: si un campo
    se llamara mal, su clave no existiría en el JSON y el centinela nunca se
    plantaría — el test pasaría sin probar nada. Comparando conjuntos, un campo
    huérfano (default silencioso) y una clave del JSON que nadie lee (config
    muerta) se ven los dos.

    Los campos marcados ``optional`` quedan fuera: son los que a propósito no
    están en el fichero, porque son secretos y su sitio es el ``.env``.
    """
    branch = _value_at(raw_config, block_type.__config_path__)
    declared = {
        expected_key(f) for f in dataclasses.fields(block_type)
        if not f.metadata.get("optional")
    }
    configured = {key for key, value in branch.items() if not isinstance(value, dict)}
    # Las sub-ramas (dicts) o son un campo del bloque o son otro bloque aparte.
    configured |= {key for key in branch if key in declared}

    assert declared == configured, (
        f"campos sin clave en el JSON: {sorted(declared - configured)}; "
        f"claves del JSON que ningún campo lee: {sorted(configured - declared)}"
    )


@pytest.mark.parametrize("snake_case_name, expected", [
    ("max_body_bytes",   "maxBodyBytes"),
    ("thresholds",       "thresholds"),
    ("clock_skew_sec",   "clockSkewSec"),
    ("min_interval_sec", "minIntervalSec"),
])
def test_to_camel_case(snake_case_name, expected):
    assert CR._to_camel_case(snake_case_name) == expected

BLOCK_FIELDS = [
    (block_type, accessor, field_info)
    for block_type, accessor in CONFIG_BLOCKS
    for field_info in dataclasses.fields(block_type)
]


@pytest.mark.parametrize(
    "block_type, accessor, field_info", BLOCK_FIELDS,
    ids=[f"{b.__name__}.{f.name}" for b, _, f in BLOCK_FIELDS],
)
def test_block_field_maps_to_its_json_key(raw_config, block_type, accessor, field_info, monkeypatch):
    """Cada campo del bloque lee la clave que le toca, o documenta que no está.

    La traducción ``snake_case`` → ``camelCase`` es automática, y ahí está el
    riesgo: un campo mal nombrado no falla, se queda con su default en
    silencio. Si la clave existe en el JSON, plantamos un centinela y exigimos
    que el bloque lo vea; si no existe, comprobamos que efectivamente cae al
    default declarado — que es información útil, no un fallo.
    """
    dotted_path = f"{block_type.__config_path__}.{expected_key(field_info)}"
    declared_default = (
        field_info.default_factory() if field_info.default is dataclasses.MISSING
        else field_info.default
    )

    try:
        _value_at(raw_config, dotted_path)
    except AssertionError:
        assert getattr(accessor(), field_info.name) == declared_default, (
            f"'{dotted_path}' no está en SecOpsConfig.json pero el bloque "
            f"tampoco devuelve el default declarado"
        )
        return

    baseline = accessor()
    monkeypatch.setattr(CR, "_configs", _with_sentinel_at(raw_config, dotted_path))

    assert accessor() != baseline, (
        f"{block_type.__name__}.{field_info.name} no reaccionó a un cambio en "
        f"'{dotted_path}': el campo está leyendo otra clave"
    )


def test_blocks_are_frozen_and_cached():
    """El bloque es inmutable (nadie puede pisar la config desde un consumidor)
    y se reutiliza mientras la config no cambie."""
    limits = CR.hygeia_limits()
    assert CR.hygeia_limits() is limits
    with pytest.raises(dataclasses.FrozenInstanceError):
        limits.max_body_bytes = 1


def test_blocks_rebuild_when_the_config_changes(raw_config, monkeypatch):
    """La caché se invalida sola al cambiar ``_configs``.

    Es el punto delicado de todo esto: la config es mutable en caliente
    (``PUT /system`` → ``reload()``), y un bloque cacheado de por vida serviría
    valores rancios después de guardar.
    """
    before = CR.hygeia_limits()
    monkeypatch.setattr(
        CR, "_configs", _with_sentinel_at(raw_config, "features.hygeia.limits.maxProcesses")
    )
    after = CR.hygeia_limits()

    assert after is not before
    assert after.max_processes == before.max_processes + 7


def test_taskqueue_config_reads_the_infrastructure_branch(raw_config, monkeypatch):
    monkeypatch.delenv("TASKQUEUE_MAX_WORKERS", raising=False)
    assert CR.get_taskqueue_config() == _value_at(raw_config, "infrastructure.taskqueue")


def test_oauth_config_reads_the_security_branch(raw_config, monkeypatch):
    """``general.security.jwt`` aparte: sus tres valores son pisables por
    entorno, y con el override puesto el centinela del fichero no se vería."""
    for env_var in ("JWT_ALGORITHM", "ACCESS_TOKEN_EXPIRY_MINUTES", "REFRESH_TOKEN_EXPIRY_DAYS"):
        monkeypatch.delenv(env_var, raising=False)
    baseline = CR.get_oauth_config()
    monkeypatch.setattr(
        CR, "_configs",
        _with_sentinel_at(raw_config, "general.security.jwt.access_token_expiry_minutes"),
    )

    assert CR.get_oauth_config() != baseline


# =============================================================================
# DIRECTORIOS
# =============================================================================

@pytest.mark.parametrize("directory_type", list(CR.DirectoryType))
def test_every_directory_type_resolves(directory_type, monkeypatch):
    """Cada miembro del enum debe encontrar su rama en el JSON.

    ``_lookup_raw_path`` sí lanza cuando no encuentra la clave (a diferencia de
    ``_cfg``), y traduce ``DirectoryType`` → ``features.<módulo>.directories``,
    que es la parte que la reestructuración movió. Sin las env vars de por
    medio, para probar el camino del fichero y no el del entorno.
    """
    for env_var in set(CR._DIRECTORY_ENV_MAPPING.values()):
        monkeypatch.delenv(env_var, raising=False)

    assert CR.get_directory_of(directory_type)
