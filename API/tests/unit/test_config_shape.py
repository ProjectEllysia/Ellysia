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
    (CR.get_hygeia_heartbeat_interval_sec,  "features.hygeia.heartbeatIntervalSec"),
    (CR.get_hygeia_retention_cron,          "features.hygeia.retentionCron"),
    (CR.get_hygeia_thresholds,              "features.hygeia.thresholds"),
    (CR.get_hygeia_max_body_bytes,          "features.hygeia.limits.maxBodyBytes"),
    (CR.get_iris_legitimate_threshold,      "features.iris.legitimateThreshold"),
    (CR.get_iris_max_ingested_per_day,      "features.iris.maxIngestedPerDay"),
    (CR.get_iris_prompts,                   "features.iris.prompts"),
    (CR.get_aegis_brands,                   "features.aegis.brands"),
    (CR.get_aegis_prompts,                  "features.aegis.prompts"),
    (CR.get_themis_traceroute_max_hops,     "features.themis.traceroute.maxHops"),
    (CR.get_host_reachability_check_port,   "features.themis.hostReachabilityCheck.port"),
    (CR.get_themis_default_folder_name,     "features.themis.folders.defaultFolderName"),
    (CR.get_themis_history_size,            "features.themis.history.maxScans"),
    (CR.get_kb_sources,                     "features.themis.kb.sources"),
    (CR.get_kb_sync_cron,                   "features.themis.kb.syncCron"),
    (CR.get_nuclei_rate_limit,              "features.themis.scanners.nuclei.rateLimit"),
    (CR.get_nuclei_default_severities,      "features.themis.scanners.nuclei.defaultSeverities"),
    (CR.get_openvas_task_timeout,           "features.themis.scanners.openvas.timeout"),
    (CR.get_openvas_scan_configs,           "features.themis.scanners.openvas.toolConfigs.scanConfigs"),
    (CR.get_openvas_port_list,              "features.themis.scanners.openvas.toolConfigs.portList"),
    (CR.get_lybra_ingest_max_checks,        "features.themis.scanners.lybra.ingest.maxChecks"),
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


@pytest.mark.parametrize("strategy_getter, dotted_path", [
    (CR.get_ai_strategy_for,    "tools.scribe.modules.themis"),
    (CR.get_email_strategy_for, "tools.herald.modules.aegis"),
])
def test_strategy_resolution_reads_the_tools_branch(
    raw_config, strategy_getter, dotted_path, monkeypatch
):
    module_name = dotted_path.rsplit(".", 1)[1]
    baseline = strategy_getter(module_name)
    monkeypatch.setattr(CR, "_configs", _with_sentinel_at(raw_config, dotted_path))

    assert strategy_getter(module_name) != baseline


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
