"""Tests unitarios del lector de configuración."""

import pytest

import src.modules.system.config_reading as CR

pytestmark = pytest.mark.unit


def test_redis_config_prefers_the_environment(monkeypatch):
    monkeypatch.setenv("REDIS_HOST", "redis.internal")
    monkeypatch.setenv("REDIS_PORT", "6380")
    monkeypatch.setenv("REDIS_DB", "2")
    monkeypatch.delenv("REDIS_PASSWORD", raising=False)

    config = CR.redis_config()
    assert config.host == "redis.internal"
    assert config.port == 6380
    assert config.db == 2
    assert config.password is None


def test_redis_connection_kwargs_honour_the_configured_connect_timeout(monkeypatch):
    """El factory del taskqueue tiene que leer el timeout del fichero.

    Hardcodeaba un 5 que ignoraba `infrastructure.redis.socket_connect_timeout`
    y dejaba muerto el valor que sí usa ping_redis().
    """
    from src.modules.system.taskqueue.connection import RedisConnectionFactory

    monkeypatch.setattr(
        CR, "redis_config",
        lambda: CR.RedisConfig(socket_connect_timeout=7),
    )

    kwargs = RedisConnectionFactory._kwargs()
    assert kwargs["socket_connect_timeout"] == 7
    # El de lectura no se aplica al worker: RQ saca jobs con BLPOP.
    assert kwargs["socket_timeout"] == 5
    assert "socket_timeout" not in RedisConnectionFactory._kwargs(blocking=True)


def test_jwt_config_from_env():
    config = CR.jwt_config()
    assert config.secret == "test-secret-key-not-for-production"
    assert config.algorithm == "HS256"
    assert config.access_token_expiry_minutes == 30.0
    assert config.refresh_token_expiry_days == 7.0


def test_jwt_secret_missing_var_raises(monkeypatch):
    monkeypatch.delenv("JWT_SECRET_KEY", raising=False)
    with pytest.raises(ValueError):
        _ = CR.jwt_config().secret


def test_jwt_algorithm_rejects_disallowed_algorithm(monkeypatch):
    # S8: sin allowlist, un JWT_ALGORITHM mal puesto (typo, "none", un
    # algoritmo asimétrico que necesita un par de claves) pasaba silencioso.
    monkeypatch.setenv("JWT_ALGORITHM", "none")
    with pytest.raises(ValueError):
        _ = CR.jwt_config().algorithm


def test_jwt_algorithm_accepts_allowed_hs_algorithm(monkeypatch):
    monkeypatch.setenv("JWT_ALGORITHM", "HS512")
    assert CR.jwt_config().algorithm == "HS512"


def test_general_config_public_url_from_env(monkeypatch):
    monkeypatch.setenv("PUBLIC_WEB_URL", "https://ellysia.example/")
    assert CR.general_config().public_url == "https://ellysia.example"


def test_general_config_public_url_falls_back_without_env(monkeypatch):
    """Sin PUBLIC_WEB_URL cae al valor de desarrollo de Vite: no hay respaldo
    en SecOpsConfig.json, publicUrl solo se configura por .env."""
    monkeypatch.delenv("PUBLIC_WEB_URL", raising=False)
    assert CR.general_config().public_url == "http://localhost:5173"


def test_taskqueue_max_workers_does_not_leak_into_the_cached_config(monkeypatch):
    """El override de entorno no debe escribirse dentro de la config cargada.

    Antes se resolvía asignándolo al dict cacheado, con lo que un valor que solo
    existía en el entorno aparecía en ``GET /system`` y acababa persistido en
    SecOpsConfig.json al primer guardado desde el SPA.
    """
    monkeypatch.setenv("TASKQUEUE_MAX_WORKERS", "99")

    assert CR.taskqueue_config().max_workers == 99
    assert CR.get_full_config()["infrastructure"]["taskqueue"]["max_workers"] != 99


def test_is_development_reflects_flask_env(monkeypatch):
    monkeypatch.setenv("FLASK_ENV", "development")
    assert CR.is_development() is True
    monkeypatch.setenv("FLASK_ENV", "production")
    assert CR.is_development() is False


def test_get_app_context_happy_path(monkeypatch):
    monkeypatch.setenv("CREATE_DATABASE", "false")
    monkeypatch.setenv("DEBUG", "false")
    monkeypatch.setenv("HOST", "127.0.0.1")
    monkeypatch.setenv("PORT", "5000")
    monkeypatch.setenv("SHUTDOWN_TIMEOUT", "30")

    ctx = CR.get_app_context()
    assert ctx.create_database is False
    assert ctx.debug is False
    assert ctx.port == 5000


def test_get_app_context_uses_false_defaults_when_envs_absent(monkeypatch):
    """Con DEBUG y CREATE_DATABASE sin definir, get_app_context() usa False por defecto."""
    monkeypatch.delenv("DEBUG", raising=False)
    monkeypatch.delenv("CREATE_DATABASE", raising=False)
    ctx = CR.get_app_context()
    assert ctx.debug is False
    assert ctx.create_database is False


# --------------------------------- Nuclei: el único árbol de plantillas (U4/R)
#
# ``templates_dir`` es una propiedad pura dado el campo del bloque, así que
# estos tests construyen el ``NucleiConfig`` a mano en vez de monkeypatchear el
# lector de configuración: lo que se prueba es la cadena de prioridad
# (fichero → entorno → ubicaciones por defecto), no de dónde salió el valor.

def test_nuclei_templates_dir_prefers_the_configured_path(tmp_path):
    configured = tmp_path / "configured"
    configured.mkdir()

    config = CR.NucleiConfig(configured_templates_dir=str(configured))

    assert config.templates_dir == configured


def test_nuclei_templates_dir_falls_back_to_the_environment(tmp_path, monkeypatch):
    from_env = tmp_path / "from-env"
    from_env.mkdir()
    monkeypatch.setenv("NUCLEI_TEMPLATES_DIR", str(from_env))

    assert CR.NucleiConfig().templates_dir == from_env


def test_nuclei_templates_dir_falls_back_to_the_nuclei_default(tmp_path, monkeypatch):
    """The Docker image's real case: nothing configured, templates under $HOME."""
    default_location = tmp_path / ".local" / "nuclei-templates"
    default_location.mkdir(parents=True)
    monkeypatch.delenv("NUCLEI_TEMPLATES_DIR", raising=False)
    monkeypatch.setattr("pathlib.Path.home", classmethod(lambda cls: tmp_path))

    assert CR.NucleiConfig().templates_dir == default_location


def test_nuclei_templates_dir_is_none_when_nothing_resolves(tmp_path, monkeypatch):
    """A missing tree is reported as such, never as an invented path."""
    monkeypatch.delenv("NUCLEI_TEMPLATES_DIR", raising=False)
    monkeypatch.setattr("pathlib.Path.home", classmethod(lambda cls: tmp_path / "empty"))

    assert CR.NucleiConfig().templates_dir is None


def test_nuclei_templates_dir_ignores_a_configured_path_that_does_not_exist(tmp_path, monkeypatch):
    """A deployment typo must not silently look like a working template tree."""
    monkeypatch.delenv("NUCLEI_TEMPLATES_DIR", raising=False)
    monkeypatch.setattr("pathlib.Path.home", classmethod(lambda cls: tmp_path / "empty"))

    config = CR.NucleiConfig(configured_templates_dir=str(tmp_path / "does-not-exist"))

    assert config.templates_dir is None
