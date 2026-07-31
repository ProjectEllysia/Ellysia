"""Tests unitarios del lector de configuración."""

import pytest

import src.modules.system.config_reading as CR

pytestmark = pytest.mark.unit


def test_get_redis_config_reads_env(monkeypatch):
    monkeypatch.setenv("REDIS_HOST", "redis.internal")
    monkeypatch.setenv("REDIS_PORT", "6380")
    monkeypatch.setenv("REDIS_DB", "2")
    monkeypatch.delenv("REDIS_PASSWORD", raising=False)

    cfg = CR.get_redis_config()
    assert cfg["host"] == "redis.internal"
    assert cfg["port"] == 6380
    assert cfg["db"] == 2
    assert cfg["password"] is None


def test_get_oauth_config_from_env():
    access, refresh, secret, algorithm = CR.get_oauth_config()
    assert secret == "test-secret-key-not-for-production"
    assert algorithm == "HS256"
    assert access == 30.0
    assert refresh == 7.0


def test_get_oauth_config_missing_var_raises(monkeypatch):
    monkeypatch.delenv("JWT_SECRET_KEY", raising=False)
    with pytest.raises(ValueError):
        CR.get_oauth_config()


def test_get_oauth_config_rejects_disallowed_algorithm(monkeypatch):
    # S8: sin allowlist, un JWT_ALGORITHM mal puesto (typo, "none", un
    # algoritmo asimétrico que necesita un par de claves) pasaba silencioso.
    monkeypatch.setenv("JWT_ALGORITHM", "none")
    with pytest.raises(ValueError):
        CR.get_oauth_config()


def test_get_oauth_config_accepts_allowed_hs_algorithm(monkeypatch):
    monkeypatch.setenv("JWT_ALGORITHM", "HS512")
    _, _, _, algorithm = CR.get_oauth_config()
    assert algorithm == "HS512"


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

def _no_config_dir(monkeypatch):
    """Deja ``features.themis.scanners.nuclei.templatesDir`` vacío sin tocar SecOpsConfig.json."""
    monkeypatch.setattr(CR, "_cfg", lambda path, default=None, cast=None: (
        "" if path == "features.themis.scanners.nuclei.templatesDir" else default
    ))


def test_nuclei_templates_dir_prefers_the_configured_path(tmp_path, monkeypatch):
    configured = tmp_path / "configured"
    configured.mkdir()
    monkeypatch.setattr(CR, "_cfg", lambda path, default=None, cast=None: (
        str(configured) if path == "features.themis.scanners.nuclei.templatesDir" else default
    ))

    assert CR.get_nuclei_templates_dir() == configured


def test_nuclei_templates_dir_falls_back_to_the_environment(tmp_path, monkeypatch):
    from_env = tmp_path / "from-env"
    from_env.mkdir()
    _no_config_dir(monkeypatch)
    monkeypatch.setenv("NUCLEI_TEMPLATES_DIR", str(from_env))

    assert CR.get_nuclei_templates_dir() == from_env


def test_nuclei_templates_dir_falls_back_to_the_nuclei_default(tmp_path, monkeypatch):
    """The Docker image's real case: nothing configured, templates under $HOME."""
    default_location = tmp_path / ".local" / "nuclei-templates"
    default_location.mkdir(parents=True)
    _no_config_dir(monkeypatch)
    monkeypatch.delenv("NUCLEI_TEMPLATES_DIR", raising=False)
    monkeypatch.setattr("pathlib.Path.home", classmethod(lambda cls: tmp_path))

    assert CR.get_nuclei_templates_dir() == default_location


def test_nuclei_templates_dir_is_none_when_nothing_resolves(tmp_path, monkeypatch):
    """A missing tree is reported as such, never as an invented path."""
    _no_config_dir(monkeypatch)
    monkeypatch.delenv("NUCLEI_TEMPLATES_DIR", raising=False)
    monkeypatch.setattr("pathlib.Path.home", classmethod(lambda cls: tmp_path / "empty"))

    assert CR.get_nuclei_templates_dir() is None


def test_nuclei_templates_dir_ignores_a_configured_path_that_does_not_exist(tmp_path, monkeypatch):
    """A deployment typo must not silently look like a working template tree."""
    monkeypatch.setattr(CR, "_cfg", lambda path, default=None, cast=None: (
        str(tmp_path / "does-not-exist") if path == "features.themis.scanners.nuclei.templatesDir" else default
    ))
    monkeypatch.delenv("NUCLEI_TEMPLATES_DIR", raising=False)
    monkeypatch.setattr("pathlib.Path.home", classmethod(lambda cls: tmp_path / "empty"))

    assert CR.get_nuclei_templates_dir() is None
