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
