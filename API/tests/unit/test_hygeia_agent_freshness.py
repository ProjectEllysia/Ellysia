"""
Tests unitarios de hygeia.services.agent_freshness.is_agent_outdated.

Sin base de datos ni Flask: función pura sobre dos cadenas de versión.
"""

import pytest

from src.modules.features.hygeia.services.agent_freshness import is_agent_outdated

pytestmark = pytest.mark.unit


def test_older_version_is_outdated():
    assert is_agent_outdated("0.3.9", "0.4.0") is True


def test_equal_version_is_not_outdated():
    assert is_agent_outdated("0.4.0", "0.4.0") is False


def test_newer_version_is_not_outdated():
    assert is_agent_outdated("0.5.1", "0.4.0") is False


def test_missing_agent_version_is_unknown():
    """Un activo que nunca ha reportado versión no se marca desactualizado."""
    assert is_agent_outdated(None, "0.4.0") is None


def test_default_floor_of_zero_never_flags_a_real_version():
    """El suelo por defecto (0.0.0) no debe marcar ningún agente real."""
    assert is_agent_outdated("0.1.0", "0.0.0") is False


@pytest.mark.parametrize("agent_version", ["dev", "1.2.3-rc1", "v1.2.3", "", "1.2.", "1..2"])
def test_malformed_agent_version_is_unknown_not_outdated(agent_version):
    """El caso central del issue: un dato corrupto nunca se lee como desactualizado."""
    assert is_agent_outdated(agent_version, "0.4.0") is None


def test_malformed_min_version_yields_unknown_for_everyone():
    """Un typo en la configuración no debe traducirse en falsos avisos para todo el parque."""
    assert is_agent_outdated("0.1.0", "no-es-una-version") is None
    assert is_agent_outdated("99.0.0", "no-es-una-version") is None


def test_shorter_segment_count_is_padded_before_comparing():
    """"1.2" y "1.2.0" no son una diferencia real."""
    assert is_agent_outdated("1.2", "1.2.0") is False
    assert is_agent_outdated("1.2.0", "1.2") is False
    assert is_agent_outdated("1.2", "1.3") is True
    assert is_agent_outdated("1.3", "1.2") is False


def test_single_segment_versions_compare_correctly():
    assert is_agent_outdated("0", "1") is True
    assert is_agent_outdated("1", "1") is False
