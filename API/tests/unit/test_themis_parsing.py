"""Tests unitarios de themis.services.parsing (validate_ip / validate_port).

Funciones puras sobre strings: no requieren BD ni app Flask.
"""

import pytest

import src.modules.system.config_reading as CR
from src.modules.features.themis.exceptions import (
    IPValidationError,
    PortValidationError,
    PrivateIPRequested,
)
from src.modules.features.themis.services.parsing import (
    validate_ip,
    validate_port,
    reject_private_ip,
)

pytestmark = pytest.mark.unit


class TestValidateIpEmptyInput:
    """_require_non_empty debe lanzar IPValidationError (nunca TypeError) para
    entradas vacías/no-string, sin importar por qué rama pase (empty vs
    whitespace-only usan kwargs distintos internamente)."""

    def test_empty_string_raises_ip_validation_error(self):
        with pytest.raises(IPValidationError):
            validate_ip("")

    def test_whitespace_only_raises_ip_validation_error(self):
        with pytest.raises(IPValidationError):
            validate_ip("   ")

    def test_none_raises_ip_validation_error(self):
        with pytest.raises(IPValidationError):
            validate_ip(None)


class TestValidatePortEmptyInput:
    """Espejo de TestValidateIpEmptyInput para validate_port: antes de la
    corrección, validate_port("") lanzaba TypeError (kwarg ip_spec en vez de
    port_spec) en lugar de PortValidationError."""

    def test_empty_string_raises_port_validation_error(self):
        with pytest.raises(PortValidationError):
            validate_port("")

    def test_whitespace_only_raises_port_validation_error(self):
        with pytest.raises(PortValidationError):
            validate_port("   ")

    def test_none_raises_port_validation_error(self):
        with pytest.raises(PortValidationError):
            validate_port(None)


class TestValidateIpFormats:
    """Prueba solo la expansión de formatos (CIDR/rango/lista); usa IPs
    privadas como datos de prueba, así que necesita 'areLocalIpsAllowed' en
    true independientemente del valor real en SecOpsConfig.json."""

    @pytest.fixture(autouse=True)
    def _allow_local_ips(self, monkeypatch):
        monkeypatch.setattr(CR, "themis_config", lambda: CR.ThemisConfig(are_local_ips_allowed=True))

    def test_single_ip(self):
        assert validate_ip("192.168.1.1") == ["192.168.1.1"]

    def test_cidr(self):
        ips = validate_ip("192.168.1.0/30", max_hosts=10)
        assert "192.168.1.1" in ips and "192.168.1.2" in ips

    def test_octet_range(self):
        ips = validate_ip("192.168.1.1-3", max_hosts=10)
        assert ips == ["192.168.1.1", "192.168.1.2", "192.168.1.3"]

    def test_comma_separated_list(self):
        assert validate_ip("192.168.1.1,192.168.1.5") == ["192.168.1.1", "192.168.1.5"]

    def test_invalid_octet_raises(self):
        with pytest.raises(IPValidationError):
            validate_ip("999.1.1.1")


class TestValidatePortFormats:
    def test_single_port(self):
        assert validate_port("80") == [80]

    def test_port_list(self):
        assert validate_port("80,443") == [80, 443]

    def test_port_range(self):
        assert validate_port("1-3") == [1, 2, 3]

    def test_ports_not_ascending_raises(self):
        with pytest.raises(PortValidationError):
            validate_port("443,80")

    def test_port_out_of_range_raises(self):
        with pytest.raises(PortValidationError):
            validate_port("70000")


class TestPrivateIpPolicy:
    """S2: 'areLocalIpsAllowed' debe rechazar IPs privadas por defecto (el
    default de config_reading es False; SecOpsConfig.json debe coincidir)."""

    def test_validate_ip_rejects_private_by_default(self, monkeypatch):
        monkeypatch.setattr(CR, "themis_config", lambda: CR.ThemisConfig(are_local_ips_allowed=False))
        with pytest.raises(PrivateIPRequested):
            validate_ip("192.168.1.1")

    def test_validate_ip_allows_private_when_configured(self, monkeypatch):
        monkeypatch.setattr(CR, "themis_config", lambda: CR.ThemisConfig(are_local_ips_allowed=True))
        assert validate_ip("192.168.1.1") == ["192.168.1.1"]

    def test_reject_private_ip_rejects_private_by_default(self, monkeypatch):
        monkeypatch.setattr(CR, "themis_config", lambda: CR.ThemisConfig(are_local_ips_allowed=False))
        with pytest.raises(PrivateIPRequested):
            reject_private_ip("10.0.0.5")

    def test_reject_private_ip_allows_public(self, monkeypatch):
        monkeypatch.setattr(CR, "themis_config", lambda: CR.ThemisConfig(are_local_ips_allowed=False))
        reject_private_ip("8.8.8.8")  # no debe lanzar
