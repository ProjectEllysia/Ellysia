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
from src.modules.features.themis.services import parsing
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


class TestHostnameTargetsReachTheSsrfGuard:
    """El guardia de objetivo único acepta nombres, y los resuelve antes de juzgar.

    Antes hacía ``ipaddress.ip_address(target)`` sin red de seguridad, así que
    un nombre lo reventaba con un ``ValueError`` sin capturar. El fallo estuvo
    tapado todo este tiempo porque ``areLocalIpsAllowed`` estaba en ``true`` en
    el SecOpsConfig.json versionado, y ese flag cortocircuita la comprobación
    entera **antes** de mirar el valor: con la defensa apagada, el bug no se
    alcanzaba.

    Resolver no es una comodidad para aceptar nombres: es parte de la defensa.
    Un nombre que apunta a loopback o al endpoint de metadatos del cloud
    atraviesa un guardia que sólo mire lo que *parece* una IP.
    """

    def test_a_hostname_pointing_at_loopback_is_rejected(self, monkeypatch):
        monkeypatch.setattr(CR, "themis_config", lambda: CR.ThemisConfig(are_local_ips_allowed=False))
        monkeypatch.setattr(
            parsing.socket, "getaddrinfo",
            lambda host, port: [(None, None, None, "", ("127.0.0.1", 0))],
        )
        with pytest.raises(PrivateIPRequested):
            parsing.reject_private_ip("interno.example.com")

    def test_a_hostname_with_one_private_record_is_rejected(self, monkeypatch):
        """Basta con que una de las direcciones sea privada: comprobar sólo la
        primera dejaría pasar un nombre con varios registros."""
        monkeypatch.setattr(CR, "themis_config", lambda: CR.ThemisConfig(are_local_ips_allowed=False))
        monkeypatch.setattr(
            parsing.socket, "getaddrinfo",
            lambda host, port: [
                (None, None, None, "", ("93.184.216.34", 0)),
                (None, None, None, "", ("10.0.0.5", 0)),
            ],
        )
        with pytest.raises(PrivateIPRequested):
            parsing.reject_private_ip("mixto.example.com")

    def test_a_hostname_pointing_at_a_public_address_passes(self, monkeypatch):
        monkeypatch.setattr(CR, "themis_config", lambda: CR.ThemisConfig(are_local_ips_allowed=False))
        monkeypatch.setattr(
            parsing.socket, "getaddrinfo",
            lambda host, port: [(None, None, None, "", ("93.184.216.34", 0))],
        )
        parsing.reject_private_ip("publico.example.com")   # no lanza

    def test_a_hostname_that_does_not_resolve_is_a_validation_error(self, monkeypatch):
        """Y no un ``ValueError`` que se escape sin capturar, que es lo que
        pasaba: el llamante no podía distinguirlo de un fallo del programa."""
        monkeypatch.setattr(CR, "themis_config", lambda: CR.ThemisConfig(are_local_ips_allowed=False))
        def _nxdomain(host, port):
            raise OSError("Name or service not known")
        monkeypatch.setattr(parsing.socket, "getaddrinfo", _nxdomain)
        with pytest.raises(IPValidationError):
            parsing.reject_private_ip("no-existe.invalid")
