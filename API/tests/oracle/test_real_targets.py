"""La lista blanca del sello de red hace exactamente lo que dice (L48).

El sello ``_no_outbound_sockets`` es lo que mantiene la suite en dos minutos y
lo que garantiza que su resultado no dependa de lo que haya al otro lado de la
red. Desde L48 tiene una excepción: las direcciones que el operador declara en
``LYBRA_REAL_TARGETS`` para el banco de paridad real.

Una excepción a una defensa es justo el sitio donde conviene no fiarse de la
lectura. Estos casos comprueban las dos mitades que importan:

- que **sin** la variable la lista queda vacía, que es lo que hace que en CI y
  en cualquier máquina que no haya decidido lo contrario el sello siga entero;
- que **con** ella entra lo declarado y nada más — ni una dirección de más por
  un separador mal puesto, ni un fallo entero por un objetivo que no resuelve.

Todo se comprueba sobre direcciones IP literales, que no necesitan DNS: un test
del sello de red que saliera a la red a resolver nombres sería una contradicción
en sus propios términos.

Vive en ``tests/oracle/`` porque ahí vive el módulo que prueba, pero **no** lleva
el marcador ``oracle``: son funciones puras sobre cadenas, sin Docker ni red, y
tienen que correr en el CI por defecto — es donde importa que la lista blanca
salga vacía.
"""

import pytest

from ._real_targets import allowed_outbound_addresses, declared_real_targets

pytestmark = pytest.mark.unit


def test_without_the_variable_nothing_is_allowed(monkeypatch):
    """El caso por defecto, y el único que corre en CI."""
    monkeypatch.delenv("LYBRA_REAL_TARGETS", raising=False)
    assert declared_real_targets() == ()
    assert allowed_outbound_addresses() == set()


def test_an_empty_or_blank_variable_is_the_same_as_none(monkeypatch):
    """Una variable declarada pero vacía —o con comas sueltas de una edición a
    medias— no puede abrir la red "un poco"."""
    for value in ("", "   ", ",", " , , "):
        monkeypatch.setenv("LYBRA_REAL_TARGETS", value)
        assert declared_real_targets() == ()
        assert allowed_outbound_addresses() == set()


def test_declared_addresses_are_parsed_and_trimmed(monkeypatch):
    monkeypatch.setenv("LYBRA_REAL_TARGETS", " 198.51.100.7 , 203.0.113.9 ")
    assert declared_real_targets() == ("198.51.100.7", "203.0.113.9")
    assert allowed_outbound_addresses() == {"198.51.100.7", "203.0.113.9"}


def test_a_target_that_does_not_resolve_does_not_sink_the_rest(monkeypatch):
    """Un nombre inválido no puede dejar sin lista blanca a los que sí lo son:
    el banco reportará ese objetivo como inalcanzable cuando le toque, que es
    donde se ve, en vez de hacer fallar la construcción del sello."""
    monkeypatch.setenv("LYBRA_REAL_TARGETS", "198.51.100.7,no-existe.invalid")
    assert "198.51.100.7" in allowed_outbound_addresses()


# --------------------------------------------------------------------------
# El oráculo alcanza el objetivo correcto (L48, arreglo del banco de paridad)
# --------------------------------------------------------------------------
#
# Estas dos comprueban la traducción de host que el contenedor de Nmap necesita.
# Son puras (no lanzan Nmap ni Docker), así que corren en CI como el resto de
# este fichero, sin marcador ``oracle``.

from ._nmap_oracle import _target_from_container


def test_loopback_is_reached_through_the_docker_host():
    """Un puerto publicado en 127.0.0.1 no es alcanzable por su loopback desde
    dentro de otro contenedor: hay que rebotar por ``host.docker.internal``."""
    assert _target_from_container("127.0.0.1") == "host.docker.internal"
    assert _target_from_container("localhost") == "host.docker.internal"


def test_an_external_target_is_scanned_directly():
    """El defecto que tenía el banco de paridad real: el contenedor de Nmap
    escaneaba ``host.docker.internal`` —la máquina Docker— en vez del objetivo
    externo, midiendo algo que no tenía nada que ver. Un host o IP que no es
    loopback se pasa tal cual."""
    assert _target_from_container("emesa.com") == "emesa.com"
    assert _target_from_container("203.0.113.9") == "203.0.113.9"
