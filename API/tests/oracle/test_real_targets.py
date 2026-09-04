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

from ._nmap_oracle import _docker_args, _target_from_container, assert_target_was_scanned


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


def test_the_oracle_container_is_told_how_to_reach_the_host():
    """Traducir el objetivo a ``host.docker.internal`` no sirve de nada si el
    contenedor no sabe resolver ese nombre, que es lo que pasa en Docker sobre
    Linux — y por tanto en el runner del banco nocturno (#455). La bandera que
    lo mapea contra la puerta de enlace del host tiene que ir en el ``docker
    run``, y antes de la imagen: lo que va después son argumentos de Nmap."""
    arguments = _docker_args("/usr/bin/docker")

    assert "--add-host" in arguments
    assert arguments[arguments.index("--add-host") + 1] == "host.docker.internal:host-gateway"
    assert arguments.index("--add-host") < arguments.index("instrumentisto/nmap")
    assert arguments[-1] == "instrumentisto/nmap"


_XML_WITH_A_CLOSED_PORT = """<?xml version="1.0"?>
<nmaprun><host><address addr="192.168.65.2" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="12121"><state state="closed"/></port></ports>
</host></nmaprun>"""

_XML_WITHOUT_A_HOST = """<?xml version="1.0"?>
<nmaprun><runstats><hosts up="0" down="0" total="0"/></runstats></nmaprun>"""


def test_a_closed_port_is_a_measurement_and_not_an_error():
    """Nmap habló con el objetivo y no encontró nada escuchando. Es un
    resultado legítimo del banco y no debe interrumpir nada."""
    assert_target_was_scanned(_XML_WITH_A_CLOSED_PORT, "", "host.docker.internal")


def test_an_unreachable_target_stops_the_bench_instead_of_scoring_zero():
    """El fallo que estuvo tres noches disfrazado de desacuerdo de fingerprint.

    Cuando el nombre no resuelve, Nmap emite este XML —válido, sin ni un
    ``<host>`` dentro— y sale con código 0. Antes eso se colaba como «Nmap no
    identificó el servicio» y restaba en la cifra de concordancia; ahora lanza,
    y el mensaje lleva la salida de error de Nmap para que el log de CI diga
    por sí solo qué pasó."""
    with pytest.raises(RuntimeError) as failure:
        assert_target_was_scanned(
            _XML_WITHOUT_A_HOST,
            'Failed to resolve "host.docker.internal".',
            "host.docker.internal",
        )

    assert "no escaneó ningún host" in str(failure.value)
    assert "Failed to resolve" in str(failure.value)


# --------------------------------------------------------------------------
# Un contenedor caído no puede leerse como un fallo del motor (#455)
# --------------------------------------------------------------------------
#
# Puras también: sólo comprueban qué hace el registro cuando no sabe nada del
# puerto, que es la mitad de la que depende que este cambio no rompa nada.

from ._docker_helpers import container_died, diagnose_port, remember_container


def test_an_unknown_port_is_never_declared_dead():
    """El comportamiento por defecto tiene que seguir siendo «sigue esperando».

    Los esperadores del banco preguntan por todos los puertos, también por los
    que nadie registró. Si un puerto desconocido se diera por muerto, el
    diagnóstico nuevo convertiría cualquier arranque lento en un fallo
    inmediato — justo la carrera que estos plazos largos existen para evitar."""
    assert container_died("/usr/bin/docker", 65_432) is False
    assert diagnose_port("/usr/bin/docker", 65_432) == ""


def test_without_a_docker_client_nothing_is_diagnosed():
    """En una máquina sin Docker los bancos se saltan enteros, pero los
    esperadores siguen siendo importables y no deben intentar inspeccionar
    nada con un cliente que no existe."""
    remember_container(65_433, "lybra-inexistente")
    try:
        assert container_died(None, 65_433) is False
        assert diagnose_port(None, 65_433) == ""
    finally:
        _forget_container(65_433)


def _forget_container(port: int) -> None:
    """Sacar un puerto del registro para no filtrarlo a otros tests."""
    from ._docker_helpers import _CONTAINERS_BY_PORT
    _CONTAINERS_BY_PORT.pop(port, None)


# --------------------------------------------------------------------------
# Un Docker colgado no puede tumbar la suite
# --------------------------------------------------------------------------

import subprocess

from ._docker_helpers import _working_docker


def test_a_hung_docker_daemon_is_reported_as_unavailable(monkeypatch):
    """Docker Desktop con su distro WSL caída deja ``docker version`` esperando
    al pipe hasta que alguien lo mata: el binario existe y responde, pero no hay
    demonio detrás.

    Antes eso subía como ``TimeoutExpired`` desde ``resolve_docker()``, que se
    llama al **importar** cada módulo del banco. Como los marcadores de pytest
    se filtran después de importar, un Docker colgado producía cinco errores de
    colección y tumbaba la suite entera — incluso con ``-m "not oracle"``, en
    tests que ni siquiera iban a ejecutarse.
    """
    def _hangs(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="docker version", timeout=10)

    monkeypatch.setattr(subprocess, "run", _hangs)
    assert _working_docker("/cualquier/ruta/docker") is False


def test_a_missing_docker_binary_is_still_reported_as_unavailable(monkeypatch):
    """La otra mitad, que ya funcionaba: el binario no existe o no se ejecuta."""
    def _explodes(*args, **kwargs):
        raise OSError("no such file")

    monkeypatch.setattr(subprocess, "run", _explodes)
    assert _working_docker("/cualquier/ruta/docker") is False
