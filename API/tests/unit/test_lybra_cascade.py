"""La cascada de identificación para servicios fuera de su puerto canónico (L10).

Los predicados de aplicabilidad deciden por nombre o por número de puerto, y en
el camino de autodescubrimiento el nombre sale a su vez de una tabla de
puertos: la decisión era, en la práctica, el número. Un MySQL en el 33060 o un
SSH en el 2222 quedaban ciegos por completo.

Todo aquí va con socket falso: la cascada recibe su conector inyectado, igual
que el resto de sondas del paquete.
"""

import pytest

from src.modules.features.themis.lybra.engine import Service
from src.modules.features.themis.lybra.fingerprinting import default_dissectors
from src.modules.features.themis.lybra.fingerprinting.cascade import (
    banner_readers,
    blind_probers,
    identify_unknown_service,
    read_volunteered_banner,
)
from src.modules.features.themis.lybra.fingerprinting.dispatch import (
    Dissector,
    DissectorResult,
)

pytestmark = pytest.mark.unit


class _FakeSocket:
    """Socket que entrega un saludo prefijado y luego se cierra."""

    def __init__(self, banner: bytes):
        self._banner = banner
        self.closed = False

    def settimeout(self, _timeout):
        pass

    def recv(self, _size):
        banner, self._banner = self._banner, b""
        return banner

    def close(self):
        self.closed = True


def _connector(banner: bytes):
    def connect(_address, _timeout):
        return _FakeSocket(banner)
    return connect


def _silent_connector():
    return _connector(b"")


def _refusing_connector():
    def connect(_address, _timeout):
        raise ConnectionRefusedError("cerrado")
    return connect


class _NullRateLimiter:
    def __init__(self):
        self.turns = 0

    def acquire(self, _host):
        self.turns += 1


def _cascade(banner, port, connect=None, **kwargs):
    return identify_unknown_service(
        "10.0.0.5",
        Service(port=port, protocol="tcp", name="", product="", version=""),
        default_dissectors(),
        _NullRateLimiter(),
        connect=connect or _connector(banner),
        **kwargs,
    )


# ================================================== la lectura del saludo


def test_a_refused_connection_yields_no_banner():
    assert read_volunteered_banner("10.0.0.5", 33060, 0.1, _refusing_connector()) is None


def test_a_silent_service_yields_no_banner():
    assert read_volunteered_banner("10.0.0.5", 33060, 0.1, _silent_connector()) is None


def test_the_socket_is_always_closed():
    sockets = []

    def connect(_address, _timeout):
        sock = _FakeSocket(b"SSH-2.0-OpenSSH_8.9p1")
        sockets.append(sock)
        return sock

    read_volunteered_banner("10.0.0.5", 2222, 0.1, connect)
    assert sockets[0].closed


# ============================== servicios reconocidos fuera de su puerto


def test_mysql_on_a_non_canonical_port_is_identified():
    # El paquete inicial de MySQL: 4 bytes de cabecera, 0x0A (HandshakeV10),
    # y la versión terminada en NUL.
    handshake = bytes((10, 0, 0, 0)) + bytes((0x0A,)) + b"8.0.35" + bytes((0,))
    result = _cascade(handshake, 33060)
    assert (result.label, result.product, result.version) == ("MySQL", "MySQL", "8.0.35")


def test_ssh_on_a_non_canonical_port_is_identified():
    result = _cascade(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n", 2222)
    assert (result.label, result.product, result.version) == ("SSH", "OpenSSH", "8.9p1")


def test_ftp_on_a_non_canonical_port_is_identified():
    result = _cascade(b"220 (vsFTPd 3.0.5)\r\n", 2121)
    assert (result.label, result.product, result.version) == ("FTP", "vsFTPd", "3.0.5")


def test_vnc_on_a_non_canonical_port_is_identified():
    result = _cascade(b"RFB 003.008\n", 5901)
    assert result.label == "VNC" and result.version == "3.8"


def test_pop3_on_a_non_canonical_port_is_identified():
    result = _cascade(b"+OK Dovecot ready.\r\n", 11000)
    assert result.label == "POP3" and result.product == "Dovecot"


def test_imap_on_a_non_canonical_port_is_identified():
    result = _cascade(b"* OK Dovecot ready.\r\n", 11430)
    assert result.label == "IMAP" and result.product == "Dovecot"


# ================================ los saludos que se parecen entre sí


def test_smtp_and_ftp_do_not_steal_each_others_greeting():
    """Los dos empiezan por "220". Sin un marcador propio, el primero de la
    lista se quedaría con todos los saludos del otro — y el producto acabaría
    etiquetado con el protocolo equivocado."""
    smtp = _cascade(b"220 mail.example.com ESMTP Exim 4.94.2\r\n", 2525)
    assert smtp.label == "SMTP" and smtp.product == "Exim"

    ftp = _cascade(b"220 ProFTPD Server (Debian)\r\n", 2121)
    assert ftp.label == "FTP" and ftp.product == "ProFTPD"


# ==================================================== servicios mudos


def test_a_mute_service_produces_no_identification_and_breaks_nothing():
    """El caso que hay que no estropear: un puerto que acepta la conexión y no
    contesta a nada sigue siendo un `open_port` informativo, como antes."""
    assert _cascade(b"", 12345, max_blind_probes=0) is None


def test_an_unrecognisable_banner_is_not_guessed():
    assert _cascade(b"\x01\x02\x03 datos binarios cualesquiera", 12345,
                    max_blind_probes=0) is None


# ============================================== presupuesto de sondas ciegas


class _CountingDissector(Dissector):
    """Dissector a ciegas que apunta cuántas veces se le ha sondado."""

    tries_blind = True

    def __init__(self, label, result=None):
        self.label = label
        self.calls = 0
        self._result = result

    def applies(self, service):
        return False

    def probe(self, target, service, rate_limiter):
        self.calls += 1
        return self._result


def _blind_cascade(dissectors, max_blind_probes):
    return identify_unknown_service(
        "10.0.0.5",
        Service(port=9999, protocol="tcp", name="", product="", version=""),
        dissectors,
        _NullRateLimiter(),
        max_blind_probes=max_blind_probes,
        connect=_silent_connector(),
    )


def test_the_blind_probe_budget_is_respected():
    """El presupuesto es lo que separa "prueba lo que ya sabes leer" de un
    escaneo de servicios completo contra cada puerto desconocido."""
    probers = [_CountingDissector(f"P{n}") for n in range(4)]
    _blind_cascade(probers, max_blind_probes=2)
    assert [prober.calls for prober in probers] == [1, 1, 0, 0]


def test_a_budget_of_zero_skips_the_blind_probes_entirely():
    probers = [_CountingDissector("P0")]
    assert _blind_cascade(probers, max_blind_probes=0) is None
    assert probers[0].calls == 0


def test_the_first_blind_probe_that_identifies_something_wins():
    found = DissectorResult("Redis", "7.2.4", "Redis")
    probers = [_CountingDissector("P0"), _CountingDissector("P1", found)]
    assert _blind_cascade(probers, max_blind_probes=3) is found
    assert probers[0].calls == 1 and probers[1].calls == 1


def test_a_blind_probe_that_raises_does_not_stop_the_next_one():
    class _Exploding(_CountingDissector):
        def probe(self, target, service, rate_limiter):
            self.calls += 1
            raise RuntimeError("boom")

    found = DissectorResult("Redis", "7.2.4", "Redis")
    probers = [_Exploding("boom"), _CountingDissector("P1", found)]
    assert _blind_cascade(probers, max_blind_probes=3) is found


# ================================= la cascada se deriva del registro


def test_the_cascade_is_derived_from_the_registry_not_a_parallel_list():
    """La razón de que `banner_readers` y `blind_probers` se calculen y no se
    escriban: una lista paralela es exactamente lo que se queda atrás. #272
    documenta el caso — un mapa a mano con dos entradas mientras el módulo ya
    definía once predicados."""
    dissectors = default_dissectors()
    readers = {dissector.label for dissector in banner_readers(dissectors)}
    blind = {dissector.label for dissector in blind_probers(dissectors)}

    assert {"SSH", "FTP", "SMTP", "IMAP", "POP3", "MySQL", "VNC"} <= readers
    # SMB y SNMP negocian o hablan UDP: no hay saludo voluntario que leer.
    assert "SMB" not in readers and "SNMP" not in readers
    assert blind == {"HTTP", "Redis"}


def test_a_new_banner_reading_dissector_joins_the_cascade_by_declaring_it():
    class _Invented(Dissector):
        label = "Inventado"

        def applies(self, service):
            return False

        def identify_from_banner(self, banner):
            return DissectorResult("Inventado", "1.0", self.label)

    invented = _Invented()
    assert banner_readers([invented]) == [invented]
    # Y uno que no la declara se queda fuera, sin tocar nada de la cascada.
    assert banner_readers([_CountingDissector("P0")]) == []
