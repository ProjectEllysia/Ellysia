"""Los checks de configuración de red que la Fase N prometió (L26).

Cierran la parte de la brecha G1 que no se resuelve escribiendo ojos: una
configuración insegura no tiene CVE y no aparece por la vía de la versión.

De los catorce que el issue lista, ocho se construyeron ya en la Fase 2. Aquí
van los cinco que faltaban: Telnet activo, VNC sin autenticación (plugins
script), y relay/STARTTLS de SMTP y FTP sin cifrado (checks network, sobre el
``NetworkSession`` real — la misma regla del resto del fichero: un doble por
encima de la sesión se inventaría capacidades que el transporte real no tiene).
"""

import pytest

from src.modules.features.themis.lybra.checks import (
    CheckRuntime,
    NetworkProbe,
    Service,
    load_checks,
)
from src.modules.features.themis.lybra.fingerprinting.telnet import TelnetProbe
from src.modules.features.themis.lybra.fingerprinting.vnc import VncProbe

pytestmark = pytest.mark.unit

_SMTP = Service(25, "tcp", "smtp", "", "", None)
_FTP = Service(21, "tcp", "ftp", "", "", None)
_TELNET = Service(23, "tcp", "telnet", "", "", None)
_VNC = Service(5900, "tcp", "vnc", "", "", None)
_CHECKS = load_checks()


class _FakeNetSocket:
    """Socket falso a nivel de bytes: saludo en el buffer, respuestas tras cada
    escritura (el mismo modelo que ``test_lybra_checks``)."""

    def __init__(self, greeting=b"", replies=()):
        self._buffer = greeting
        self._replies = list(replies)
        self.sent = b""

    def recv(self, size):
        chunk, self._buffer = self._buffer[:size], self._buffer[size:]
        return chunk

    def sendall(self, data):
        self.sent += data
        if self._replies:
            self._buffer += self._replies.pop(0)

    def close(self):
        pass


def _fired(check_id, sock, service):
    # Sólo el check bajo prueba: los checks del mismo servicio comparten la
    # sesión de red (la caché de sondas de L08), así que ejecutar el feed
    # entero dejaría a otro check consumiendo el socket antes que éste. Aislarlo
    # es lo que se quiere medir aquí — el comportamiento de un check, no la
    # orquestación.
    plain_id = check_id.split(":")[1].split("@")[0]
    only = [c for c in _CHECKS if c.id == plain_id]
    runtime = CheckRuntime(
        only, lambda *a: None,
        network_open=NetworkProbe(connect=lambda address, timeout: sock).open)
    return [f for f in runtime.run("h", [service]) if f["check_id"] == check_id]


# =============================================================== Telnet


def _telnet_plugin(reply):
    from src.modules.features.themis.lybra.script_checks import TelnetEnabledPlugin

    class _Sock:
        def settimeout(self, _t):
            pass

        def recv(self, _n):
            return reply

        def close(self):
            pass

    probe = TelnetProbe(connect=lambda address, timeout: _Sock())
    return TelnetEnabledPlugin(probe=probe)


class _Ctx:
    def __init__(self, service):
        self.target = "10.0.0.5"
        self.service = service
        self.sibling_services = ()

    def acquire(self):
        pass


def test_telnet_is_flagged_when_the_service_opens_with_iac():
    """Un servidor Telnet abre negociando opciones: el primer byte es IAC
    (0xFF). Esa firma es lo que dispara."""
    assert _telnet_plugin(b"\xff\xfb\x01").run(_Ctx(_TELNET)) is True


def test_a_mute_or_non_telnet_port_23_is_not_flagged():
    """Un puerto 23 abierto no basta: podría ser cualquier servicio mudo en un
    puerto reutilizado. Sin la firma del protocolo, no hay hallazgo."""
    assert _telnet_plugin(b"").run(_Ctx(_TELNET)) is False
    assert _telnet_plugin(b"SSH-2.0-x").run(_Ctx(_TELNET)) is False


def test_the_telnet_check_is_registered_and_wired():
    from src.modules.features.themis.lybra.script_checks import default_script_plugins

    check = next(c for c in _CHECKS if c.id == "telnet-enabled")
    assert check.service == "telnet" and check.severity == "HIGH"
    assert check.script in default_script_plugins()


# ================================================================== VNC


def _vnc_plugin(types):
    from src.modules.features.themis.lybra.script_checks import VncNoAuthenticationPlugin

    class _Probe(VncProbe):
        def security_types(self, host, port=5900):
            return types

    return VncNoAuthenticationPlugin(probe=_Probe())


def test_vnc_without_authentication_is_flagged():
    """El tipo de seguridad 1 es None (RFC 6143): entrar sin contraseña."""
    assert _vnc_plugin([1, 2]).run(_Ctx(_VNC)) is True


def test_vnc_that_only_offers_authentication_is_not_flagged():
    assert _vnc_plugin([2]).run(_Ctx(_VNC)) is False


def test_a_vnc_that_rejected_or_was_unreadable_is_not_flagged():
    assert _vnc_plugin([]).run(_Ctx(_VNC)) is False       # recuento 0: rechazo
    assert _vnc_plugin(None).run(_Ctx(_VNC)) is False      # no era RFB


# ================================================================= SMTP


_SMTP_BANNER = b"220 mail.example.com ESMTP Postfix\r\n"


def test_an_open_relay_is_flagged_when_the_external_rcpt_is_accepted():
    sock = _FakeNetSocket(
        greeting=_SMTP_BANNER,
        replies=[
            b"250-mail.example.com\r\n250 STARTTLS\r\n",   # EHLO
            b"250 2.1.0 Ok\r\n",                           # MAIL FROM
            b"250 2.1.5 Ok\r\n",                           # RCPT TO externo aceptado
        ],
    )
    assert _fired("lybra:smtp-open-relay@1", sock, _SMTP)


def test_a_closed_relay_that_rejects_the_external_rcpt_is_not_flagged():
    sock = _FakeNetSocket(
        greeting=_SMTP_BANNER,
        replies=[
            b"250-mail.example.com\r\n250 STARTTLS\r\n",
            b"250 2.1.0 Ok\r\n",
            b"554 5.7.1 Relay access denied\r\n",          # rechaza el relay
        ],
    )
    assert not _fired("lybra:smtp-open-relay@1", sock, _SMTP)


def test_a_server_without_starttls_is_flagged():
    sock = _FakeNetSocket(
        greeting=_SMTP_BANNER,
        replies=[b"250-mail.example.com\r\n250 SIZE 10240000\r\n250 HELP\r\n"],
    )
    assert _fired("lybra:smtp-no-starttls@1", sock, _SMTP)


def test_a_server_that_announces_starttls_is_not_flagged():
    sock = _FakeNetSocket(
        greeting=_SMTP_BANNER,
        replies=[b"250-mail.example.com\r\n250-STARTTLS\r\n250 HELP\r\n"],
    )
    assert not _fired("lybra:smtp-no-starttls@1", sock, _SMTP)


# ================================================================== FTP


def test_ftp_without_tls_is_flagged_when_auth_tls_is_refused():
    sock = _FakeNetSocket(
        greeting=b"220 (vsFTPd 3.0.3)\r\n",
        replies=[b"500 Unknown command.\r\n"],             # AUTH TLS rechazado
    )
    assert _fired("lybra:ftp-no-tls@1", sock, _FTP)


def test_ftp_with_ftps_support_is_not_flagged():
    sock = _FakeNetSocket(
        greeting=b"220 (vsFTPd 3.0.3)\r\n",
        replies=[b"234 Proceed with negotiation.\r\n"],    # AUTH TLS aceptado
    )
    assert not _fired("lybra:ftp-no-tls@1", sock, _FTP)


# ============================================= la brecha G1, contada entera


def test_at_least_five_network_config_findings_are_reachable():
    """El criterio de cierre: un host con SMB, FTP, SMTP y una base de datos
    abiertos alcanza al menos cinco hallazgos de configuración de red. Aquí se
    comprueba el inventario —que los checks existen, en su familia— no la red."""
    network_config = {c.id for c in _CHECKS if c.category in ("network_config",)}
    expected = {"smbv1-enabled", "smb-signing-not-required",
                "telnet-enabled", "smtp-open-relay", "smtp-no-starttls", "ftp-no-tls",
                "dns-open-resolver", "ntp-monlist-enabled"}
    assert expected <= network_config
    assert len(network_config) >= 5
