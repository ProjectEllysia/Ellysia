"""Unit tests for the Lybra active-check runtime (Fase R).

Pure: an injected ``fetch``/``network_open`` returns crafted responses, so no
real network. Exercises the bundled feed, the matchers, HTTP-service
selection, the safe/aggressive gate, and the ``type: "network"`` family Fase N
adds.

Para la familia ``network``, el transporte se sustituye **a nivel de socket**
(bytes) y no a nivel de sesión: la nota al principio de esa sección explica
por qué, y es la regla que el resto de la casa ya sigue con los dissectors.
"""

import json

import yaml

import pytest

from src.modules.features.themis.lybra import checks as checks_mod
from src.modules.features.themis.lybra import (
    load_checks,
    CheckRuntime,
    NetworkProbe,
    Response,
    SmbSigningNotRequiredPlugin,
    SnmpDefaultCommunityPlugin,
    default_script_plugins,
    is_http_service,
    is_ftp_service,
    is_redis_service,
    Service,
)

pytestmark = pytest.mark.unit


def _fetcher(by_path):
    """Fake fetch: returns the Response mapped to the requested path (or a 404)."""
    calls = []

    def fetch(host, port, method, path):
        calls.append((host, port, method, path))
        return by_path.get(path, Response(404, "", {}))

    fetch.calls = calls
    return fetch


_HTTP = Service(80, "tcp", "http", "nginx", "1.18", None)


# -------------------------------------------------------------- bundled feed

def test_bundled_feed_loads():
    checks = load_checks()
    ids = {c.id for c in checks}
    assert {"git-config-exposure", "dotenv-exposure", "missing-hsts-header"} <= ids
    git = next(c for c in checks if c.id == "git-config-exposure")
    assert git.check_id == "lybra:git-config-exposure@1"
    assert git.finding["qod"] == 99


# ------------------------------------------------------------------- matchers

def test_git_config_exposure_confirmed():
    fetch = _fetcher({"/.git/config": Response(200, "[core]\n\trepositoryformatversion = 0\n", {})})
    findings = CheckRuntime(load_checks(), fetch).run("10.0.0.5", [_HTTP])

    git = [f for f in findings if f["check_id"] == "lybra:git-config-exposure@1"]
    assert len(git) == 1
    assert git[0]["qod"] == 99 and git[0]["confirmed"] is True
    assert git[0]["category"] == "exposed_path"
    assert git[0]["port"] == 80


def test_git_config_not_exposed_gives_no_finding():
    # 404 for /.git/config -> status matcher fails -> no finding.
    fetch = _fetcher({"/.git/config": Response(404, "Not Found", {})})
    findings = CheckRuntime(load_checks(), fetch).run("10.0.0.5", [_HTTP])
    assert not any(f["check_id"].startswith("lybra:git-config") for f in findings)


def test_missing_hsts_detected_and_absent_when_present():
    # No HSTS header on "/" -> negative header matcher fires.
    fetch_missing = _fetcher({"/": Response(200, "<html>", {})})
    missing = CheckRuntime(load_checks(), fetch_missing).run("h", [_HTTP])
    assert any(f["check_id"] == "lybra:missing-hsts-header@1" for f in missing)

    # HSTS present -> negative matcher does not fire -> no finding.
    fetch_present = _fetcher({"/": Response(200, "<html>", {"strict-transport-security": "max-age=63072000"})})
    present = CheckRuntime(load_checks(), fetch_present).run("h", [_HTTP])
    assert not any(f["check_id"] == "lybra:missing-hsts-header@1" for f in present)


def test_dotenv_regex_matcher():
    fetch = _fetcher({"/.env": Response(200, "APP_KEY=base64:secret\nDB_PASSWORD=hunter2\n", {})})
    findings = CheckRuntime(load_checks(), fetch).run("h", [_HTTP])
    assert any(f["check_id"] == "lybra:dotenv-exposure@1" for f in findings)


# --------------------------------------------------------- service selection

def test_only_http_services_are_probed():
    ssh = Service(22, "tcp", "ssh", "OpenSSH", "7.4", None)
    fetch = _fetcher({})
    CheckRuntime(load_checks(), fetch).run("h", [ssh])
    assert fetch.calls == []            # nothing probed for a non-HTTP service

    assert is_http_service(_HTTP) is True
    assert is_http_service(ssh) is False


# ------------------------------------------------------------ safe/aggressive

_AGGRESSIVE_FEED = {
    "checks": [{
        "id": "aggressive-probe", "version": 1, "type": "http",
        "category": "exposed_path", "severity": "HIGH", "service": "http",
        "mode": "aggressive",
        "requests": [{"path": "/x", "matchers": [{"type": "status", "value": [200]}]}],
        "finding": {"title": "x"},
    }]
}


def test_safe_mode_skips_aggressive_checks(tmp_path):
    feed = tmp_path / "feed.json"
    feed.write_text(json.dumps(_AGGRESSIVE_FEED), encoding="utf-8")
    checks = load_checks(str(feed))
    fetch = _fetcher({"/x": Response(200, "", {})})

    assert CheckRuntime(checks, fetch, mode="safe").run("h", [_HTTP]) == []
    aggressive = CheckRuntime(checks, fetch, mode="aggressive").run("h", [_HTTP])
    assert len(aggressive) == 1


# --------------------------------------------------- network checks (Fase N)
#
# **Dónde se sustituye el transporte, y por qué ahí.** Los tests de
# comportamiento de protocolo de esta sección inyectan un *socket* falso y
# dejan que el ``NetworkSession`` real haga su trabajo — la misma regla que ya
# siguen los dissectors, que se ejercitan con bytes y no con probes falsos.
#
# Un doble que sustituya a ``NetworkSession`` entera acaba siendo más capaz que
# la pieza real: entrega respuestas multilínea completas que ``exchange`` jamás
# produciría, y con eso documenta lo que el autor creía que pasaba en vez de lo
# que pasa. Así es como un bug de transporte sobrevivió a una sección entera de
# tests en verde.
#
# ``_FakeNetworkSession`` se queda **sólo** para la orquestación del runtime
# (que no se sondee un servicio que no aplica, que sin ``network_open`` no se
# haga nada, que la sesión se cierre siempre): eso no es comportamiento de
# protocolo y no necesita bytes.

_FTP = Service(21, "tcp", "ftp", "", "", None)
_REDIS = Service(6379, "tcp", "redis", "", "", None)

# Saludo que un vsftpd real deja en el buffer en el instante de conectar, antes
# de que el cliente escriba nada.
_FTP_BANNER = b"220 (vsFTPd 3.0.3)\r\n"
# El mismo saludo en su forma multilínea, igual de habitual (RFC 959 §4.2).
_FTP_MULTILINE_BANNER = b"220-Bienvenido a este FTP\r\n220 (vsFTPd 3.0.3)\r\n"
# Respuesta real de Redis a INFO: un bulk string RESP cuya primera línea es la
# longitud, no el contenido.
_REDIS_INFO = b"$3116\r\n# Server\r\nredis_version:7.0.11\r\nredis_mode:standalone\r\n"


class _FakeNetSocket:
    """Un socket falso a nivel de bytes: entrega un flujo y encola respuestas.

    Modela las dos cosas que un doble por encima de la sesión borra: el saludo
    ya está en el buffer en el instante de conectar, y cada respuesta aparece
    **después** de que el cliente escriba su comando. Los trozos que devuelve
    ``recv`` tampoco tienen por qué coincidir con las líneas del protocolo.

    Args:
        greeting: Los bytes que el servidor ya tiene puestos al conectar.
        replies: Un flujo de respuesta por cada escritura del cliente, en orden.
        chunk_size: El máximo de bytes que devuelve un ``recv``, para poder
            trocear la respuesta de forma arbitraria.
    """

    def __init__(self, greeting: bytes = b"", replies=(), chunk_size: int = 65536):
        self._buffer = greeting
        self._replies = list(replies)
        self._chunk = chunk_size
        self.sent = b""
        self.closed = False
        self.recv_calls = 0

    def recv(self, size: int) -> bytes:
        self.recv_calls += 1
        take = min(size, self._chunk)
        chunk, self._buffer = self._buffer[:take], self._buffer[take:]
        return chunk

    def sendall(self, data: bytes) -> None:
        self.sent += data
        if self._replies:
            self._buffer += self._replies.pop(0)

    def close(self) -> None:
        self.closed = True


def _network_open_over(sock):
    """Un ``network_open`` que abre el :class:`NetworkSession` **real** sobre ``sock``."""
    return NetworkProbe(connect=lambda address, timeout: sock).open


class _FakeNetworkSession:
    """Doble de orquestación: apunta lo que se le pidió, sin hablar ningún protocolo.

    Sólo para los tests que verifican *qué* hace el runtime (a qué servicios
    abre sesión, si la cierra), nunca para los que verifican qué entiende del
    otro extremo — para eso está :class:`_FakeNetSocket`, que es un nivel más
    abajo y no puede inventarse capacidades que el transporte real no tiene.
    """

    def __init__(self, replies):
        self._replies = list(replies)
        self.sent: list = []
        self.closed = False

    def exchange(self, send, read="line"):
        self.sent.append(send)
        if not self._replies:
            return None
        reply = self._replies.pop(0)
        return Response(status=0, body=reply, headers={}) if reply is not None else None

    def close(self):
        self.closed = True


def _network_open_for(replies):
    """Un ``network_open`` que reparte una única sesión de orquestación."""
    session = _FakeNetworkSession(replies)

    def open_(host, port):
        return session
    open_.session = session
    return open_


def _findings_for(check_id, sock, service):
    """Corre el feed sobre ``service`` con el transporte real y filtra por check."""
    runtime = CheckRuntime(load_checks(), lambda *a: None, network_open=_network_open_over(sock))
    return [f for f in runtime.run("h", [service]) if f["check_id"] == check_id]


# ------------------------------------------ ftp-anonymous-login (comportamiento)

def test_ftp_anonymous_login_confirmed_when_both_steps_succeed():
    sock = _FakeNetSocket(
        greeting=_FTP_BANNER,
        replies=[b"331 Please specify the password.\r\n", b"230 Login successful.\r\n"],
    )

    ftp = _findings_for("lybra:ftp-anonymous-login@2", sock, _FTP)

    assert len(ftp) == 1
    assert ftp[0]["qod"] == 99 and ftp[0]["confirmed"] is True
    assert ftp[0]["category"] == "default_credentials"
    assert ftp[0]["port"] == 21
    # Los dos pasos de la secuencia de login fueron por la misma sesión, en orden.
    assert sock.sent == b"USER anonymous\r\nPASS anonymous@lybra.local\r\n"


def test_ftp_anonymous_login_confirmed_with_a_multiline_banner():
    sock = _FakeNetSocket(
        greeting=_FTP_MULTILINE_BANNER,
        replies=[b"331 Please specify the password.\r\n", b"230 Login successful.\r\n"],
    )
    assert len(_findings_for("lybra:ftp-anonymous-login@2", sock, _FTP)) == 1


def test_ftp_anonymous_login_absent_when_credentials_rejected():
    sock = _FakeNetSocket(
        greeting=_FTP_BANNER,
        replies=[b"331 Please specify the password.\r\n", b"530 Login incorrect.\r\n"],
    )
    assert _findings_for("lybra:ftp-anonymous-login@2", sock, _FTP) == []


def test_ftp_anonymous_login_abandoned_when_the_server_says_nothing():
    sock = _FakeNetSocket(greeting=b"", replies=[])
    assert _findings_for("lybra:ftp-anonymous-login@2", sock, _FTP) == []


def test_ftp_anonymous_login_abandoned_on_connect_failure():
    findings = CheckRuntime(
        load_checks(), lambda *a: None, network_open=lambda host, port: None
    ).run("h", [_FTP])
    assert not any(f["check_id"] == "lybra:ftp-anonymous-login@2" for f in findings)


# ------------------------------- redis-unauthenticated-access (comportamiento)

def test_redis_unauthenticated_access_confirmed_when_info_succeeds():
    sock = _FakeNetSocket(replies=[_REDIS_INFO])

    redis_findings = _findings_for("lybra:redis-unauthenticated-access@2", sock, _REDIS)

    assert len(redis_findings) == 1
    assert redis_findings[0]["qod"] == 99 and redis_findings[0]["confirmed"] is True
    assert redis_findings[0]["category"] == "default_credentials"
    assert sock.sent == b"INFO\r\n"


def test_redis_unauthenticated_access_absent_when_auth_required():
    sock = _FakeNetSocket(replies=[b"-NOAUTH Authentication required.\r\n"])
    assert _findings_for("lybra:redis-unauthenticated-access@2", sock, _REDIS) == []


# ------------------------------------------------- selección y orquestación

def test_network_checks_never_run_without_a_network_open_callable():
    # Mirrors test_only_http_services_are_probed: omitting network_open must
    # cost nothing, not silently probe with some default.
    findings = CheckRuntime(load_checks(), lambda *a: None).run("h", [_FTP])
    assert findings == []


def test_only_ftp_services_are_probed_by_network_checks():
    open_ = _network_open_for(["331 x", "230 x"])
    CheckRuntime(load_checks(), lambda *a: None, network_open=open_).run("h", [_HTTP])
    assert open_.session.sent == []            # nothing exchanged for a non-FTP service

    assert is_ftp_service(_FTP) is True
    assert is_ftp_service(_HTTP) is False


def test_only_redis_services_are_probed_by_redis_check():
    open_ = _network_open_for(["$40\r\nredis_version:7.0.11\r\n"])
    CheckRuntime(load_checks(), lambda *a: None, network_open=open_).run("h", [_HTTP])
    assert open_.session.sent == []            # nothing exchanged for a non-Redis service

    assert is_redis_service(_REDIS) is True
    assert is_redis_service(_HTTP) is False


def test_the_session_of_a_network_check_is_always_closed():
    open_ = _network_open_for([None])
    CheckRuntime(load_checks(), lambda *a: None, network_open=open_).run("h", [_FTP])
    assert open_.session.closed is True


# ----------------------------------------------- NetworkProbe (socket falso)

def test_network_probe_session_reads_banner_without_sending():
    sock = _FakeNetSocket(greeting=_FTP_BANNER)
    session = NetworkProbe(connect=lambda address, timeout: sock).open("10.0.0.5", 21)

    response = session.exchange(None)

    assert response.body == "220 (vsFTPd 3.0.3)"
    assert sock.sent == b""                    # nothing written for a banner-only read


def test_network_probe_session_sends_then_reads():
    sock = _FakeNetSocket(replies=[b"331 Please specify the password.\r\n"])
    session = NetworkProbe(connect=lambda address, timeout: sock).open("10.0.0.5", 21)

    response = session.exchange("USER anonymous\r\n")

    assert sock.sent == b"USER anonymous\r\n"
    assert response.body == "331 Please specify the password."
    session.close()
    assert sock.closed is True


def test_network_probe_session_reads_a_line_split_across_recv_chunks():
    # Un servidor real no entrega la línea entera de una vez: el criterio de
    # fin de respuesta es del protocolo, no del tamaño del trozo que llegue.
    sock = _FakeNetSocket(greeting=_FTP_BANNER, chunk_size=1)
    session = NetworkProbe(connect=lambda address, timeout: sock).open("10.0.0.5", 21)
    assert session.exchange(None).body == "220 (vsFTPd 3.0.3)"


def test_network_probe_returns_none_on_connect_failure():
    def failing_connect(address, timeout):
        raise OSError("connection refused")
    assert NetworkProbe(connect=failing_connect).open("10.0.0.5", 21) is None


def test_network_session_exchange_returns_none_on_empty_read():
    sock = _FakeNetSocket(greeting=b"")
    session = NetworkProbe(connect=lambda address, timeout: sock).open("10.0.0.5", 21)
    assert session.exchange(None) is None


def test_network_session_no_longer_reads_one_byte_per_syscall():
    # El lector anterior pedía los bytes de uno en uno: una llamada al sistema
    # por byte recibido. Una línea corta debe costar un puñado de recv, no uno
    # por carácter.
    sock = _FakeNetSocket(greeting=_FTP_BANNER)
    session = NetworkProbe(connect=lambda address, timeout: sock).open("10.0.0.5", 21)

    session.exchange(None)

    assert sock.recv_calls < len(_FTP_BANNER)


# ------------------------------------------- modos de lectura (``read:``)
#
# Dónde termina una respuesta es un hecho del protocolo, no del transporte. Un
# modo mal elegido no da error: lee los bytes equivocados y el check deja de
# disparar en silencio, que es el fallo que este bloque existe para impedir.

def _session_over(greeting=b"", replies=()):
    sock = _FakeNetSocket(greeting=greeting, replies=replies)
    return NetworkProbe(connect=lambda address, timeout: sock).open("10.0.0.5", 21)


def test_read_line_stops_at_the_first_newline():
    session = _session_over(greeting=b"331 Primera\r\n230 Segunda\r\n")
    assert session.exchange(None, read="line").body == "331 Primera"


def test_read_block_joins_the_continuation_lines_of_a_status_reply():
    # Un código seguido de "-" anuncia que la respuesta sigue; el mismo código
    # seguido de espacio la cierra.
    session = _session_over(greeting=b"220-Primera\r\n220-Segunda\r\n220 Ultima\r\n")

    body = session.exchange(None, read="block").body

    assert "Primera" in body and "Segunda" in body and "Ultima" in body


def test_read_block_stops_at_a_line_that_is_not_a_continuation():
    # Con una respuesta de una sola línea, "block" se comporta como "line": no
    # se queda esperando más datos que no van a llegar.
    session = _session_over(greeting=b"220 Unica\r\n331 De la siguiente respuesta\r\n")
    assert session.exchange(None, read="block").body == "220 Unica"


def test_read_block_does_not_over_read_a_banner_without_status_codes():
    # Un saludo que no usa códigos de estado (SSH, por ejemplo) tampoco es una
    # continuación, así que cierra el bloque en la primera línea. Sin esta
    # regla, "block" se quedaría leyendo hasta agotar el tiempo de espera.
    session = _session_over(greeting=b"SSH-2.0-OpenSSH_8.9\r\nmas cosas\r\n")
    assert session.exchange(None, read="block").body == "SSH-2.0-OpenSSH_8.9"


def test_read_resp_bulk_returns_the_announced_payload_and_not_its_header():
    session = _session_over(replies=[_REDIS_INFO])

    body = session.exchange("INFO\r\n", read="resp-bulk").body

    assert body.startswith("# Server")
    assert "redis_version:7.0.11" in body
    assert "$" not in body                 # la línea de longitud no forma parte del contenido


def test_read_resp_bulk_returns_a_non_bulk_reply_untouched():
    # Un error de Redis es una línea suelta que empieza por "-": ya es la
    # respuesta entera, y es justo la que el matcher negativo tiene que ver.
    session = _session_over(replies=[b"-NOAUTH Authentication required.\r\n"])
    assert session.exchange("INFO\r\n", read="resp-bulk").body == "-NOAUTH Authentication required."


def test_read_resp_bulk_leaves_the_trailing_bytes_for_the_next_read():
    # RESP cierra el bulk con un CRLF que no cuenta en la longitud anunciada.
    # Ese sobrante se queda en el buffer y no puede comerse la respuesta
    # siguiente.
    session = _session_over(replies=[b"$2\r\nOK\r\n+PONG\r\n"])

    assert session.exchange("INFO\r\n", read="resp-bulk").body == "OK"
    assert session.exchange("PING\r\n", read="line").body == "+PONG"


def test_a_truncated_bulk_reply_returns_what_arrived_instead_of_hanging():
    # El servidor anuncia 3116 bytes y cierra la conexión tras unos pocos.
    session = _session_over(replies=[b"$3116\r\nredis_version:7.0.11\r\n"])
    assert "redis_version:7.0.11" in session.exchange("INFO\r\n", read="resp-bulk").body


# ------------------------------------ el feed declara cómo termina cada respuesta

def test_the_bundled_network_checks_declare_their_read_semantics():
    checks = {check.id: check for check in load_checks()}

    ftp = checks["ftp-anonymous-login"]
    assert ftp.expect_banner is True       # FTP saluda al conectar
    assert [request.read for request in ftp.requests] == ["block", "block"]

    redis_check = checks["redis-unauthenticated-access"]
    assert redis_check.expect_banner is False   # Redis no saluda
    assert [request.read for request in redis_check.requests] == ["resp-bulk"]


def test_a_request_without_a_declared_read_mode_keeps_the_original_behaviour():
    git = next(check for check in load_checks() if check.id == "git-config-exposure")
    assert git.requests[0].read == "line"
    assert git.expect_banner is False


def test_an_unknown_read_mode_fails_at_load_time(tmp_path):
    # Un modo que nadie implementa es un bug del feed. Si se ignorase en
    # silencio, el check leería una línea donde el protocolo necesita un
    # bloque y no dispararía nunca: exactamente el falso negativo silencioso
    # que este cambio elimina.
    feed = tmp_path / "feed.json"
    feed.write_text(json.dumps({"checks": [{
        "id": "modo-inventado", "version": 1, "type": "network",
        "category": "network_config", "severity": "HIGH", "service": "ftp",
        "requests": [{"send": "PING\r\n", "read": "telepatia", "matchers": []}],
        "finding": {"title": "x"},
    }]}), encoding="utf-8")

    with pytest.raises(ValueError, match="telepatia"):
        load_checks(str(feed))


# --------------------------- a qué protocolo aplica un check ``network``
#
# Un check `network` dice a qué protocolo va dirigido con una cadena
# (`service: ftp`), y el runtime necesita el predicado que decide si un
# servicio descubierto es de ese protocolo. Ese mapa se mantenía a mano y tenía
# dos entradas cuando el módulo ya definía once predicados: un check de SMTP o
# de MySQL se cargaba, se validaba, y se descartaba sin decir nada.

_MYSQL = Service(3306, "tcp", "mysql", "", "", None)

_MYSQL_NETWORK_FEED = {
    "checks": [{
        "id": "mysql-saluda", "version": 1, "type": "network",
        "category": "network_config", "severity": "INFO", "service": "mysql",
        "mode": "safe",
        "requests": [{"matchers": [{"type": "word", "part": "body", "words": ["mysql_native_password"]}]}],
        "finding": {"title": "MySQL contesta"},
    }]
}


def _feed_file(tmp_path, document):
    feed = tmp_path / "feed.json"
    feed.write_text(json.dumps(document), encoding="utf-8")
    return str(feed)


def test_every_service_predicate_is_available_to_a_network_check():
    # Invariante al estilo de test_config_shape: definir un predicado nuevo
    # basta para poder escribir checks de ese protocolo. Sin esto, cada
    # protocolo costaba dos ediciones y olvidar la segunda no daba error.
    predicates = {
        name for name in dir(checks_mod)
        if name.startswith("is_") and name.endswith("_service")
    }
    esperados = {name[len("is_"):-len("_service")] for name in predicates}

    assert esperados == set(checks_mod._NETWORK_SERVICE_MATCHERS)
    assert len(esperados) > 2, "el mapa derivado debe cubrir más que ftp y redis"


def test_a_network_check_for_a_protocol_that_nobody_wired_by_hand_runs(tmp_path):
    # MySQL nunca estuvo en la tabla escrita a mano, y su predicado sí existía.
    checks = load_checks(_feed_file(tmp_path, _MYSQL_NETWORK_FEED))
    sock = _FakeNetSocket(greeting=b"5.7.42-log\x00mysql_native_password\n")

    findings = CheckRuntime(
        checks, lambda *a: None, network_open=_network_open_over(sock)
    ).run("h", [_MYSQL])

    assert [f["check_id"] for f in findings] == ["lybra:mysql-saluda@1"]


def test_an_unknown_service_fails_at_load_time(tmp_path):
    # Un check que no puede aplicar a nada es un bug del feed. Si se ignora,
    # se confunde con "no ha disparado contra este host", que es normal — y
    # así nadie se entera nunca.
    document = {"checks": [dict(_MYSQL_NETWORK_FEED["checks"][0], id="protocolo-inventado",
                                service="noexiste")]}

    with pytest.raises(ValueError, match="noexiste"):
        load_checks(_feed_file(tmp_path, document))


def test_every_network_service_in_the_bundled_feed_has_a_predicate():
    network_services = {check.service for check in load_checks() if check.type == "network"}
    assert network_services <= set(checks_mod._NETWORK_SERVICE_MATCHERS)


def test_a_check_that_skipped_the_loader_with_an_unknown_service_is_logged(caplog):
    # Los checks traducidos de plantillas de Nuclei se construyen directamente,
    # sin pasar por el cargador, así que su `service` es lo que dijera el
    # documento de origen. Ahí el aviso lo tiene que dar el runtime.
    translated = checks_mod.Check(
        id="traducido", version=1, type="network", category="network_config",
        severity="INFO", service="protocolo-de-otro-mundo", mode="safe",
        requests=(), finding={}, namespace="nuclei",
    )
    sock = _FakeNetSocket(greeting=b"lo que sea\r\n")

    with caplog.at_level("WARNING"):
        findings = CheckRuntime(
            [translated], lambda *a: None, network_open=_network_open_over(sock)
        ).run("h", [_FTP])

    assert findings == []
    assert "protocolo-de-otro-mundo" in caplog.text


# --------------------------------------------------- ``type: "script"`` (Fase R)

class _FakeSmbProbe:
    """Stands in for SmbProbe: returns a canned (dialect, security_mode) pair.

    ``None`` models a failed negotiation (unreachable, or a reply that did not
    parse), which must never be read as "signing is not required".
    """

    def __init__(self, result):
        self._result = result
        self.calls = []

    def fetch(self, host, port=445):
        self.calls.append((host, port))
        return self._result


_SMB = Service(445, "tcp", "microsoft-ds", "", "", None)

# MS-SMB2 §2.2.4: SecurityMode bit 0x0002 is SIGNING_REQUIRED; 0x0001 alone is
# SIGNING_ENABLED, i.e. offered but not enforced — exactly the finding's target.
_DIALECT_302 = 0x0302
_SIGNING_ENABLED_ONLY = 0x0001
_SIGNING_REQUIRED = 0x0003


def _script_runtime(probe, mode="safe"):
    plugins = {"smb-signing-not-required": SmbSigningNotRequiredPlugin(probe=probe)}
    return CheckRuntime(
        load_checks(),
        _fetcher({}),
        mode=mode,
        script_plugins=plugins,
    )


def test_smb_signing_not_required_fires_when_signing_is_only_enabled():
    probe = _FakeSmbProbe((_DIALECT_302, _SIGNING_ENABLED_ONLY))
    findings = _script_runtime(probe).run("10.0.0.5", [_SMB])

    smb = [f for f in findings if f["check_id"] == "lybra:smb-signing-not-required@1"]
    assert len(smb) == 1
    assert smb[0]["confirmed"] is True
    assert smb[0]["qod"] == 99
    assert smb[0]["port"] == 445
    assert probe.calls == [("10.0.0.5", 445)]


def test_smb_signing_not_required_silent_when_signing_is_enforced():
    probe = _FakeSmbProbe((_DIALECT_302, _SIGNING_REQUIRED))
    findings = _script_runtime(probe).run("10.0.0.5", [_SMB])
    assert findings == []


def test_smb_script_check_abandoned_when_negotiation_fails():
    """No evidence must never be read as a positive — the rule every family follows."""
    findings = _script_runtime(_FakeSmbProbe(None)).run("10.0.0.5", [_SMB])
    assert findings == []


def test_smb_script_check_silent_on_unrecognised_dialect():
    probe = _FakeSmbProbe((0xFFFF, _SIGNING_ENABLED_ONLY))
    findings = _script_runtime(probe).run("10.0.0.5", [_SMB])
    assert findings == []


def test_the_smb_verdict_survives_renaming_the_fingerprint_label(monkeypatch):
    """Invariante: la etiqueta legible no es el protocolo entre dos piezas.

    El plugin decidía buscando la subcadena ``"firma no requerida"`` dentro del
    texto que produce ``fingerprint_smb``. Con eso, traducir esa etiqueta al
    inglés —o corregirle una tilde— apagaba el check sin que fallara nada: se
    ejecutaba, devolvía ``False``, y el SMB sin firma dejaba de aparecer.

    Aquí se renombra la etiqueta a propósito, dejando intacto el dato que sí
    importa (el ``SecurityMode``), y el veredicto tiene que ser el mismo en los
    dos sentidos.
    """
    from src.modules.features.themis.lybra import script_checks as script_module

    original = script_module.fingerprint_smb

    def renamed(dialect_revision, security_mode):
        fingerprint = original(dialect_revision, security_mode)
        etiqueta = None if fingerprint.product is None else "SMB2 (unsigned!)"
        return type(fingerprint)(
            product=etiqueta, version=fingerprint.version, confidence=fingerprint.confidence,
        )

    monkeypatch.setattr(script_module, "fingerprint_smb", renamed)

    sin_firma = _FakeSmbProbe((_DIALECT_302, _SIGNING_ENABLED_ONLY))
    con_firma = _FakeSmbProbe((_DIALECT_302, _SIGNING_REQUIRED))

    dispara = _script_runtime(sin_firma).run("10.0.0.5", [_SMB])
    calla = _script_runtime(con_firma).run("10.0.0.5", [_SMB])

    assert [f["check_id"] for f in dispara] == ["lybra:smb-signing-not-required@1"]
    assert calla == []


def test_script_checks_never_run_without_plugins_injected():
    """The default wiring of a caller that knows nothing about scripts."""
    findings = CheckRuntime(load_checks(), _fetcher({})).run("10.0.0.5", [_SMB])
    assert findings == []


def test_only_smb_services_are_probed_by_the_smb_script_check():
    probe = _FakeSmbProbe((_DIALECT_302, _SIGNING_ENABLED_ONLY))
    findings = _script_runtime(probe).run("10.0.0.5", [_HTTP])

    assert probe.calls == []
    assert [f for f in findings if f["check_id"].startswith("lybra:smb-")] == []


def test_a_raising_plugin_costs_its_own_check_not_the_scan():
    class _ExplodingProbe:
        def fetch(self, host, port=445):
            raise RuntimeError("malformed reply from some appliance")

    findings = _script_runtime(_ExplodingProbe()).run("10.0.0.5", [_SMB])
    assert findings == []


def test_script_check_declares_its_plugin_in_the_bundled_feed():
    """The feed entry and the registry must agree, or the check silently never runs."""
    check = next(c for c in load_checks() if c.id == "smb-signing-not-required")
    assert check.type == "script"
    assert check.script in default_script_plugins()


# ------------------------------------------ snmp-default-community (Ronda 1)

class _FakeSnmpProbe:
    """Stands in for SnmpProbe: returns a canned sysDescr string, or ``None``
    for "no reply" — the same no-evidence-no-finding contract as _FakeSmbProbe.
    """

    def __init__(self, result):
        self._result = result
        self.calls = []

    def fetch(self, host, port=161, community="public"):
        self.calls.append((host, port, community))
        return self._result


_SNMP = Service(161, "udp", "snmp", "", "", None)


def _snmp_runtime(probe, mode="safe"):
    plugins = {"snmp-default-community": SnmpDefaultCommunityPlugin(probe=probe)}
    return CheckRuntime(load_checks(), _fetcher({}), mode=mode, script_plugins=plugins)


def test_snmp_default_community_fires_when_public_answers():
    probe = _FakeSnmpProbe("Linux router 5.4.0")
    findings = _snmp_runtime(probe).run("10.0.0.5", [_SNMP])

    snmp = [f for f in findings if f["check_id"] == "lybra:snmp-default-community@1"]
    assert len(snmp) == 1
    assert snmp[0]["confirmed"] is True
    assert snmp[0]["qod"] == 99
    assert snmp[0]["port"] == 161
    assert probe.calls == [("10.0.0.5", 161, "public")]


def test_snmp_default_community_silent_when_no_reply():
    findings = _snmp_runtime(_FakeSnmpProbe(None)).run("10.0.0.5", [_SNMP])
    assert findings == []


def test_snmp_plugin_skips_tcp_161():
    """El mismo puerto por TCP nunca debe recibir un datagrama SNMP."""
    tcp_snmp = Service(161, "tcp", "snmp", "", "", None)
    probe = _FakeSnmpProbe("Linux router 5.4.0")
    findings = _snmp_runtime(probe).run("10.0.0.5", [tcp_snmp])

    assert probe.calls == []
    assert findings == []


def test_snmp_check_in_bundled_feed():
    check = next(c for c in load_checks() if c.id == "snmp-default-community")
    assert check.type == "script"
    assert check.service == "snmp"
    assert check.script in default_script_plugins()


# ------------------------------------------- feed en YAML y compatibilidad (Fase R)

def test_bundled_feed_is_yaml():
    """El feed propio vive en YAML desde la Fase R; el JSON se retiró."""
    from src.modules.features.themis.lybra.checks import _BUNDLED_FEED
    assert _BUNDLED_FEED.suffix == ".yaml"
    assert _BUNDLED_FEED.exists()


def test_yaml_and_json_feeds_parse_to_identical_checks(tmp_path):
    """La migración es un cambio de formato, no de comportamiento.

    Ambos deserializadores alimentan el mismo ``_parse_check`` con dicts
    idénticos, así que un feed escrito en cualquiera de los dos formatos debe
    producir objetos ``Check`` iguales campo a campo. Es lo que convirtió la
    migración del feed propio en algo verificable en vez de un acto de fe.
    """
    document = {
        "feedVersion": "test-feed-1",
        "checks": [
            {
                "id": "some-check", "version": 2, "type": "http",
                "category": "exposed_path", "severity": "HIGH", "service": "http",
                "mode": "safe",
                "requests": [{
                    "method": "GET", "path": "/x", "matchers-condition": "or",
                    "matchers": [
                        {"type": "status", "value": [200, 302]},
                        {"type": "word", "part": "header", "words": ["a"], "negative": True},
                    ],
                }],
                "finding": {"title": "T", "qod": 99, "confirmed": True},
            },
            {
                "id": "a-tls-check", "version": 1, "type": "tls",
                "category": "tls", "severity": "LOW", "service": "https",
                "mode": "aggressive", "tlsRule": "expired",
                "finding": {"title": "T2"},
            },
        ],
    }
    as_json = tmp_path / "feed.json"
    as_yaml = tmp_path / "feed.yaml"
    as_json.write_text(json.dumps(document), encoding="utf-8")
    as_yaml.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")

    assert load_checks(str(as_json)) == load_checks(str(as_yaml))


def test_yml_extension_is_accepted_too(tmp_path):
    feed = tmp_path / "feed.yml"
    feed.write_text(yaml.safe_dump(_AGGRESSIVE_FEED), encoding="utf-8")
    assert len(load_checks(str(feed))) == 1


def test_an_empty_yaml_feed_yields_no_checks(tmp_path):
    """Un fichero vacío parsea a None en YAML; no debe reventar el cargador."""
    feed = tmp_path / "feed.yaml"
    feed.write_text("", encoding="utf-8")
    assert load_checks(str(feed)) == []


def test_yaml_feed_supports_comments(tmp_path):
    """La razón de fondo de la migración: poder explicar por qué existe un check."""
    feed = tmp_path / "feed.yaml"
    feed.write_text(
        "# Este comentario es el motivo de que el feed sea YAML.\n"
        "feedVersion: commented-1\n"
        "checks:\n"
        "  - id: documented-check   # y este también\n"
        "    version: 1\n"
        "    type: http\n"
        "    requests:\n"
        "      - path: /x\n"
        "        matchers:\n"
        "          - {type: status, value: [200]}\n"
        "    finding: {title: T}\n",
        encoding="utf-8",
    )
    checks = load_checks(str(feed))
    assert [c.id for c in checks] == ["documented-check"]
