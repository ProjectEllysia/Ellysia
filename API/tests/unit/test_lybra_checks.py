"""Unit tests for the Lybra active-check runtime (Fase R).

Pure: an injected ``fetch``/``network_open`` returns crafted responses, so no
real network. Exercises the bundled feed, the matchers, HTTP-service
selection, the safe/aggressive gate, and the ``type: "network"`` family Fase N
adds (a fake, in-memory session standing in for a real TCP connection).
"""

import json

import pytest

from src.modules.features.themis.lybra import (
    load_checks,
    CheckRuntime,
    NetworkProbe,
    Response,
    SmbSigningNotRequiredPlugin,
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

_FTP = Service(21, "tcp", "ftp", "", "", None)


class _FakeNetworkSession:
    """A scripted stand-in for a real TCP connection: each ``exchange`` call
    consumes the next canned reply, in order — exactly what a login sequence
    like FTP's USER/PASS needs from a single, shared connection."""

    def __init__(self, replies):
        self._replies = list(replies)
        self.sent: list = []
        self.closed = False

    def exchange(self, send):
        self.sent.append(send)
        if not self._replies:
            return None
        reply = self._replies.pop(0)
        return Response(status=0, body=reply, headers={}) if reply is not None else None

    def close(self):
        self.closed = True


def _network_open_for(replies):
    """A ``network_open`` that hands out one fresh scripted session."""
    session = _FakeNetworkSession(replies)

    def open_(host, port):
        return session
    open_.session = session
    return open_


def test_ftp_anonymous_login_confirmed_when_both_steps_succeed():
    open_ = _network_open_for(["331 Please specify the password.", "230 Login successful."])
    findings = CheckRuntime(load_checks(), lambda *a: None, network_open=open_).run("h", [_FTP])

    ftp = [f for f in findings if f["check_id"] == "lybra:ftp-anonymous-login@1"]
    assert len(ftp) == 1
    assert ftp[0]["qod"] == 99 and ftp[0]["confirmed"] is True
    assert ftp[0]["category"] == "default_credentials"
    assert ftp[0]["port"] == 21
    # Both steps of the login sequence went over the same session, in order.
    assert open_.session.sent == ["USER anonymous\r\n", "PASS anonymous@lybra.local\r\n"]


def test_ftp_anonymous_login_absent_when_credentials_rejected():
    open_ = _network_open_for(["331 Please specify the password.", "530 Login incorrect."])
    findings = CheckRuntime(load_checks(), lambda *a: None, network_open=open_).run("h", [_FTP])
    assert not any(f["check_id"] == "lybra:ftp-anonymous-login@1" for f in findings)


def test_ftp_anonymous_login_abandoned_on_connect_failure():
    findings = CheckRuntime(
        load_checks(), lambda *a: None, network_open=lambda host, port: None
    ).run("h", [_FTP])
    assert not any(f["check_id"] == "lybra:ftp-anonymous-login@1" for f in findings)


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


# ---------------------------------------- redis-unauthenticated-access (Fase N)

_REDIS = Service(6379, "tcp", "redis", "", "", None)


def test_redis_unauthenticated_access_confirmed_when_info_succeeds():
    reply = "$120\r\n# Server\r\nredis_version:7.0.11\r\nredis_mode:standalone\r\n"
    open_ = _network_open_for([reply])
    findings = CheckRuntime(load_checks(), lambda *a: None, network_open=open_).run("h", [_REDIS])

    redis_findings = [f for f in findings if f["check_id"] == "lybra:redis-unauthenticated-access@1"]
    assert len(redis_findings) == 1
    assert redis_findings[0]["qod"] == 99 and redis_findings[0]["confirmed"] is True
    assert redis_findings[0]["category"] == "default_credentials"
    assert open_.session.sent == ["INFO\r\n"]


def test_redis_unauthenticated_access_absent_when_auth_required():
    open_ = _network_open_for(["-NOAUTH Authentication required.\r\n"])
    findings = CheckRuntime(load_checks(), lambda *a: None, network_open=open_).run("h", [_REDIS])
    assert not any(f["check_id"] == "lybra:redis-unauthenticated-access@1" for f in findings)


def test_only_redis_services_are_probed_by_redis_check():
    open_ = _network_open_for(["$40\r\nredis_version:7.0.11\r\n"])
    CheckRuntime(load_checks(), lambda *a: None, network_open=open_).run("h", [_HTTP])
    assert open_.session.sent == []            # nothing exchanged for a non-Redis service

    assert is_redis_service(_REDIS) is True
    assert is_redis_service(_HTTP) is False


# --------------------------------------------- NetworkProbe (fake socket)

class _FakeNetSocket:
    """A byte-stream-backed stand-in for a real network-check socket."""

    def __init__(self, data: bytes):
        self._buf = data
        self.sent = b""
        self.closed = False

    def recv(self, n: int) -> bytes:
        chunk, self._buf = self._buf[:n], self._buf[n:]
        return chunk

    def sendall(self, data: bytes) -> None:
        self.sent += data

    def close(self) -> None:
        self.closed = True


def test_network_probe_session_reads_banner_without_sending():
    fake_sock = _FakeNetSocket(b"220 (vsFTPd 2.3.4)\r\n")
    session = NetworkProbe(connect=lambda addr, timeout: fake_sock).open("10.0.0.5", 21)

    resp = session.exchange(None)

    assert resp.body == "220 (vsFTPd 2.3.4)"
    assert fake_sock.sent == b""               # nothing written for a banner-only read


def test_network_probe_session_sends_then_reads():
    fake_sock = _FakeNetSocket(b"331 Please specify the password.\r\n")
    session = NetworkProbe(connect=lambda addr, timeout: fake_sock).open("10.0.0.5", 21)

    resp = session.exchange("USER anonymous\r\n")

    assert fake_sock.sent == b"USER anonymous\r\n"
    assert resp.body == "331 Please specify the password."
    session.close()
    assert fake_sock.closed is True


def test_network_probe_returns_none_on_connect_failure():
    def failing_connect(addr, timeout):
        raise OSError("connection refused")
    assert NetworkProbe(connect=failing_connect).open("10.0.0.5", 21) is None


def test_network_session_exchange_returns_none_on_empty_read():
    fake_sock = _FakeNetSocket(b"")
    session = NetworkProbe(connect=lambda addr, timeout: fake_sock).open("10.0.0.5", 21)
    assert session.exchange(None) is None


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
