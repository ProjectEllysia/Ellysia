"""Unit tests for the Lybra active-check runtime (Fase R).

Pure: an injected ``fetch`` returns crafted responses, so no network. Exercises
the bundled feed, the matchers, HTTP-service selection and the safe/aggressive
gate.
"""

import json

import pytest

from src.modules.features.themis.lybra import (
    load_checks,
    CheckRuntime,
    Response,
    is_http_service,
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
