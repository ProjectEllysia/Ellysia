"""Tests unitarios de los helpers compartidos de endpoints."""

import socket

import pytest
from flask import Flask

from src.modules.shared._endpoints import (
    current_actor,
    normalize_target
)
from src.modules.shared._exceptions import MissingParameterError

pytestmark = pytest.mark.unit


# --------------------------------------------------------------- normalize_target

def test_normalize_target_accepts_plain_ip():
    ip, hostname = normalize_target("8.8.8.8")
    assert ip == "8.8.8.8"
    assert hostname == "8.8.8.8"


def test_normalize_target_strips_url_scheme_and_port():
    ip, hostname = normalize_target("http://1.2.3.4:8080/path")
    assert ip == "1.2.3.4"


def test_normalize_target_resolves_domain(monkeypatch):
    monkeypatch.setattr(socket, "gethostbyname", lambda host: "93.184.216.34")
    ip, hostname = normalize_target("example.com")
    assert ip == "93.184.216.34"
    assert hostname == "example.com"


def test_normalize_target_unresolvable_raises(monkeypatch):
    def _boom(host):
        raise socket.gaierror("no such host")

    monkeypatch.setattr(socket, "gethostbyname", _boom)
    with pytest.raises(ValueError):
        normalize_target("does-not-exist.invalid")


# ------------------------------------------- helpers que dependen de flask.request

@pytest.fixture()
def flask_ctx():
    app = Flask(__name__)
    return app


def test_current_actor_anonymous(flask_ctx):
    with flask_ctx.test_request_context("/"):
        assert current_actor() == "anonymous"


def test_current_actor_with_user(flask_ctx):
    with flask_ctx.test_request_context("/") as ctx:
        ctx.request.current_username = "alice"
        ctx.request.current_user_id = 7
        assert current_actor() == "alice(id=7)"
