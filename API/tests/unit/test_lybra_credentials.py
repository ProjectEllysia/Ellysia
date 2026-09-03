"""El motor de credenciales por defecto (Fase D, L31).

Es la única familia de detección de Lybra que escribe en el objetivo, así que
lo que estos tests protegen no es sólo "encuentra el par correcto" sino las
tres garantías que hacen esa escritura segura: el presupuesto de intentos se
cuenta **por cuenta**, para en el primer éxito, y la contraseña que funcionó
no aparece nunca en el hallazgo ni en su evidencia.
"""

import pytest

from src.modules.features.themis.lybra.checks import Response, Service
from src.modules.features.themis.lybra.credentials import (
    CredentialEntry,
    CredentialPair,
    CredentialRuntime,
    load_credentials,
    validate_credentials,
)
from src.modules.features.themis.lybra.checks import Matcher

pytestmark = pytest.mark.unit

_SVC = Service(80, "tcp", "http", None, None, None)


def _entry(accounts, matchers=None, **kwargs):
    if matchers is None:
        matchers = (Matcher(type="status", values=(200,)),)
    return CredentialEntry(
        id=kwargs.pop("id", "test-panel"),
        version=kwargs.pop("version", 1),
        service=kwargs.pop("service", "http"),
        path=kwargs.pop("path", "/admin"),
        accounts=tuple(accounts),
        matchers=tuple(matchers),
        **kwargs,
    )


# =============================================== el par correcto dispara

def test_a_correct_pair_produces_a_confirmed_finding():
    entry = _entry([CredentialPair("admin", "admin")])

    def fetch(host, port, method, path, body, headers):
        assert headers == {"Authorization": "Basic YWRtaW46YWRtaW4="}
        return Response(200, "bienvenido", {})

    findings = CredentialRuntime([entry], fetch).run("10.0.0.1", [_SVC])
    assert len(findings) == 1
    assert findings[0]["category"] == "default_credentials"
    assert findings[0]["confirmed"] is True
    assert findings[0]["qod"] == 99


def test_a_wrong_pair_produces_nothing():
    entry = _entry([CredentialPair("admin", "admin")])

    def fetch(host, port, method, path, body, headers):
        return Response(401, "unauthorized", {})

    assert CredentialRuntime([entry], fetch).run("10.0.0.1", [_SVC]) == []


# =============================================== plaintext, en ningún sitio

def test_the_password_never_appears_in_the_finding():
    entry = _entry([CredentialPair("admin", "s3cr3t-p4ss")])

    def fetch(host, port, method, path, body, headers):
        return Response(200, "ok", {})

    finding = CredentialRuntime([entry], fetch).run("10.0.0.1", [_SVC])[0]
    assert "s3cr3t-p4ss" not in str(finding)


def test_the_password_never_appears_in_the_evidence():
    entry = _entry([CredentialPair("admin", "s3cr3t-p4ss")])

    def fetch(host, port, method, path, body, headers):
        return Response(200, "ok", {"X-Served-By": "app-1"})

    finding = CredentialRuntime([entry], fetch, capture_evidence=True).run("10.0.0.1", [_SVC])[0]
    assert "_evidence" in finding
    assert "s3cr3t-p4ss" not in str(finding["_evidence"])
    assert finding["_evidence"]["payload"]["username"] == "admin"


# =============================================== presupuesto por cuenta

def test_the_budget_is_counted_per_account_not_per_service():
    """Tres contraseñas contra 'admin' y una contra 'root' en el mismo
    servicio: con el tope en 2, a 'admin' solo le quedan dos intentos, pero a
    'root' — una cuenta distinta — le sigue quedando su propio presupuesto
    entero."""
    entry = _entry([
        CredentialPair("admin", "wrong1"),
        CredentialPair("admin", "wrong2"),
        CredentialPair("admin", "wrong3"),   # nunca se llega: tope de 2 para 'admin'
        CredentialPair("root", "toor"),      # cuenta distinta, presupuesto propio
    ])
    tried = []

    def fetch(host, port, method, path, body, headers):
        tried.append(headers["Authorization"])
        if headers["Authorization"] == _basic("root", "toor"):
            return Response(200, "ok", {})
        return Response(401, "no", {})

    findings = CredentialRuntime([entry], fetch, max_attempts_per_account=2).run("10.0.0.1", [_SVC])
    assert len(findings) == 1
    assert len(tried) == 3          # 2 de admin + 1 de root (éxito, para ahí)
    assert _basic("admin", "wrong3") not in tried


def test_stops_at_the_first_successful_account():
    entry = _entry([
        CredentialPair("admin", "admin"),
        CredentialPair("root", "toor"),
    ])
    tried = []

    def fetch(host, port, method, path, body, headers):
        tried.append(headers["Authorization"])
        return Response(200, "ok", {})   # la primera cuenta ya funciona

    findings = CredentialRuntime([entry], fetch).run("10.0.0.1", [_SVC])
    assert len(findings) == 1
    assert len(tried) == 1


# =============================================== registro incluso al fallar

def test_every_attempt_is_logged_even_on_failure(caplog):
    entry = _entry([CredentialPair("admin", "admin")])

    def fetch(host, port, method, path, body, headers):
        return Response(401, "no", {})

    with caplog.at_level("INFO"):
        CredentialRuntime([entry], fetch).run("10.0.0.1", [_SVC])
    assert any("intento" in record.message for record in caplog.records)


# =============================================== servicio no aplicable

def test_an_entry_is_skipped_against_a_non_matching_service():
    entry = _entry([CredentialPair("admin", "admin")], service="http")
    ftp_service = Service(21, "tcp", "ftp", None, None, None)
    called = []

    def fetch(host, port, method, path, body, headers):
        called.append(1)
        return Response(200, "ok", {})

    assert CredentialRuntime([entry], fetch).run("10.0.0.1", [ftp_service]) == []
    assert not called


# =============================================== el feed empaquetado

def test_the_shipped_feed_is_well_formed():
    entries = load_credentials()
    assert len(entries) >= 3
    assert validate_credentials(entries) == []


def test_the_shipped_feed_never_stores_a_password_in_a_finding_field_name():
    """Sanity check estructural: ninguna entrada del feed usa un nombre de
    campo que sugiera que la contraseña se vaya a guardar en el hallazgo."""
    for entry in load_credentials():
        assert "password" not in entry.finding


# =============================================== validación de forma

def test_an_entry_without_accounts_is_reported():
    entry = _entry([])
    assert any("ninguna cuenta" in problem for problem in validate_credentials([entry]))


def test_an_entry_without_matchers_is_reported():
    entry = _entry([CredentialPair("a", "b")], matchers=())
    assert any("matcher" in problem for problem in validate_credentials([entry]))


def test_an_entry_with_an_unknown_service_is_reported():
    entry = _entry([CredentialPair("a", "b")], service="carrier-pigeon")
    assert any("sin predicado" in problem for problem in validate_credentials([entry]))


def test_a_duplicate_id_and_version_is_reported():
    entry = _entry([CredentialPair("a", "b")])
    assert any("duplicada" in problem for problem in validate_credentials([entry, entry]))


def _basic(username: str, password: str) -> str:
    import base64
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return f"Basic {token}"
