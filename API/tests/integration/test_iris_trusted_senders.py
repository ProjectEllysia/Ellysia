"""Excepciones de confianza por usuario: reducir un falso positivo sin abrir un bypass.

Cubre el criterio de cierre: el analista quita un falso positivo recurrente para
sí mismo —no para toda la instalación—, la excepción caduca, se revoca sin
borrarse y deja rastro en cada análisis. Y las dos reglas que no se relajan:
solo se aplica a correo que demuestra venir de ese remitente, y nunca desactiva
los gates de adjuntos peligrosos ni de autenticación forjada.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from src.modules.features.iris.managers.analysis import IrisManager
from src.modules.features.iris.model import IrisAnalysis
from src.modules.features.iris.repositories import IrisAnalysisRepository, IrisTrustedSenderRepository
from src.modules.infrastructure import UnitOfWork
from src.modules.shared import utcnow_naive
from src.modules.users.services.permissions import AttributeType

pytestmark = pytest.mark.integration

_IRIS_ATTRIBUTES = [attribute.db_name for attribute in (
    AttributeType.IRIS_READ, AttributeType.IRIS_CREATE,
    AttributeType.IRIS_UPDATE, AttributeType.IRIS_DELETE,
)]

_RECEIVED_BY_OUR_MX = (
    "Received: from mail.proveedor.com (mail.proveedor.com [203.0.113.10]) "
    "by mx.example.com with ESMTPS id abc123; Mon, 07 Sep 2026 09:30:00 +0000"
)
_RECEIVED_BY_STRANGER = (
    "Received: from mail.proveedor.com (mail.proveedor.com [203.0.113.10]) "
    "by relay.otro.net with ESMTPS id abc123; Mon, 07 Sep 2026 09:30:00 +0000"
)

_EXE_ATTACHMENT = (
    "--frontera\n"
    "Content-Type: application/octet-stream; name=\"factura.exe\"\n"
    "Content-Disposition: attachment; filename=\"factura.exe\"\n"
    "Content-Transfer-Encoding: base64\n\n"
    "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAA=\n"
)


def _message(*, received: str = _RECEIVED_BY_OUR_MX, attachment: str = "") -> str:
    """Factura legítima de un proveedor que siempre responde desde Gmail.

    El ``Reply-To`` en un webmail gratuito es el falso positivo recurrente que
    la excepción debe poder quitar.
    """
    return (
        f"{received}\n"
        "Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=proveedor.com; "
        "dkim=pass header.d=proveedor.com; dmarc=pass\n"
        'From: "Proveedor" <facturas@proveedor.com>\n'
        "Reply-To: proveedor.facturas@gmail.com\n"
        "Return-Path: <facturas@proveedor.com>\n"
        "To: cliente@example.com\n"
        "Subject: Factura de septiembre\n"
        "Date: Mon, 07 Sep 2026 09:30:00 +0000\n"
        "Message-ID: <factura-09@proveedor.com>\n"
        "MIME-Version: 1.0\n"
        "Content-Type: multipart/mixed; boundary=\"frontera\"\n\n"
        "--frontera\n"
        "Content-Type: text/plain; charset=utf-8\n\n"
        "Hola Ana, te adjunto la factura de este mes. Un saludo, Luis.\n"
        f"{attachment}"
        "--frontera--\n"
    )


def _analyze(app, user_id: int, raw: str) -> int:
    with app.app_context():
        with UnitOfWork() as uow:
            analysis = IrisAnalysis(raw_headers=raw, user_id=user_id, status="pending")
            IrisAnalysisRepository(uow).save(analysis)
            analysis_id = analysis.id
        IrisManager()._run_analysis(analysis_id, raw)
    return analysis_id


@pytest.fixture
def analyst(make_user, auth_headers):
    user = make_user(role="role_user", attributes=_IRIS_ATTRIBUTES)
    return user, auth_headers(user)


def _trust(client, headers, **overrides):
    body = {"kind": "domain", "value": "proveedor.com", "reason": "Proveedor habitual de facturación"}
    body.update(overrides)
    return client.post("/iris/trusted-senders", headers=headers, json=body)


# ------------------------------------------------------------- ciclo de vida

def test_an_analyst_declares_a_trusted_domain_with_reason_and_expiry(client, analyst):
    _, headers = analyst

    response = _trust(client, headers, value="@Proveedor.COM.", expiresInDays=30)

    assert response.status_code == 201
    entry = response.get_json()
    assert entry["kind"] == "domain"
    assert entry["value"] == "proveedor.com"
    assert entry["reason"] == "Proveedor habitual de facturación"
    assert entry["status"] == "active"
    assert entry["expiresAt"] > entry["createdAt"]


@pytest.mark.parametrize("overrides", [
    {"reason": "   "},
    {"value": "no es un dominio"},
    {"kind": "sender", "value": "sin-arroba.com"},
    {"expiresInDays": 400},
    {"kind": "everything"},
])
def test_an_exception_without_reason_or_with_an_invalid_value_is_rejected(client, analyst, overrides):
    _, headers = analyst

    response = _trust(client, headers, **overrides)

    assert response.status_code in (400, 422)


def test_the_same_active_exception_cannot_be_declared_twice(client, analyst):
    _, headers = analyst
    assert _trust(client, headers).status_code == 201

    assert _trust(client, headers).status_code == 400


def test_revoking_keeps_the_exception_for_the_audit(client, analyst):
    _, headers = analyst
    entry_id = _trust(client, headers).get_json()["trustedSenderId"]

    revoked = client.delete(f"/iris/trusted-senders/{entry_id}", headers=headers)

    assert revoked.status_code == 200
    assert revoked.get_json()["status"] == "revoked"
    active = client.get("/iris/trusted-senders", headers=headers).get_json()
    assert active["trustedSenders"] == []
    audit = client.get("/iris/trusted-senders?includeInactive=true", headers=headers).get_json()
    assert [(entry["trustedSenderId"], entry["status"]) for entry in audit["trustedSenders"]] == [
        (entry_id, "revoked")
    ]
    assert audit["trustedSenders"][0]["revokedAt"]


def test_an_exception_belongs_to_whoever_created_it(client, analyst, make_user, auth_headers):
    _, headers = analyst
    entry_id = _trust(client, headers).get_json()["trustedSenderId"]
    stranger_headers = auth_headers(make_user(role="role_user", attributes=_IRIS_ATTRIBUTES))

    assert client.delete(f"/iris/trusted-senders/{entry_id}", headers=stranger_headers).status_code == 404
    assert client.get("/iris/trusted-senders", headers=stranger_headers).get_json()["trustedSenders"] == []


# ------------------------------------------------------ efecto sobre el análisis

def test_without_an_exception_the_free_webmail_reply_to_is_flagged(client, app, analyst):
    user, headers = analyst

    report = client.get(f"/iris/results/{_analyze(app, user.id, _message())}", headers=headers).get_json()

    assert report["verdict"] != "Legitimate"
    assert "reply target is free webmail" in report["gateReasons"]
    assert report["trustApplied"] is None


def test_a_trusted_and_authenticated_sender_loses_the_false_positive(client, app, analyst):
    user, headers = analyst
    entry_id = _trust(client, headers).get_json()["trustedSenderId"]

    report = client.get(f"/iris/results/{_analyze(app, user.id, _message())}", headers=headers).get_json()

    assert report["verdict"] == "Legitimate"
    assert "reply target is free webmail" not in report["gateReasons"]
    trust = report["trustApplied"]
    assert trust["entryId"] == entry_id and trust["applied"] is True
    assert "Reply-To Free Provider" in trust["modulatedRules"]
    assert trust["reason"] == "Proveedor habitual de facturación"
    assert any("Excepción de confianza aplicada" in reason for reason in report["gateReasons"])
    rule = next(rule for rule in report["rules"] if rule["ruleName"] == "Reply-To Free Provider")
    assert rule["verdict"] == "trusted" and rule["score"] == 0
    assert rule["details"]["trustOverride"]["originalVerdict"] == "fail"


def test_an_exception_never_disables_the_dangerous_attachment_gate(client, app, analyst):
    user, headers = analyst
    _trust(client, headers)

    raw = _message(attachment=_EXE_ATTACHMENT)
    report = client.get(f"/iris/results/{_analyze(app, user.id, raw)}", headers=headers).get_json()

    assert report["verdict"] != "Legitimate"
    assert "dangerous attachment" in report["gateReasons"]
    assert report["trustApplied"]["applied"] is True


def test_an_exception_is_ignored_when_the_authentication_cannot_be_verified(client, app, analyst):
    """El ``dmarc=pass`` lo firma un servidor que no está en la cadena: pudo
    escribirlo el propio remitente, así que no demuestra nada."""
    user, headers = analyst
    _trust(client, headers)

    raw = _message(received=_RECEIVED_BY_STRANGER)
    report = client.get(f"/iris/results/{_analyze(app, user.id, raw)}", headers=headers).get_json()

    assert report["verdict"] != "Legitimate"
    assert report["trustApplied"]["applied"] is False
    assert report["trustApplied"]["modulatedRules"] == []
    assert any("no se aplicó" in reason for reason in report["gateReasons"])


def test_an_expired_exception_no_longer_applies(client, app, analyst):
    user, headers = analyst
    entry_id = _trust(client, headers).get_json()["trustedSenderId"]
    with app.app_context():
        with UnitOfWork() as uow:
            repo = IrisTrustedSenderRepository(uow)
            entry = repo.get_by_id(entry_id)
            entry.expires_at = utcnow_naive() - timedelta(minutes=1)
            repo.update(entry)

    report = client.get(f"/iris/results/{_analyze(app, user.id, _message())}", headers=headers).get_json()

    assert report["trustApplied"] is None
    assert report["verdict"] != "Legitimate"
    audit = client.get("/iris/trusted-senders?includeInactive=true", headers=headers).get_json()
    assert audit["trustedSenders"][0]["status"] == "expired"


def test_another_users_exception_does_not_apply(client, app, analyst, make_user, auth_headers):
    user, headers = analyst
    other_headers = auth_headers(make_user(role="role_user", attributes=_IRIS_ATTRIBUTES))
    _trust(client, other_headers)

    report = client.get(f"/iris/results/{_analyze(app, user.id, _message())}", headers=headers).get_json()

    assert report["trustApplied"] is None
    assert report["verdict"] != "Legitimate"
