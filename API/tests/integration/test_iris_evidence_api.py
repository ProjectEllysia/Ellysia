"""La API devuelve la evidencia anclada de cada hallazgo.

Ejecuta el catálogo real sobre un phishing con un enlace a una IP literal y un
ejecutable adjunto, como lo haría el worker, y comprueba que cada regla que
penaliza llega por API con evidencia o con el motivo de por qué no la tiene.
"""

from __future__ import annotations

import base64

import pytest

from src.modules.features.iris.managers.analysis import IrisManager
from src.modules.features.iris.model import IrisAnalysis
from src.modules.features.iris.repositories import IrisAnalysisRepository
from src.modules.infrastructure import UnitOfWork

pytestmark = pytest.mark.integration

_PHISHING = (
    "From: PayPal Soporte <alerta@paypa1-secure.example>\r\n"
    "Reply-To: cobros@gmail.com\r\n"
    "To: victima@corp.example\r\n"
    "Subject: Verifique su cuenta urgentemente\r\n"
    "Date: Mon, 1 Jan 2026 10:00:00 +0000\r\n"
    "Message-ID: <x1@paypa1-secure.example>\r\n"
    "MIME-Version: 1.0\r\n"
    "Content-Type: multipart/mixed; boundary=\"B\"\r\n\r\n"
    "--B\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
    "<p>Estimado cliente, verifique su cuenta.</p>"
    "<a href=\"http://192.168.10.20/login\">https://www.paypal.com</a>\r\n"
    "--B\r\nContent-Type: application/octet-stream\r\n"
    "Content-Disposition: attachment; filename=\"factura.pdf.exe\"\r\n"
    "Content-Transfer-Encoding: base64\r\n\r\n"
    + base64.b64encode(b"MZ\x90\x00").decode() + "\r\n--B--\r\n"
)


def _analyze(app, user_id: int, raw: str) -> int:
    with app.app_context():
        with UnitOfWork() as uow:
            analysis = IrisAnalysis(raw_headers=raw, user_id=user_id, status="pending")
            IrisAnalysisRepository(uow).save(analysis)
            analysis_id = analysis.id
        IrisManager()._run_analysis(analysis_id, raw)
    return analysis_id


def test_every_penalising_rule_has_evidence_or_says_why_not(client, app, root_user, root_headers):
    analysis_id = _analyze(app, root_user.id, _PHISHING)

    report = client.get(f"/iris/results/{analysis_id}", headers=root_headers).get_json()

    penalising = [rule for rule in report["rules"] if rule["score"] < 0]
    assert penalising
    for rule in penalising:
        assert rule["evidence"] or rule["evidenceUnavailableReason"], rule["ruleName"]

    by_name = {rule["ruleName"]: rule for rule in report["rules"]}
    body_links = by_name["Body Links"]["evidence"]
    assert body_links[0]["kind"] == "url"
    assert body_links[0]["excerpt"].startswith("hxxp://192.168.10.20/login")
    attachments = by_name["Suspicious Attachments"]["evidence"]
    assert attachments[0]["kind"] == "attachment"
    assert attachments[0]["locator"]["filename"] == "factura.pdf.exe"


def test_rules_that_do_not_penalise_carry_no_evidence(client, app, root_user, root_headers):
    analysis_id = _analyze(app, root_user.id, _PHISHING)

    report = client.get(f"/iris/results/{analysis_id}", headers=root_headers).get_json()

    for rule in report["rules"]:
        if rule["score"] >= 0:
            assert rule["evidence"] == [], rule["ruleName"]
            assert rule["evidenceUnavailableReason"] is None, rule["ruleName"]
