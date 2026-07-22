"""Corpus de regresión de falsos positivos (Fase 1, sección 1.6 del plan
``plans/feature/iris/iris-mailbox-connector.md``).

Antes de este test no existía ningún test de *calibración*: ningún corpus
etiquetado de correo legítimo real que ejecutara el motor completo (las ~40
reglas + agregación + gates) y verificara que no cae en falso positivo. Los
hallazgos B1-B4/F3/F4/N3 (matching de frases sin límite de palabra,
"confidencial" en bec_phrases, triple contabilización Reply-To/Return-Path/
Triangulation en correo de ESP, comparación de dominio completo en
Return-Path, credential-harvest saltado en marcas multi-tenant) existían
precisamente porque nada los habría detectado.

Cada caso ejecuta el motor real end-to-end (mismo camino que
``IrisManager._run_analysis``, pero sin TaskQueue/DB) sobre un ``.eml``
representativo de las simulaciones de la sección 1.1 del plan.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from email.utils import format_datetime

import pytest

from src.modules.features.iris.managers import IrisManager
from src.modules.features.iris.services.parsers import parse_raw_message
from src.modules.features.iris.services.rules import iris_rules

pytestmark = pytest.mark.unit


def _recent_date() -> str:
    return format_datetime(datetime.now(timezone.utc))


def _run_engine(raw: str):
    """Ejecuta el motor completo sobre *raw*, igual que ``IrisManager._run_analysis``
    (mismo dispatch needs_context/headers, mismo clamp subtractivo, misma
    agregación y gates) pero sin TaskQueue ni base de datos."""
    context = parse_raw_message(raw)
    results = []
    named_results = {}
    for rule_def in iris_rules.get_rules():
        rule_input = context if rule_def.get("needs_context") else context.headers
        result = rule_def["func"](rule_input)
        result = replace(result, score=min(0.0, float(result.score)))
        results.append(result)
        named_results[rule_def["name"]] = result

    total_score = IrisManager._aggregate_score(results)
    base_verdict = IrisManager()._determine_verdict(total_score)
    verdict, gate_reasons = IrisManager._apply_verdict_gates(base_verdict, named_results)
    return verdict, total_score, gate_reasons


def _newsletter_via_esp() -> str:
    date = _recent_date()
    return (
        "From: Acme Corp <news@acme.com>\r\n"
        "Reply-To: reply-abc123@reply.mailchimp.com\r\n"
        "Return-Path: <bounce-abc123@bounce.sendgrid.net>\r\n"
        "To: subscriber@example.com\r\n"
        "Subject: Tu boletin de mayo\r\n"
        f"Date: {date}\r\n"
        "Message-ID: <abc123@mailchimp.com>\r\n"
        "Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=bounce.sendgrid.net; "
        "dkim=pass header.d=acme.com; dmarc=pass\r\n"
        "List-Unsubscribe: <https://acme.com/unsubscribe>, <mailto:unsub@acme.com>\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "\r\n"
        "<html><body><p>Hola,</p><p>Aqui tienes las novedades de mayo. "
        "Gracias por seguir con nosotros y por confiar en nuestro equipo.</p>"
        '<img src="https://cdn.mailchimp.com/img/logo.png" alt="logo"/>'
        "</body></html>\r\n"
    )


def _corporate_internal_notice() -> str:
    date = _recent_date()
    return (
        'From: "RRHH Acme" <rrhh@acme.com>\r\n'
        "To: empleados@acme.com\r\n"
        "Return-Path: <rrhh@acme.com>\r\n"
        "Subject: Aviso importante sobre vacaciones\r\n"
        f"Date: {date}\r\n"
        "Message-ID: <xyz789@acme.com>\r\n"
        "Authentication-Results: mx.acme.com; spf=pass smtp.mailfrom=acme.com; "
        "dkim=pass header.d=acme.com; dmarc=pass\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "\r\n"
        "Estimado equipo,\r\n\r\n"
        "Les recordamos el procedimiento para solicitar vacaciones este ano. "
        "Por favor completen el formulario interno antes de fin de mes.\r\n\r\n"
        "Saludos,\r\nRRHH\r\n\r\n"
        "--\r\n"
        "La informacion contenida en este mensaje es confidencial. Si no es "
        "el destinatario, por favor borrelo y notifique al remitente.\r\n"
    )


def _bank_security_alert() -> str:
    date = _recent_date()
    return (
        'From: "Banco Ejemplo" <alertas@bancoejemplo.com>\r\n'
        "To: cliente@example.com\r\n"
        "Return-Path: <alertas@bancoejemplo.com>\r\n"
        "Subject: Alerta de seguridad: nuevo inicio de sesion detectado\r\n"
        f"Date: {date}\r\n"
        "Message-ID: <alert123@bancoejemplo.com>\r\n"
        "Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=bancoejemplo.com; "
        "dkim=pass header.d=bancoejemplo.com; dmarc=pass\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "\r\n"
        "Estimado cliente,\r\n\r\n"
        "Hemos detectado un nuevo inicio de sesion en su cuenta desde un "
        "dispositivo desconocido. Si no reconoce esta actividad, "
        "contactenos de inmediato por telefono.\r\n\r\n"
        "Atentamente,\r\nBanco Ejemplo\r\n"
    )


def _evident_phishing() -> str:
    date = _recent_date()
    return (
        'From: "PayPal Security" <security@paypa1-verify.tk>\r\n'
        "Reply-To: support@paypa1-verify.tk\r\n"
        "To: victim@example.com\r\n"
        "Subject: Urgent: verify your account now\r\n"
        f"Date: {date}\r\n"
        "Message-ID: <1@paypa1-verify.tk>\r\n"
        "Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=paypa1-verify.tk; "
        "dkim=fail; dmarc=fail\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "\r\n"
        "<html><body><p>Dear customer,</p>"
        "<p>Please verify your account immediately or it will be suspended.</p>"
        '<a href="http://paypa1-verify.tk/login">Verify Now</a></body></html>\r\n'
    )


@pytest.mark.parametrize("build_message", [
    _newsletter_via_esp,
    _corporate_internal_notice,
    _bank_security_alert,
], ids=["newsletter_esp", "corporate_internal_notice", "bank_security_alert"])
def test_legitimate_corpus_is_not_flagged(build_message):
    verdict, total_score, gate_reasons = _run_engine(build_message())
    assert verdict == "Legitimate", (
        f"esperado Legitimate, se obtuvo {verdict} (score={total_score}, gates={gate_reasons})"
    )
    assert total_score >= 80


def test_evident_phishing_is_still_flagged():
    # Control negativo: los arreglos de falsos positivos no deben neutralizar
    # la deteccion real (lookalike domain + auth fail + urgencia).
    verdict, total_score, gate_reasons = _run_engine(_evident_phishing())
    assert verdict == "Phishing"
    assert gate_reasons
