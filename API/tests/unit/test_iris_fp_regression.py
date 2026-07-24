"""Corpus de regresión de falsos positivos.

Prerrequisito bloqueante de la recalibración de pesos
(``plans/feature/iris/iris-rule-weight-recalibration.md``, sección 7.1): sin
un corpus que de verdad estrese los contaminantes identificados por el
consejo (saludo genérico, urgencia media, tracking de imágenes, cadena
Received interna, destinatarios ocultos, coexistiendo en el mismo correo,
como pasa en el correo legítimo real), cualquier cambio de peso es a ciegas.
Los primeros cuatro casos (``newsletter_esp``, ``corporate_internal_notice``,
``bank_security_alert``, ``evident_phishing``) son el corpus mínimo original,
deliberadamente simple. Los que siguen son más agresivos a propósito: cada
uno combina 3-4 señales contaminantes reales a la vez, replicando los
correos-tipo que el informe de recalibración simuló a mano.

Cada caso ejecuta el motor real end-to-end (mismo camino que
``IrisManager._run_analysis``, pero sin TaskQueue/DB) sobre un ``.eml``
representativo.
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
    rules_defs = iris_rules.get_rules()
    results = []
    named_results = {}
    for rule_def in rules_defs:
        rule_input = context if rule_def.get("needs_context") else context.headers
        result = rule_def["func"](rule_input)
        result = replace(result, score=min(0.0, float(result.score)))
        results.append(result)
        named_results[rule_def["name"]] = result

    total_score = IrisManager._aggregate_score(rules_defs, results)
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


def _aggressive_marketing_newsletter() -> str:
    """E-commerce newsletter que combina tres contaminantes reales a la vez:
    BCC (destinatarios ocultos), saludo genérico + dos verbos de acción, e
    imagen externa desde un CDN de terceros que no es un ESP conocido —
    exactamente la combinación que un correo de marketing legítimo produce
    de forma rutinaria."""
    date = _recent_date()
    return (
        "From: Tienda Ejemplo <ofertas@retailtienda.com>\r\n"
        "To: undisclosed-recipients:;\r\n"
        "Return-Path: <ofertas@retailtienda.com>\r\n"
        "Subject: Oferta exclusiva: actualiza tus datos de envio\r\n"
        f"Date: {date}\r\n"
        "Message-ID: <promo123@retailtienda.com>\r\n"
        "Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=retailtienda.com; "
        "dkim=pass header.d=retailtienda.com; dmarc=pass\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "\r\n"
        "<html><body><p>Estimado cliente,</p>"
        "<p>Actualiza tu informacion de envio y confirma tu cuenta antes del viernes "
        "para no perderte nuestra oferta exclusiva de temporada.</p>"
        '<img src="https://static.retailer-cdn.net/logo.png" alt="logo"/>'
        "</body></html>\r\n"
    )


def _it_notice_deep_received_chain() -> str:
    """Aviso interno de IT: cadena Received enteramente RFC1918 (varios saltos
    internos sin TLS), saludo genérico, dos verbos de acción y una keyword de
    urgencia baja — el patrón de un aviso corporativo real, no de phishing."""
    date = _recent_date()
    return (
        'From: "IT Acme" <it@acme.com>\r\n'
        "To: usuarios@acme.com\r\n"
        "Return-Path: <it@acme.com>\r\n"
        "Received: from mail1.internal.acme.com (mail1.internal.acme.com [10.0.1.5])\r\n"
        f"    by mx.acme.com; {date}\r\n"
        "Received: from mail2.internal.acme.com (mail2.internal.acme.com [10.0.2.9])\r\n"
        f"    by mail1.internal.acme.com; {date}\r\n"
        "Received: from mail3.internal.acme.com (mail3.internal.acme.com [10.0.3.12])\r\n"
        f"    by mail2.internal.acme.com; {date}\r\n"
        "Subject: Actualizacion urgente de VPN\r\n"
        f"Date: {date}\r\n"
        "Message-ID: <vpn456@acme.com>\r\n"
        "Authentication-Results: mx.acme.com; spf=pass smtp.mailfrom=acme.com; "
        "dkim=pass header.d=acme.com; dmarc=pass\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "\r\n"
        "Estimado usuario,\r\n\r\n"
        "Actualiza tu contrasena de acceso a la VPN corporativa y confirma tu cuenta "
        "antes del viernes para evitar interrupciones en el servicio.\r\n\r\n"
        "Saludos,\r\nDepartamento de IT\r\n"
    )


def _bank_alert_strong_urgency() -> str:
    """Alerta bancaria real con urgencia alta (dos keywords de high_signal),
    saludo genérico, y una frase de credential_phrases que un banco legítimo
    usa sin ninguna intención maliciosa ("verifica tu cuenta")."""
    date = _recent_date()
    return (
        'From: "Banco Real" <alertas@bancoreal.com>\r\n'
        "To: cliente@example.com\r\n"
        "Return-Path: <alertas@bancoreal.com>\r\n"
        "Subject: Aviso final: su cuenta ha sido bloqueada\r\n"
        f"Date: {date}\r\n"
        "Message-ID: <alert789@bancoreal.com>\r\n"
        "Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=bancoreal.com; "
        "dkim=pass header.d=bancoreal.com; dmarc=pass\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "\r\n"
        "Estimado cliente,\r\n\r\n"
        "Hemos detectado actividad inusual en su cuenta. Verifica tu cuenta cuanto "
        "antes llamando al numero que aparece en el reverso de su tarjeta.\r\n\r\n"
        "Atentamente,\r\nBanco Real\r\n"
    )


def _english_order_confirmation() -> str:
    """Recibo transaccional en inglés vía un ESP distinto (Postmark) — cubre
    el caso multilingüe y confirma que el allowlist de ESPs no está
    sobreajustado a Mailchimp/SendGrid."""
    date = _recent_date()
    return (
        "From: Acme Store <orders@acmestore.com>\r\n"
        "Reply-To: reply@postmarkapp.com\r\n"
        "Return-Path: <bounce@postmarkapp.com>\r\n"
        "To: buyer@example.com\r\n"
        "Subject: Your order #48213 has shipped\r\n"
        f"Date: {date}\r\n"
        "Message-ID: <order48213@postmarkapp.com>\r\n"
        "Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=postmarkapp.com; "
        "dkim=pass header.d=acmestore.com; dmarc=pass\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "\r\n"
        "Hi there,\r\n\r\n"
        "Good news! Your order #48213 has shipped and is on its way. "
        "You can track your package using the link in your account.\r\n\r\n"
        "Thanks for shopping with us,\r\nAcme Store\r\n"
    )


def _bec_from_free_provider() -> str:
    """BEC clásico: CEO impostor desde Gmail pidiendo una transferencia
    urgente, sin enlaces ni adjuntos — el caso donde la detección depende
    por completo del gate ``bec_free``, no del score (score sube tras la
    recalibración, el gate debe seguir sosteniendo el veredicto)."""
    date = _recent_date()
    return (
        'From: "Juan Perez (CEO)" <juan.perez.ceo@gmail.com>\r\n'
        "To: finanzas@acme.com\r\n"
        "Subject: Transferencia urgente\r\n"
        f"Date: {date}\r\n"
        "Message-ID: <bec1@gmail.com>\r\n"
        "Authentication-Results: mx.acme.com; spf=pass smtp.mailfrom=gmail.com; "
        "dkim=pass header.d=gmail.com; dmarc=pass\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "\r\n"
        "Necesito que proceses el pago de una factura pendiente hoy mismo, es "
        "confidencial, no lo comentes con nadie mas del equipo. Te paso los datos "
        "bancarios nuevos en cuanto confirmes que puedes hacerlo.\r\n\r\n"
        "Gracias,\r\nJuan\r\n"
    )


@pytest.mark.parametrize("build_message", [
    _newsletter_via_esp,
    _corporate_internal_notice,
    _bank_security_alert,
    _aggressive_marketing_newsletter,
    _it_notice_deep_received_chain,
    _bank_alert_strong_urgency,
    _english_order_confirmation,
], ids=[
    "newsletter_esp",
    "corporate_internal_notice",
    "bank_security_alert",
    "aggressive_marketing_newsletter",
    "it_notice_deep_received_chain",
    "bank_alert_strong_urgency",
    "english_order_confirmation",
])
def test_legitimate_corpus_is_not_flagged(build_message):
    verdict, total_score, gate_reasons = _run_engine(build_message())
    assert verdict == "Legitimate", (
        f"esperado Legitimate, se obtuvo {verdict} (score={total_score}, gates={gate_reasons})"
    )
    assert total_score >= 80


@pytest.mark.parametrize("build_message", [
    _evident_phishing,
    _bec_from_free_provider,
], ids=["evident_phishing", "bec_from_free_provider"])
def test_phishing_corpus_is_still_flagged(build_message):
    # Control negativo: los arreglos de falsos positivos no deben neutralizar
    # la deteccion real. Cada caso debe seguir cayendo en Phishing por gate,
    # no por score -- es justo lo que la recalibracion no puede romper.
    verdict, total_score, gate_reasons = _run_engine(build_message())
    assert verdict == "Phishing", (
        f"esperado Phishing, se obtuvo {verdict} (score={total_score}, gates={gate_reasons})"
    )
    assert gate_reasons
