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


def _m365_delivered_otp() -> str:
    """OTP transaccional enviado vía Mailgun y entregado por Microsoft 365
    (análisis #34 del corpus real, veredicto Phishing por gate). M365 emite
    ``Authentication-Results`` SIN authserv-id, y la cadena de entrega normal
    de M365 encadena 5 saltos: las dos cosas juntas gateaban a Phishing un
    correo que autentica limpio."""
    date = _recent_date()
    return (
        "From: dbdiagram.io <dbdiagram@holistics.io>\r\n"
        "To: usuario@empresa.com\r\n"
        "Return-Path: <bounce+0df99b.f848cf@ops.mg.holistics.io>\r\n"
        "Subject: OTP for dbdiagram login\r\n"
        f"Date: {date}\r\n"
        "Message-ID: <20260717103041.1@holistics.io>\r\n"
        "Authentication-Results: spf=pass (sender ip is 204.220.183.7) "
        "smtp.mailfrom=ops.mg.holistics.io; dkim=pass (signature was verified) "
        "header.d=holistics.io; dmarc=pass action=none header.from=holistics.io\r\n"
        "Received: from VI0P193MB2694.EURP193.PROD.OUTLOOK.COM (2603:10a6::1) by "
        f"VI0P193MB2694.EURP193.PROD.OUTLOOK.COM (2603:10a6::1); {date}\r\n"
        "Received: from DU7PR01CA0032.eurprd01.prod.exchangelabs.com (15.21.223.11) by "
        f"VI0P193MB2694.EURP193.PROD.OUTLOOK.COM (15.21.223.12); {date}\r\n"
        "Received: from DB3PEPF00008860.eurprd02.prod.outlook.com (15.21.223.13) by "
        f"DU7PR01CA0032.eurprd01.prod.exchangelabs.com (15.21.223.11); {date}\r\n"
        "Received: from k7.k3ae2098.use4.send.mailgun.net (204.220.183.7) by "
        f"DB3PEPF00008860.eurprd02.prod.outlook.com (10.167.242.6); {date}\r\n"
        'Content-Type: text/html; charset="utf-8"\r\n'
        "\r\n"
        "<html><body><p>Hi, your one-time password for dbdiagram is 402913. "
        "It expires in 10 minutes. If you did not request it you can ignore "
        "this message.</p>"
        '<img src="https://dbdiagram.io/static/logo.png" alt="logo"/>'
        "</body></html>\r\n"
    )


def _app_notification_internal_origin() -> str:
    """Notificación de una aplicación (GitHub Actions) cuyo salto de origen es
    ``from localhost [10.x] by smtp.<dominio-del-From>`` — el patrón de todo
    remitente que genera correo en su propia infraestructura (análisis #32,
    veredicto Suspicious por el gate de cadena Received)."""
    date = _recent_date()
    return (
        "From: Gabriel Musteata <notifications@github.com>\r\n"
        "To: ProjectEllysia/HygeiaAgent <HygeiaAgent@noreply.github.com>\r\n"
        "Reply-To: ProjectEllysia/HygeiaAgent <HygeiaAgent@noreply.github.com>\r\n"
        "Subject: [ProjectEllysia/HygeiaAgent] Run failed: CI\r\n"
        f"Date: {date}\r\n"
        "Message-ID: <ProjectEllysia/HygeiaAgent/check-suites/1@github.com>\r\n"
        "Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=github.com; "
        "dkim=pass header.d=github.com; dmarc=pass\r\n"
        "Received: from out-19.smtp.github.com (out-19.smtp.github.com. [192.30.252.202]) "
        f"by mx.google.com with UTF8SMTPS id af79; {date}\r\n"
        "Received: from localhost (hubbernetes-node-220bbd2.va3-iad.github.net "
        f"[10.48.100.73]) by smtp.github.com (Postfix) id 6F983280A5E; {date}\r\n"
        'Content-Type: text/html; charset="utf-8"\r\n'
        "\r\n"
        "<html><body><p>CI: Some jobs were not successful on branch "
        "feature/inventory-ingest. Review the failing jobs and re-run them "
        "when the fix is pushed.</p>"
        '<img src="https://github.githubassets.com/assets/actions-1cc0c3.png"/>'
        '<a href="https://github.com/ProjectEllysia/HygeiaAgent/actions/runs/1">'
        "View workflow run</a></body></html>\r\n"
    )


def _mjml_layout_newsletter() -> str:
    """Newsletter maquetada con MJML: los ``<td>`` contenedores llevan
    ``font-size:0`` (el truco estándar para eliminar el espacio entre columnas
    inline-block en Outlook) con el botón y su enlace VISIBLES dentro
    (análisis #31, veredicto Suspicious por el gate de texto oculto)."""
    date = _recent_date()
    return (
        "From: Tienda <ofertas@orders.tiendaejemplo.com>\r\n"
        'To: "cliente@example.com" <cliente@example.com>\r\n'
        "Subject: No guardaste tu direccion\r\n"
        f"Date: {date}\r\n"
        "Message-ID: <20260724211512.9e4@orders.tiendaejemplo.com>\r\n"
        "List-Unsubscribe: <mailto:unsubscribe@tiendaejemplo.com>\r\n"
        "Authentication-Results: mx.google.com; spf=pass "
        "smtp.mailfrom=orders.tiendaejemplo.com; dkim=pass "
        "header.d=tiendaejemplo.com; dmarc=pass\r\n"
        "Received: from a26.euw1.send.eu.mailgun.net (a26.euw1.send.eu.mailgun.net. "
        f"[198.244.62.26]) by mx.google.com with UTF8SMTPS id ffacd; {date}\r\n"
        'Content-Type: text/html; charset="utf-8"\r\n'
        "\r\n"
        "<html><body>\r\n"
        '<td style="line-height:0px;font-size:0px;mso-line-height-rule:exactly;">\r\n'
        '<div style="margin:0 auto;max-width:576px">\r\n'
        "<p>Hola Gabriel, parece que no guardaste tu direccion correctamente. "
        "Haz clic en el boton a continuacion para volver a intentarlo.</p>\r\n"
        '<td align="center" style="font-size:0;padding:0;word-break:break-word">\r\n'
        '<a href="https://app.tiendaejemplo.com/transit.html?biz=5008">Anadir ahora</a>\r\n'
        "</td>\r\n</div>\r\n</td>\r\n"
        '<img src="https://aimg.tienda-cdn.com/upload/a91033ec.png"/>\r\n'
        "</body></html>\r\n"
    )


def _newsletter_own_domain_click_tracking() -> str:
    """Boletín cuyo click-tracking reescribe cada href a un subdominio
    redirector del PROPIO remitente mientras el texto visible conserva la URL
    original (análisis #57, veredicto Phishing por el gate de cloaked link).
    Incluye también el caso de texto visible y href en el mismo dominio
    registrable con subdominio distinto."""
    date = _recent_date()
    return (
        "From: Emilio Carrion <hola@boletinejemplo.com>\r\n"
        'To: "lector@example.com" <lector@example.com>\r\n'
        "Subject: El enemigo no es el bug: es el sedimento\r\n"
        f"Date: {date}\r\n"
        "Message-ID: <4c9c8c925cb6eea2@boletinejemplo.com>\r\n"
        "Authentication-Results: mx.example.com; spf=pass "
        "smtp.mailfrom=boletinejemplo.com; dkim=pass header.d=boletinejemplo.com; "
        "dmarc=pass\r\n"
        "Received: from mta-203-43-90.sparkpostmail.com "
        "(mta-203-43-90.sparkpostmail.com. [168.203.43.90]) by mx.example.com "
        f"with ESMTPS id ffacd; {date}\r\n"
        "Received: from [10.95.195.23] ([10.95.195.23]) by "
        f"i-0d67b025.mta3vrest.sd.prd.sparkpost (ecelerity 5.2.0) with REST id DC; {date}\r\n"
        'Content-Type: text/html; charset="utf-8"\r\n'
        "\r\n"
        "<html><body><p>Las 4 formas de sedimento en diffs de IA y la pregunta "
        "que desactiva cada una. Revisar codigo esta siendo un caos con todo el "
        "mundo tirando de IA para todo.</p>"
        '<a href="https://eot.boletinejemplo.com/f/a/TlNyRzpCHN3UtR6C~~/AAAHURA~/aU5DDcrz">'
        "https://youtu.be/JMezeu2Zl-U</a>"
        '<a href="https://eot.boletinejemplo.com/f/a/Spp8nkVZmU_bUP5R~~/AAAHURA~/7GeJAhKP">'
        "https://lgtm.boletinejemplo.com</a>"
        "</body></html>\r\n"
    )


def _api_injected_newsletter() -> str:
    """Boletín inyectado por API cuya primera línea Received es
    ``Received: by <IP privada>`` sin ``from`` alguno — el formato que usan los
    ESP que aceptan el mensaje por HTTP/REST (análisis #60, veredicto
    Suspicious por el gate de cadena Received)."""
    date = _recent_date()
    return (
        "From: Empath <hello@boletinmsp.com>\r\n"
        "To: usuario@empresa.com\r\n"
        "Reply-To: hello@boletinmsp.com\r\n"
        "Return-Path: <1axboxju893tg7eaagtofaqrh34@22487964m.boletinmsp.com>\r\n"
        "Subject: The Aurora-7 Breach goes live this week\r\n"
        f"Date: {date}\r\n"
        "Message-ID: <20260721090006.1@22487964m.boletinmsp.com>\r\n"
        "Authentication-Results: spf=pass (sender IP is 158.247.29.205) "
        "smtp.mailfrom=22487964m.boletinmsp.com; dkim=pass (signature was "
        "verified) header.d=boletinmsp.com; dmarc=pass action=none "
        "header.from=boletinmsp.com\r\n"
        "Received: from AS8P193MB2142.EURP193.PROD.OUTLOOK.COM (2603:10a6:20b:44e::13) "
        f"by PAXP193MB1869.EURP193.PROD.OUTLOOK.COM with HTTPS; {date}\r\n"
        "Received: from bid48wv.22487964m.boletinmsp.com (158.247.29.205) by "
        "DB5PEPF00014B8F.mail.protection.outlook.com (10.167.8.203) with "
        f"Microsoft SMTP Server; {date}\r\n"
        f"Received: by 172.16.56.96 with SMTP id a0b9znrox27ui25fp8isr5o7x0vlrj5; {date}\r\n"
        'Content-Type: text/html; charset="utf-8"\r\n'
        "\r\n"
        "<html><body><p>The Aurora-7 Breach goes live this week. Join the "
        "tabletop exercise and see how your team responds under pressure.</p>"
        '<a href="https://boletinmsp.com/aurora-7">Register now</a></body></html>\r\n'
    )


def _fintech_terms_update() -> str:
    """Aviso legal de una fintech cuyo pie regulatorio menciona criptomonedas
    y criptoactivos sin ninguna petición de transferencia (análisis #61,
    veredicto Suspicious; el sustantivo suelto disparaba el patrón BEC)."""
    date = _recent_date()
    return (
        "From: Fintech <no-reply@fintechejemplo.com>\r\n"
        'To: "cliente@example.com" <cliente@example.com>\r\n'
        "Subject: Actualizacion de nuestros Terminos y Condiciones de Trading\r\n"
        f"Date: {date}\r\n"
        "Message-ID: <0F.32.33140@i-07bd6903.mta1vrest.sd.prd.sparkpost>\r\n"
        "Authentication-Results: mx.example.com; spf=pass "
        "smtp.mailfrom=sp-bounce.fintechejemplo.com; dkim=pass "
        "header.d=fintechejemplo.com; dmarc=pass\r\n"
        "Received: from mta-83-158.sparkpostmail.com (mta-83-158.sparkpostmail.com. "
        f"[192.174.83.158]) by mx.example.com with ESMTPS id 956f; {date}\r\n"
        "Received: from [10.90.28.56] ([10.90.28.56]) by "
        f"i-07bd6903.mta1vrest.sd.prd.sparkpost (ecelerity 5.2.0) with REST id 0F; {date}\r\n"
        'Content-Type: text/html; charset="utf-8"\r\n'
        "\r\n"
        "<html><body><p>Vamos a modificar los Terminos y Condiciones de Trading "
        "el 18 de julio de 2026.</p>"
        '<a href="https://www.fintechejemplo.com/legal/investment-services-terms/">'
        "Ver Terminos y Condiciones actualizados</a>"
        "<p>Los productos de criptomonedas son proporcionados por una empresa "
        "privada registrada en la Republica de Chipre, autorizada por la "
        "Comision de Valores y Bolsa de Chipre como proveedor de servicios de "
        "criptoactivos (CASP) en virtud del Reglamento (UE) 2023/1114 (MiCA).</p>"
        "</body></html>\r\n"
    )


@pytest.mark.parametrize("build_message", [
    _newsletter_via_esp,
    _corporate_internal_notice,
    _bank_security_alert,
    _aggressive_marketing_newsletter,
    _it_notice_deep_received_chain,
    _bank_alert_strong_urgency,
    _english_order_confirmation,
    _m365_delivered_otp,
    _app_notification_internal_origin,
    _mjml_layout_newsletter,
    _newsletter_own_domain_click_tracking,
    _api_injected_newsletter,
    _fintech_terms_update,
], ids=[
    "newsletter_esp",
    "corporate_internal_notice",
    "bank_security_alert",
    "aggressive_marketing_newsletter",
    "it_notice_deep_received_chain",
    "bank_alert_strong_urgency",
    "english_order_confirmation",
    "m365_delivered_otp",
    "app_notification_internal_origin",
    "mjml_layout_newsletter",
    "newsletter_own_domain_click_tracking",
    "api_injected_newsletter",
    "fintech_terms_update",
])
def test_legitimate_corpus_is_not_flagged(build_message):
    verdict, total_score, gate_reasons = _run_engine(build_message())
    assert verdict == "Legitimate", (
        f"esperado Legitimate, se obtuvo {verdict} (score={total_score}, gates={gate_reasons})"
    )
    assert total_score >= 80


def _cloaked_brand_link_on_own_domain() -> str:
    """Cloaking real que la exención de "redirector del propio remitente" NO
    debe dejar pasar: el texto visible promete `paypal.com` y el href apunta al
    dominio del propio atacante. El destino ser "suyo" no lo exime, porque el
    texto visible está prometiendo la identidad de una marca ajena."""
    date = _recent_date()
    return (
        'From: "PayPal Service" <service@paypal-secure-verify.com>\r\n'
        "To: victima@empresa.com\r\n"
        "Subject: Action required: verify your account\r\n"
        f"Date: {date}\r\n"
        "Message-ID: <1@paypal-secure-verify.com>\r\n"
        "Authentication-Results: mx.empresa.com; "
        "spf=fail smtp.mailfrom=paypal-secure-verify.com; dkim=fail; dmarc=fail\r\n"
        'Content-Type: text/html; charset="utf-8"\r\n'
        "\r\n"
        "<html><body><p>Your account has been locked. Verify your account now.</p>"
        '<a href="https://login.paypal-secure-verify.com/signin">https://www.paypal.com</a>'
        "</body></html>\r\n"
    )


def _bec_crypto_transfer_request() -> str:
    """BEC que pide la transferencia en cripto con una frase ACCIONABLE — lo
    que debe seguir detectándose tras retirar el sustantivo suelto
    "criptomonedas" de la lista de frases."""
    date = _recent_date()
    return (
        'From: "Director Financiero" <cfo.pagos@gmail.com>\r\n'
        "To: finanzas@empresa.com\r\n"
        "Subject: Pago urgente proveedor\r\n"
        f"Date: {date}\r\n"
        "Message-ID: <2@gmail.com>\r\n"
        "Authentication-Results: mx.empresa.com; spf=pass smtp.mailfrom=gmail.com; "
        "dkim=pass header.d=gmail.com; dmarc=pass\r\n"
        'Content-Type: text/plain; charset="utf-8"\r\n'
        "\r\n"
        "Necesito que hagas una transferencia cripto hoy mismo al proveedor, es "
        "confidencial. Te paso los datos bancarios nuevos en cuanto confirmes.\r\n"
    )


def _forged_received_chain() -> str:
    """Cadena Received fabricada: la IP privada del origen ya no puntúa, así
    que este caso comprueba que el veredicto lo sostienen las señales que sí
    miran coherencia (inversión temporal, desfase con Date, marca en
    subdominio, fallo de auth)."""
    return (
        'From: "Soporte IT" <soporte@acme-it-alerts.com>\r\n'
        "To: usuario@acme.com\r\n"
        "Subject: Verificacion requerida: cuenta suspendida\r\n"
        f"Date: {_recent_date()}\r\n"
        "Message-ID: <3@random-host.xyz>\r\n"
        "Authentication-Results: mx.acme.com; "
        "spf=fail smtp.mailfrom=acme-it-alerts.com; dmarc=fail\r\n"
        "Received: from mx.acme.com by mx.acme.com; Wed, 25 Jun 2025 10:00:00 +0000\r\n"
        "Received: from [10.0.0.5] by relay.desconocido.xyz; Wed, 25 Jun 2025 18:00:00 +0000\r\n"
        'Content-Type: text/html; charset="utf-8"\r\n'
        "\r\n"
        "<html><body><p>Su cuenta ha sido bloqueada. Verifica tu cuenta ahora.</p>"
        '<a href="http://acme-it-alerts.com.sesiones-seguras.tk/login">Acceder</a>'
        "</body></html>\r\n"
    )


@pytest.mark.parametrize("build_message", [
    _evident_phishing,
    _bec_from_free_provider,
    _cloaked_brand_link_on_own_domain,
    _bec_crypto_transfer_request,
    _forged_received_chain,
], ids=[
    "evident_phishing",
    "bec_from_free_provider",
    "cloaked_brand_link_on_own_domain",
    "bec_crypto_transfer_request",
    "forged_received_chain",
])
def test_phishing_corpus_is_still_flagged(build_message):
    # Control negativo: los arreglos de falsos positivos no deben neutralizar
    # la deteccion real. Cada caso debe seguir cayendo en Phishing por gate,
    # no por score -- es justo lo que la recalibracion no puede romper.
    verdict, total_score, gate_reasons = _run_engine(build_message())
    assert verdict == "Phishing", (
        f"esperado Phishing, se obtuvo {verdict} (score={total_score}, gates={gate_reasons})"
    )
    assert gate_reasons
