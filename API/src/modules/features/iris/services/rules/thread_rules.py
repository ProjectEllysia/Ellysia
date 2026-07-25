"""
Thread/threading rules — is this message genuinely part of the
conversation it claims to be?

- **Fake Reply Chain**: Subject looks like a reply/forward (``Re:``,
  ``Fwd:``...) but no In-Reply-To/References/Thread-Index headers back
  that up — a common trick to borrow trust from an implied prior thread.
- **Self-Referencing In-Reply-To**: In-Reply-To (or the first References
  entry) points at the message's *own* Message-ID — forged threading
  headers that were never validated against a real prior message.
- **Message-ID check**: is there even a well-formed, non-trivial
  Message-ID?
- **Message-ID Domain**: does the Message-ID's domain plausibly belong to
  the From domain (or a known ESP)?
"""

from __future__ import annotations

import re

import src.modules.system.config_reading as CR
from ..registry import iris_rules, RuleResult
from ..shared import esp_msgid_domains, extract_domain, registrable_domain
from ..parsers import parse_received_line

REPLY_PREFIXES = [
    r"re(?:\[\d+\])?:",     # Re:, Re[2]:, RE:
    r"fwd?:",               # Fwd:, FW:
    r"aw(?:\[\d+\])?:",     # AW: (German Antowort)
    r"r(?:\[\d+\])?:",      # R:, R[1]:
    r"rv(?:\[\d+\])?:",     # RV: (Spanish reenvío)
    r"enc(?:\s*\()?",       # ENC (encaminado)
]

REPLY_PREFIX_PATTERN = re.compile(
    r"^\s*(?:" + "|".join(REPLY_PREFIXES) + r")\s*",
    re.IGNORECASE,
)


@iris_rules.register(
    name="Fake Reply Chain", category="header_analysis",
    description="Detecta si el asunto imita una respuesta o reenvío sin los cabeceras In-Reply-To o References",
)
def check_fake_reply_chain(headers: dict) -> RuleResult:
    subject = headers.get("subject", "")
    in_reply_to = headers.get("in-reply-to", "")
    references = headers.get("references", "")
    thread_index = headers.get("thread-index", "")
    thread_topic = headers.get("thread-topic", "")

    if not subject:
        return RuleResult(
            score=0, verdict="neutral",
            details={"subject": ""},
            recommendation=None,
        )

    match = REPLY_PREFIX_PATTERN.match(subject)

    if not match:
        return RuleResult(
            score=0, verdict="pass",
            details={"subject": subject, "has_reply_prefix": False},
            recommendation=None,
        )

    reply_prefix = match.group(0).strip()

    has_reply_references = bool(in_reply_to.strip()) or bool(references.strip())
    has_outlook_threading = bool(thread_index.strip()) or bool(thread_topic.strip())
    has_threading = has_reply_references or has_outlook_threading

    if has_threading:
        return RuleResult(
            score=2, verdict="pass",
            details={
                "subject": subject,
                "reply_prefix": reply_prefix,
                "has_threading_headers": True,
                "source": "In-Reply-To/References" if has_reply_references else "Thread-Index/Thread-Topic",
            },
            recommendation=None,
        )

    # Recalibración de pesos (SOC): señal débil que solapaba con
    # Self-Referencing In-Reply-To (el caso fuerte de threading fabricado,
    # que sí gatea). Se mantiene informativa en el informe (verdict "fail")
    # pero deja de restar -- no cambia ningún veredicto por sí sola.
    return RuleResult(
        score=0, verdict="fail",
        details={
            "subject": subject,
            "reply_prefix": reply_prefix,
            "has_threading_headers": False,
            "in_reply_to": in_reply_to or "missing",
            "references": references or "missing",
            "thread_index": thread_index or "missing",
            "thread_topic": thread_topic or "missing",
        },
        recommendation=(
            f"El asunto del correo comienza con '{reply_prefix}' simulando ser parte de "
            "una conversación previa, pero no se encontraron los cabeceras In-Reply-To, "
            "References, Thread-Index ni Thread-Topic que los mensajes de respuesta legítimos "
            "suelen incluir. Esto es una táctica común de phishing para generar confianza falsa. "
            "No asumas que es una respuesta a un hilo real."
        ),
    )


# A single pattern for "the value inside <angle brackets>" -- Message-ID,
# In-Reply-To and References all use the same RFC 5322 msg-id syntax, so
# one compiled regex covers all three (previously three identical copies).
_ANGLE_BRACKET_RE = re.compile(r"<([^>]+)>")


def _strip_brackets(value: str) -> str:
    match = _ANGLE_BRACKET_RE.search(value or "")
    return match.group(1).strip() if match else ""


@iris_rules.register(
    name="Self-Referencing In-Reply-To",
    category="header_analysis",
    description=(
        "Detecta cuando In-Reply-To (o el primer References) apunta al "
        "propio Message-ID del correo. Patrón típico de kits de phishing "
        "que simulan hilos de respuesta fabricando las cabeceras."
    ),
)
def check_self_referencing_in_reply_to(headers: dict) -> RuleResult:
    message_id = _strip_brackets(headers.get("message-id", ""))
    in_reply_to = _strip_brackets(headers.get("in-reply-to", ""))
    references = headers.get("references", "")

    if not message_id:
        return RuleResult(
            score=0, verdict="neutral",
            details={"reason": "no message-id"},
            recommendation=None,
        )

    if in_reply_to and in_reply_to == message_id:
        return RuleResult(
            score=CR.get_iris_scoring_weight("self_referencing_thread.fail", -12), verdict="fail",
            details={
                "message_id": message_id,
                "in_reply_to": in_reply_to,
                "self_referencing_in_reply_to": True,
            },
            recommendation=(
                "El In-Reply-To del correo apunta al propio Message-ID. Una "
                "respuesta legítima nunca se cita a sí misma como su "
                "predecesora: las cabeceras de threading son fabricadas. "
                "Esto es típico de kits de phishing que simulan conversaciones."
            ),
        )

    first_ref = ""
    if references:
        ref_match = _ANGLE_BRACKET_RE.search(references)
        if ref_match:
            first_ref = ref_match.group(1).strip()
    if first_ref and first_ref == message_id:
        return RuleResult(
            score=CR.get_iris_scoring_weight("self_referencing_thread.fail", -12), verdict="fail",
            details={
                "message_id": message_id,
                "first_reference": first_ref,
                "self_referencing_in_references": True,
            },
            recommendation=(
                "El primer References del correo apunta al propio Message-ID. "
                "Las cabeceras de threading son fabricadas; el correo no es "
                "parte de un hilo legítimo."
            ),
        )

    return RuleResult(
        score=0, verdict="pass",
        details={"message_id": message_id},
        recommendation=None,
    )


@iris_rules.register(
    name="Message-ID check", category="header_analysis",
    description="Verifica que el Message-ID esté presente y tenga una longitud razonable",
)
def check_message_id(headers: dict) -> RuleResult:
    message_id = headers.get("message-id", "")

    if not message_id or len(message_id.strip()) < 5:
        # Recalibración de pesos (SOC): correo automatizado legítimo genera
        # Message-IDs cortos/ausentes con frecuencia; ruido puro de log,
        # nunca decide un veredicto por sí solo.
        return RuleResult(
            score=0, verdict="fail",
            details={"message_id": message_id or "missing", "length": len(message_id.strip())},
            recommendation="El Message-ID está ausente o es sospechosamente corto. "
                           "Los mensajes legítimos suelen tener un Message-ID único y completo.",
        )

    return RuleResult(
        score=1, verdict="pass",
        details={"message_id": message_id, "length": len(message_id.strip())},
        recommendation=None,
    )


@iris_rules.register(
    name="Message-ID Domain", category="header_analysis",
    description="Compara el dominio del Message-ID con el dominio del remitente",
)
def check_msgid_domain(headers: dict) -> RuleResult:
    """Compare the Message-ID domain against the From domain.

    Returns:
        - ``pass`` (score +1) when the Message-ID domain aligns with From,
          or is a known ESP sending domain (legitimate cross-domain pattern).
        - ``fail`` (score -3) when the domains differ for no benign reason.
        - ``neutral`` (score 0) when either domain is absent/unparseable.
    """
    message_id = headers.get("message-id", "")
    from_domain = registrable_domain(extract_domain(headers.get("from", "")))

    match = re.search(r"@([\w.-]+)", message_id)
    raw_msgid_domain = match.group(1).lower() if match else None
    msgid_domain = registrable_domain(raw_msgid_domain) if raw_msgid_domain else None

    if not msgid_domain or not from_domain:
        return RuleResult(score=0, verdict="neutral", details={"message_id": message_id}, recommendation=None)

    if msgid_domain == from_domain:
        return RuleResult(
            score=1, verdict="pass",
            details={"msgid_domain": msgid_domain, "from_domain": from_domain},
            recommendation=None,
        )

    # Legitimate ESPs generate the Message-ID on their own infrastructure;
    # a mismatch against a known ESP domain is expected, not suspicious.
    if msgid_domain in esp_msgid_domains():
        return RuleResult(
            score=0, verdict="pass",
            details={"msgid_domain": msgid_domain, "from_domain": from_domain, "esp": True},
            recommendation=None,
        )

    # Recalibración de pesos (SOC): residuo benigno una vez el ESP está
    # exento arriba, pero gana valor de corroboración junto a la nueva
    # correlación Message-ID <-> cadena Received (check_msgid_received_correlation).
    return RuleResult(
        score=CR.get_iris_scoring_weight("msgid_domain.fail", -2), verdict="fail",
        details={"msgid_domain": msgid_domain, "from_domain": from_domain},
        recommendation=(
            f"El dominio del Message-ID ({msgid_domain}) no coincide con el del remitente "
            f"({from_domain}). Puede ser legítimo (algunos servicios de envío generan el "
            "Message-ID en su propia infraestructura), pero también es un indicio de falsificación."
        ),
    )


@iris_rules.register(
    name="Message-ID Received Correlation",
    category="header_analysis",
    description=(
        "Comprueba que el dominio del Message-ID aparezca en algún host "
        "`by`/`from` de la propia cadena Received -- un Message-ID acuñado "
        "por un host completamente ausente de la cadena es una señal débil "
        "de fabricación de cabeceras, corroborante, no decisiva en solitario."
    ),
    needs_context=True,
)
def check_msgid_received_correlation(context) -> RuleResult:
    headers = context.headers
    message_id = headers.get("message-id", "")
    match = re.search(r"@([\w.-]+)", message_id)
    msgid_domain = registrable_domain(match.group(1).lower()) if match else None

    if not msgid_domain or not context.received_headers:
        return RuleResult(score=0, verdict="neutral", details={})

    # Calibración FP: un Message-ID acuñado con el dominio del PROPIO
    # remitente es el caso normal, no fabricación -- lo genera la aplicación
    # que compone el correo, que casi nunca es la máquina que aparece en la
    # cadena Received (relay por ESP, Mailgun/SendGrid/M365...). La señal de
    # esta regla es un Message-ID de un tercero ajeno tanto al From como a la
    # cadena; alineado con el From no aporta nada (y `check_msgid_domain` ya
    # cubre el desalineamiento From <-> Message-ID por separado).
    from_domain = registrable_domain(extract_domain(headers.get("from", "")))
    if from_domain and msgid_domain == from_domain:
        return RuleResult(
            score=0, verdict="pass",
            details={"msgid_domain": msgid_domain, "aligned_with_from": True},
        )

    # Mismo criterio que check_msgid_domain: los ESPs generan el Message-ID
    # en su propia infraestructura, nunca en la del remitente ni en ningún
    # salto Received -- exento igual, para no duplicar el mismo ruido.
    if msgid_domain in esp_msgid_domains():
        return RuleResult(score=0, verdict="pass", details={"msgid_domain": msgid_domain, "esp": True})

    chain_domains: set[str] = set()
    for line in context.received_headers:
        parsed = parse_received_line(line)
        for field in ("by", "from"):
            host = (parsed.get(field) or "").strip().rstrip(".,;")
            if host:
                dom = registrable_domain(host)
                if dom:
                    chain_domains.add(dom)

    if not chain_domains:
        return RuleResult(score=0, verdict="neutral", details={"reason": "no hosts in Received chain"})

    if msgid_domain in chain_domains:
        return RuleResult(score=0, verdict="pass", details={"msgid_domain": msgid_domain})

    return RuleResult(
        score=CR.get_iris_scoring_weight("msgid_received_correlation.fail", -4), verdict="fail",
        details={"msgid_domain": msgid_domain, "chain_domains": sorted(chain_domains)},
        recommendation=(
            f"El dominio del Message-ID ({msgid_domain}) no aparece en ningún salto de la "
            "propia cadena Received. Señal débil de fabricación de cabeceras; corrobora "
            "otras señales, no es decisiva en solitario."
        ),
    )
