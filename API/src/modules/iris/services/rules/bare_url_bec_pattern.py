"""
BEC / Wire-Transfer Pattern rule — flags the classic Business Email
Compromise payload: a corporate-looking sender requesting an urgent
financial action (wire transfer, gift cards, crypto, banking change).

The body-content rule already detects credential phrases, but it does
not weight them against the *legitimacy* of the sender domain. In a BEC
attack, the sender domain is the real corporate domain (it was either
spoofed successfully or a legitimate account was compromised) and the
phishing signal lives entirely in the body asking for money.
"""

from ..registry import iris_rules, RuleResult
from ..shared import bec_phrases, extract_domain, registrable_domain, strip_html


@iris_rules.register(
    name="BEC Wire Transfer Pattern",
    category="content_analysis",
    description=(
        "Detecta el patrón típico de BEC (Business Email Compromise): "
        "remitente con dominio corporativo y cuerpo pidiendo wire transfer, "
        "cripto, tarjetas de regalo, o cambio de cuenta bancaria."
    ),
    needs_context=True,
)
def check_bec_wire_pattern(context) -> RuleResult:
    headers = context.headers
    body_html = context.body_html or ""
    body_text = context.body_text or ""
    text = (body_text + " " + strip_html(body_html)).lower()

    from_domain = registrable_domain(extract_domain(headers.get("from", "")))
    reply_domain = registrable_domain(extract_domain(headers.get("reply-to", "")))

    if not from_domain:
        return RuleResult(score=0, verdict="neutral", details={}, recommendation=None)

    matches = [p for p in bec_phrases() if p in text]

    if not matches:
        return RuleResult(score=0, verdict="neutral",
                          details={"from_domain": from_domain, "matches": []}, recommendation=None)

    suspicious_redirect = (
        reply_domain and reply_domain != from_domain
    )

    base = -15
    if len(matches) >= 2:
        base -= 6
    if suspicious_redirect:
        base -= 4

    return RuleResult(
        score=base, verdict="fail",
        details={
            "from_domain": from_domain,
            "reply_domain": reply_domain,
            "matches": matches,
            "redirect_to_external_reply": suspicious_redirect,
        },
        recommendation=(
            f"El cuerpo contiene {len(matches)} frase(s) típica(s) de fraude BEC "
            f"({', '.join(matches[:3])}). El remitente usa un dominio "
            f"corporativo ({from_domain}), lo que hace este patrón especialmente "
            "peligroso: si el dominio es legítimo, la cuenta puede estar "
            "comprometida; si es suplantado, es un ataque dirigido. Verifica "
            "por un canal alternativo (teléfono, en persona) ANTES de "
            "realizar cualquier pago o cambio de datos bancarios."
        ),
    )
