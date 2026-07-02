"""
Reply-To mismatch rule — detects when Reply-To differs from From.

Phishing campaigns often set Reply-To to an attacker-controlled address
so that replies go to the attacker even if the From address is legitimate.
"""

from ..registry import iris_rules, RuleResult
from ..shared import registrable_domain


@iris_rules.register(name="Reply-To check", category="header_analysis",
                     description="Detecta si Reply-To difiere del remitente real")
def check_reply_to(headers: dict) -> RuleResult:
    """Detect when ``Reply-To`` points to a different organisation than ``From``.

    Phishing campaigns routinely set Reply-To to an attacker-controlled
    address so that replies bypass the victim's mailbox. Legitimate bulk
    mail (ESP-sent newsletters) commonly uses a *different subdomain of the
    same organisation* for Reply-To (e.g. ``comunicaciones.unir.net`` vs
    ``info.unir.net``), so domains are compared at the registrable-domain
    level rather than as exact strings.

    Returns:
        - ``pass`` (score +3) when Reply-To is absent or organisationally
          aligned with From.
        - ``fail`` (score -10) when the organisational domains differ.
        - ``neutral`` (score 0) when From is missing entirely.
    """
    from_addr = headers.get("from", "")
    reply_to = headers.get("reply-to", "")

    if not reply_to:
        return RuleResult(
            score=3, verdict="pass",
            details={"reply_to": "not present — normal behaviour"},
            recommendation=None,
        )

    if not from_addr:
        return RuleResult(
            score=0, verdict="neutral",
            details={"from": "missing"},
            recommendation="No se encontró cabecera 'From'. El correo está gravemente malformado.",
        )

    from_domain = from_addr.split("@")[-1].rstrip(">").strip() if "@" in from_addr else from_addr
    reply_domain = reply_to.split("@")[-1].rstrip(">").strip() if "@" in reply_to else reply_to

    if registrable_domain(from_domain) != registrable_domain(reply_domain):
        return RuleResult(
            score=-10, verdict="fail",
            details={
                "from": from_addr,
                "reply_to": reply_to,
                "from_domain": from_domain,
                "reply_domain": reply_domain,
            },
            recommendation="La dirección Reply-To apunta a un dominio diferente al remitente. "
                           "En ataques de phishing, las respuestas se redirigen al atacante. "
                           "Verifica que esta diferencia sea intencionada.",
        )

    return RuleResult(
        score=3, verdict="pass",
        details={"from": from_addr, "reply_to": reply_to, "match": True},
        recommendation=None,
    )
