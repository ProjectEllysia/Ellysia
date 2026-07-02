"""
Message-ID Domain rule — compares the domain inside the Message-ID with the
From domain.

Legitimate mail systems normally generate the Message-ID on the sending
infrastructure of the From domain, so a Message-ID whose domain is unrelated
to the sender is a (weak) spoofing indicator.  Kept low-weight because some
legitimate ESPs generate Message-IDs on their own infrastructure.
"""

import re

from ..registry import iris_rules, RuleResult
from ..shared import esp_msgid_domains, extract_domain, registrable_domain


@iris_rules.register(name="Message-ID Domain", category="header_analysis",
                     description="Compara el dominio del Message-ID con el dominio del remitente")
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

    return RuleResult(
        score=-3, verdict="fail",
        details={"msgid_domain": msgid_domain, "from_domain": from_domain},
        recommendation=(
            f"El dominio del Message-ID ({msgid_domain}) no coincide con el del remitente "
            f"({from_domain}). Puede ser legítimo (algunos servicios de envío generan el "
            "Message-ID en su propia infraestructura), pero también es un indicio de falsificación."
        ),
    )
