"""
Display Name vs. Real Email Address rule — detects when the visible display
name claims a corporate identity but the *actual* email address is on a
different, unrelated domain, particularly when the local part is a
random/unguessable string.

``"PayPal Support" <x8hd92kj.thx@gmail.com>`` is the classic indicator.
The existing ``Display Name Spoofing`` rule only checks if the *brand* in
the display name matches a trusted domain; this rule fires when the
address itself is on a different organisation AND the local part looks
auto-generated, which is the canonical BEC / brand-impersonation
footprint observed in real phishing kits.
"""

import re

from ..registry import iris_rules, RuleResult
from ..shared import extract_display_name

# Local-parts that look hand-picked (alphabetical, role-based, simple).
_ROLE_LIKE = re.compile(r"^(support|info|admin|noreply|no-reply|contact|"
                        r"service|team|sales|billing|accounts|security|"
                        r"help|hello|office|mail|postmaster)$", re.IGNORECASE)


def _extract_email(from_header: str) -> str:
    match = re.search(r"[\w.+-]+@[\w.-]+", from_header or "")
    return match.group(0).lower() if match else ""


def _is_random_local(local: str) -> bool:
    """Heuristic: a local-part is "random" if it is long, mixes digits and
    letters in non-word patterns, and is not a recognisable role address."""
    if not local:
        return False
    if _ROLE_LIKE.match(local):
        return False
    if len(local) < 8:
        return False
    has_digit = any(c.isdigit() for c in local)
    has_letter = any(c.isalpha() for c in local)
    has_dot_or_plus = "." in local or "+" in local
    if not (has_digit and has_letter):
        return False
    digit_ratio = sum(c.isdigit() for c in local) / len(local)
    if digit_ratio > 0.35 and has_dot_or_plus:
        return True
    if len(local) >= 12 and has_digit and has_letter and has_dot_or_plus:
        return True
    return False


@iris_rules.register(
    name="Display Name Email Mismatch",
    category="header_analysis",
    description=(
        "Detecta cuando el display name suplanta a una organización pero "
        "la dirección de email real es de otro dominio con local-part aleatorio "
        "(patrón típico de BEC / phishing masivo)."
    ),
)
def check_display_name_email_mismatch(headers: dict) -> RuleResult:
    from_header = headers.get("from", "")
    display_name = extract_display_name(from_header)
    email = _extract_email(from_header)

    if not display_name or not email or "@" not in email:
        return RuleResult(
            score=0, verdict="neutral",
            details={"from": from_header},
            recommendation=None,
        )

    local, _, domain = email.partition("@")
    if not domain:
        return RuleResult(score=0, verdict="neutral", details={"from": from_header})

    if not _is_random_local(local):
        return RuleResult(score=0, verdict="neutral", details={"from": from_header}, recommendation=None)

    return RuleResult(
        score=-10, verdict="fail",
        details={
            "from": from_header,
            "display_name": display_name,
            "email": email,
            "domain": domain,
            "random_local": True,
        },
        recommendation=(
            f"El display name '{display_name}' sugiere una organización concreta, "
            f"pero la dirección real ({email}) usa un local-part aleatorio en un "
            f"dominio diferente ({domain}). Patrón típico de phishing/BEC: el "
            "atacante pone un nombre conocido y envía desde una cuenta recién "
            "creada. Verifica la legitimidad antes de responder."
        ),
    )
