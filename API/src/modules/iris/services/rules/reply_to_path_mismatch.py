"""
From / Reply-To / Return-Path Triangulation rule — flags messages where
the three identity headers point to three *different* organisational
domains, which is structurally inconsistent with a normal business
email.

In a normal business email:
- From and Reply-To may differ at the *subdomain* level (e.g. different
  marketing subdomains) but share the registrable domain.
- Return-Path (envelope sender) is often a transactional mailer domain
  (SendGrid, Mailgun, etc.) but still ties to the same organisation.
- All three pointing to *three unrelated* registrable domains is the
  fingerprint of a phishing campaign that hops through multiple
  infrastructures, or a BEC attack that uses a compromised account
  with a free-mail Reply-To.

The existing ``reply_to`` and ``return_path_mismatch`` rules compare
two at a time; this rule checks the trio as a whole.
"""

import re

from ..registry import iris_rules, RuleResult
from ..shared import extract_domain, registrable_domain


def _email_domain(header_value: str) -> str | None:
    if not header_value:
        return None
    match = re.search(r"[\w.+-]+@([\w.-]+)", header_value)
    if not match:
        return None
    return registrable_domain(extract_domain(match.group(0)))


@iris_rules.register(
    name="From Reply-To Return-Path Triangulation",
    category="header_analysis",
    description=(
        "Detecta mensajes donde From, Reply-To y Return-Path apuntan a tres "
        "dominios organizativos diferentes, una firma estructural de "
        "phishing/BEC que los chequeos de a pares no detectan."
    ),
)
def check_triangulation(headers: dict) -> RuleResult:
    from_dom = _email_domain(headers.get("from", ""))
    reply_dom = _email_domain(headers.get("reply-to", ""))
    return_dom = _email_domain(
        headers.get("return-path", "")
        or headers.get("envelope-from", "")
        or headers.get("sender", "")
    )

    if not from_dom:
        return RuleResult(score=0, verdict="neutral", details={}, recommendation=None)

    present = [d for d in (from_dom, reply_dom, return_dom) if d]
    distinct = set(present)

    if len(distinct) < 3:
        return RuleResult(
            score=0, verdict="neutral",
            details={
                "from_domain": from_dom,
                "reply_to_domain": reply_dom,
                "return_path_domain": return_dom,
                "distinct_count": len(distinct),
            },
            recommendation=None,
        )

    return RuleResult(
        score=-12, verdict="fail",
        details={
            "from_domain": from_dom,
            "reply_to_domain": reply_dom,
            "return_path_domain": return_dom,
            "distinct_count": len(distinct),
        },
        recommendation=(
            f"Las tres cabeceras de identidad apuntan a tres dominios "
            f"organizativos distintos: From={from_dom}, Reply-To={reply_dom}, "
            f"Return-Path={return_dom}. En un correo legítimo estos dominios "
            "suelen coincidir o pertenecer a la misma organización (con "
            "subdominios del ESP como excepción). Esta triangulación es una "
            "firma estructural de phishing/BEC: el mensaje atraviesa o imita "
            "infraestructuras no relacionadas."
        ),
    )
