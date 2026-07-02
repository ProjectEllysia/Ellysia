"""
Content-Type check rule — informational report of the message body type.

Being plain-text-only used to be treated as a mild phishing signal, but in
practice a huge volume of *legitimate* transactional mail (GitHub, Slack,
bank and university notifications) is plain-text only, while modern phishing
is almost always HTML. The discriminating power is therefore ~zero, so this
rule no longer penalises plain-text — it only reports the content type.
"""

from ..registry import iris_rules, RuleResult


@iris_rules.register(name="Content-Type check", category="header_analysis",
                     description="Informa del tipo de contenido del correo (texto plano vs multipart/HTML)")
def check_content_type(headers: dict) -> RuleResult:
    content_type = headers.get("content-type", "")

    if not content_type:
        return RuleResult(
            score=0, verdict="neutral",
            details={"content_type": "missing"},
            recommendation=None,
        )

    if "multipart" not in content_type.lower() and "text/plain" in content_type.lower():
        # Plain-text-only: informational, not a penalty (very common in legit mail).
        return RuleResult(
            score=0, verdict="pass",
            details={"content_type": "text/plain only (no HTML alternative)"},
            recommendation=None,
        )

    return RuleResult(
        score=0, verdict="pass",
        details={"content_type": content_type},
        recommendation=None,
    )
