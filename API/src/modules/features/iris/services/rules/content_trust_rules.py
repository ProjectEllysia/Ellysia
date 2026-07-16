"""
Content-type and bulk-mail trust signals — soft, mostly-informational
checks that never carry much weight on their own.

- **Content-Type check**: informational report of the body MIME type.
  Plain-text-only used to be treated as a mild phishing signal, but a huge
  volume of legitimate transactional mail is plain-text only while modern
  phishing is almost always HTML — the discriminating power is ~zero, so
  this rule never penalises, only reports.
- **List-Unsubscribe**: presence of a well-formed unsubscribe mechanism
  (RFC 8058 one-click) is a weak *positive* legitimacy signal for bulk
  mail — reputable senders include it, targeted phishing rarely bothers.
  Forgeable, so the weight stays small and never negative.
"""

from __future__ import annotations

from ..registry import iris_rules, RuleResult


@iris_rules.register(
    name="Content-Type check", category="header_analysis",
    description="Informa del tipo de contenido del correo (texto plano vs multipart/HTML)",
)
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


@iris_rules.register(
    name="List-Unsubscribe", category="header_analysis",
    description="Detecta un mecanismo de baja (List-Unsubscribe) válido como señal débil de legitimidad de correo masivo",
)
def check_list_unsubscribe(headers: dict) -> RuleResult:
    """Reward a valid List-Unsubscribe mechanism.

    Returns:
        - ``pass`` (score +2/+3) when List-Unsubscribe (and one-click) is present.
        - ``neutral`` (score 0) when absent.
    """
    unsubscribe = headers.get("list-unsubscribe", "").strip()
    if not unsubscribe:
        return RuleResult(score=0, verdict="neutral", details={}, recommendation=None)

    has_target = "http" in unsubscribe.lower() or "mailto:" in unsubscribe.lower()
    if not has_target:
        return RuleResult(score=0, verdict="neutral",
                          details={"list_unsubscribe": unsubscribe}, recommendation=None)

    one_click = "one-click" in headers.get("list-unsubscribe-post", "").lower()
    return RuleResult(
        score=3 if one_click else 2,
        verdict="pass",
        details={"list_unsubscribe": unsubscribe, "one_click": one_click},
        recommendation=None,
    )
