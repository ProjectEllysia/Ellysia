"""
List-Unsubscribe rule — treats the presence of a well-formed unsubscribe
mechanism as a (weak) legitimacy signal.

Reputable bulk / marketing senders include ``List-Unsubscribe`` (and often
``List-Unsubscribe-Post`` for one-click RFC 8058 unsubscription).  Targeted
phishing rarely bothers, so a valid unsubscribe header slightly raises
credibility.  It is only a soft signal — phishing *can* forge it — so the
weight is small and never negative.
"""

from ..registry import iris_rules, RuleResult


@iris_rules.register(name="List-Unsubscribe", category="header_analysis",
                     description="Detecta un mecanismo de baja (List-Unsubscribe) válido como señal débil de legitimidad de correo masivo")
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
