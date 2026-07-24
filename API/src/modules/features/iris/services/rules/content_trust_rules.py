"""
Bulk-mail trust signals — soft, mostly-informational checks that never
carry much weight on their own.

- **List-Unsubscribe**: presence of a well-formed unsubscribe mechanism
  (RFC 8058 one-click) is a weak *positive* legitimacy signal for bulk
  mail — reputable senders include it, targeted phishing rarely bothers.
  Forgeable, so the weight stays small and never negative.

Recalibración de pesos (F6): "Content-Type check" vivía aquí y se ha
retirado -- confirmado código muerto (siempre devolvía score=0, nunca
aportaba señal real; el propio módulo lo documentaba como informativo puro).
"""

from __future__ import annotations

from ..registry import iris_rules, RuleResult


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
