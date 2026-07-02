"""
From header check rule — verifies that the From header is present and
well-formed.

A missing or malformed From header is a strong phishing indicator since
legitimate mailers always set a valid sender address.
"""

from ..registry import iris_rules, RuleResult


@iris_rules.register(name="From header check", category="header_analysis",
                     description="Verifica que la cabecera From esté presente y no esté vacía")
def check_from_header(headers: dict) -> RuleResult:
    from_addr = headers.get("from", "")

    if not from_addr or "<>" in from_addr:
        return RuleResult(
            score=-10, verdict="fail",
            details={"from": from_addr or "missing"},
            recommendation="La cabecera From está vacía o es inválida. "
                           "Un correo legítimo siempre tiene un remitente identificable.",
        )

    return RuleResult(
        score=1, verdict="pass",
        details={"from": from_addr},
        recommendation=None,
    )
