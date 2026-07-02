"""
Message-ID check rule — verifies the presence and length of Message-ID.

Legitimate emails always carry a unique Message-ID. A missing or
suspiciously short value is common in bulk-phishing campaigns.
"""

from ..registry import iris_rules, RuleResult


@iris_rules.register(name="Message-ID check", category="header_analysis",
                     description="Verifica que el Message-ID esté presente y tenga una longitud razonable")
def check_message_id(headers: dict) -> RuleResult:
    message_id = headers.get("message-id", "")

    if not message_id or len(message_id.strip()) < 5:
        return RuleResult(
            score=-4, verdict="fail",
            details={"message_id": message_id or "missing", "length": len(message_id.strip())},
            recommendation="El Message-ID está ausente o es sospechosamente corto. "
                           "Los mensajes legítimos suelen tener un Message-ID único y completo.",
        )

    return RuleResult(
        score=1, verdict="pass",
        details={"message_id": message_id, "length": len(message_id.strip())},
        recommendation=None,
    )
