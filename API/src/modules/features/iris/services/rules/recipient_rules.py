"""
Recipient rules — who was this message actually addressed to?

- **Undisclosed Recipients**: the To header is empty or set to
  "undisclosed-recipients", indicating the email was sent via BCC
  (common in phishing blasts, though also used by legitimate
  newsletters — this is a soft signal, not a strong one).
"""

from __future__ import annotations

import src.modules.system.config_reading as CR
from ..registry import iris_rules, RuleResult
from ..wordlists import undisclosed_patterns


@iris_rules.register(
    name="Undisclosed Recipients", rule_id="iris.recipient.undisclosed_recipients", severity="low", evidence_headers=("to", "cc"), category="header_analysis",
    description="Detecta si el campo To está vacío o contiene destinatarios no revelados (BCC)",
)
def check_undisclosed_recipients(headers: dict) -> RuleResult:
    to_addr = headers.get("to", "")
    cc_addr = headers.get("cc", "")

    to_stripped = to_addr.strip()
    cc_stripped = cc_addr.strip()

    is_to_empty = not to_stripped
    is_undisclosed = any(pattern in to_stripped.lower() for pattern in undisclosed_patterns())

    if is_to_empty and not cc_stripped:
        return RuleResult(
            score=CR.get_iris_scoring_weight("undisclosed_recipients.empty", -3), verdict="empty",  # recalibración de pesos
            details={
                "to": to_addr or "missing",
                "cc": cc_addr or "missing",
                "reason": "To and CC are both empty — BCC-only send",
            },
            recommendation=(
                "El correo no tiene destinatarios visibles (To ni CC), "
                "lo que indica que se envió con todos los destinatarios en copia oculta (BCC). "
                "Aunque algunas listas de correo legítimas usan este método, "
                "también es común en campañas de phishing masivas."
            ),
        )

    if is_undisclosed:
        return RuleResult(
            score=CR.get_iris_scoring_weight("undisclosed_recipients.undisclosed", -3), verdict="undisclosed",  # recalibración de pesos
            details={
                "to": to_stripped,
                "reason": "To header set to undisclosed recipients",
            },
            recommendation=(
                "El campo To contiene 'Undisclosed-Recipients', indicando que "
                "los destinatarios reales están ocultos (BCC). "
                "Los correos legítimos de remitentes conocidos suelen dirigirse "
                "al destinatario por su nombre o dirección de correo."
            ),
        )

    if is_to_empty and cc_stripped:
        return RuleResult(
            score=0, verdict="empty_to",  # recalibración de pesos
            details={
                "to": "missing",
                "cc": cc_stripped,
                "reason": "To is empty but CC is present",
            },
            recommendation=(
                "El campo To está vacío pero hay destinatarios en CC. "
                "Es poco común pero posible en ciertos flujos de trabajo."
            ),
        )

    return RuleResult(
        score=2, verdict="pass",
        details={
            "to": to_stripped,
            "cc": cc_stripped,
        },
        recommendation=None,
    )
