"""
Self-Referencing In-Reply-To rule — flags messages whose ``In-Reply-To``
or first ``References`` entry points to the message's own ``Message-ID``.

A legitimate reply always has an ``In-Reply-To`` whose ID was generated
by a *previous*, *different* message. Phishing kits that simulate
replies sometimes fabricate a Message-ID, then reuse the same value as
the In-Reply-To of a follow-up message to make the thread look
continuous. Detecting the self-reference is a cheap, high-signal
indicator that the threading is forged.
"""

import re

from ..registry import iris_rules, RuleResult

_MESSAGE_ID_RE = re.compile(r"<([^>]+)>")
_INREPLYTO_RE = re.compile(r"<([^>]+)>")
_REFERENCES_RE = re.compile(r"<([^>]+)>")


def _strip_brackets(value: str) -> str:
    match = _MESSAGE_ID_RE.search(value or "")
    return match.group(1).strip() if match else ""


@iris_rules.register(
    name="Self-Referencing In-Reply-To",
    category="header_analysis",
    description=(
        "Detecta cuando In-Reply-To (o el primer References) apunta al "
        "propio Message-ID del correo. Patrón típico de kits de phishing "
        "que simulan hilos de respuesta fabricando las cabeceras."
    ),
)
def check_self_referencing_in_reply_to(headers: dict) -> RuleResult:
    message_id = _strip_brackets(headers.get("message-id", ""))
    in_reply_to = _strip_brackets(headers.get("in-reply-to", ""))
    references = headers.get("references", "")

    if not message_id:
        return RuleResult(
            score=0, verdict="neutral",
            details={"reason": "no message-id"},
            recommendation=None,
        )

    if in_reply_to and in_reply_to == message_id:
        return RuleResult(
            score=-12, verdict="fail",
            details={
                "message_id": message_id,
                "in_reply_to": in_reply_to,
                "self_referencing_in_reply_to": True,
            },
            recommendation=(
                "El In-Reply-To del correo apunta al propio Message-ID. Una "
                "respuesta legítima nunca se cita a sí misma como su "
                "predecesora: las cabeceras de threading son fabricadas. "
                "Esto es típico de kits de phishing que simulan conversaciones."
            ),
        )

    first_ref = ""
    if references:
        ref_match = _REFERENCES_RE.search(references)
        if ref_match:
            first_ref = ref_match.group(1).strip()
    if first_ref and first_ref == message_id:
        return RuleResult(
            score=-12, verdict="fail",
            details={
                "message_id": message_id,
                "first_reference": first_ref,
                "self_referencing_in_references": True,
            },
            recommendation=(
                "El primer References del correo apunta al propio Message-ID. "
                "Las cabeceras de threading son fabricadas; el correo no es "
                "parte de un hilo legítimo."
            ),
        )

    return RuleResult(
        score=0, verdict="pass",
        details={"message_id": message_id},
        recommendation=None,
    )
