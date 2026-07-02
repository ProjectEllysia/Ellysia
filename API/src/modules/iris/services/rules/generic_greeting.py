"""
Generic Greeting + Action Verb rule — flags the canonical mass-mailing
phishing pattern: a generic greeting ("Dear customer / Dear user / Dear
sir or madam") combined with a high-signal action verb
("verify / confirm / update / suspend / password") in the body.

Both elements on their own are weak: legitimate first-time mailouts use
generic greetings, and many legitimate transactional emails use action
verbs. The *combination* is the strong signal — bulk phish rarely
personalises and almost always asks the user to do something risky.
"""

from ..registry import iris_rules, RuleResult
from ..shared import action_verbs, generic_greetings, strip_html


@iris_rules.register(
    name="Generic Greeting",
    category="content_analysis",
    description=(
        "Detecta el patrón clásico de phishing masivo: saludo genérico "
        "('Dear customer') combinado con un verbo de acción sospechoso "
        "('verify', 'confirm', 'update') en el cuerpo del correo."
    ),
    needs_context=True,
)
def check_generic_greeting(context) -> RuleResult:
    body_html = context.body_html or ""
    body_text = context.body_text or ""
    text = (body_text + " " + strip_html(body_html)).lower()
    if not text.strip():
        return RuleResult(score=0, verdict="neutral", details={"reason": "empty body"})

    first_chunk = text[:600]

    greeting_hits = [g for g in generic_greetings() if g in first_chunk]
    action_hits = [v for v in action_verbs() if v in text]

    if not greeting_hits or not action_hits:
        return RuleResult(
            score=0, verdict="neutral",
            details={"greeting_hits": greeting_hits, "action_hits": action_hits},
            recommendation=None,
        )

    score = -8
    if len(action_hits) >= 2:
        score -= 3

    return RuleResult(
        score=score, verdict="fail",
        details={
            "greeting_hits": greeting_hits,
            "action_hits": action_hits,
        },
        recommendation=(
            "El correo usa un saludo genérico "
            f"('{greeting_hits[0]}') y un verbo de acción sospechoso "
            f"('{action_hits[0]}'). Esta combinación es típica del phishing "
            "masivo: los remitentes legítimos que tienen tu dirección suelen "
            "personalizar el saludo. Verifica la legitimidad antes de actuar."
        ),
    )
