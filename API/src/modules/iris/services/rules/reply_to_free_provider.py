"""
Reply-To / Return-Path to free provider rule — detects the classic Business
Email Compromise (BEC) pattern where the visible ``From`` looks corporate
but replies are silently redirected to a free webmail account.

Attackers spoof ``From: CEO <ceo@company.com>`` while setting
``Reply-To: ceo.private@gmail.com`` so the victim's reply (and any wire
transfer) goes to the attacker.  The generic Reply-To rule only checks for a
domain mismatch; this rule adds the high-signal case of a free-provider
reply target behind a corporate-looking sender.
"""

from ..registry import iris_rules, RuleResult
from ..shared import extract_domain, is_free_provider


@iris_rules.register(name="Reply-To Free Provider", category="header_analysis",
                     description="Detecta el patrón BEC: remitente con dominio corporativo pero Reply-To/Return-Path apuntando a un correo gratuito")
def check_reply_to_free_provider(headers: dict) -> RuleResult:
    """Flag a corporate-looking From whose reply target is a free webmail account.

    Returns:
        - ``fail`` (score -8) when From is non-free but Reply-To/Return-Path is free.
        - ``pass`` (score +1) otherwise.
        - ``neutral`` (score 0) when there is no From domain or no reply target.
    """
    from_domain = extract_domain(headers.get("from", ""))
    if not from_domain:
        return RuleResult(score=0, verdict="neutral", details={}, recommendation=None)

    # If the sender itself is a free provider, this pattern does not apply.
    if is_free_provider(from_domain):
        return RuleResult(score=1, verdict="pass", details={"from_domain": from_domain}, recommendation=None)

    redirect_targets: dict[str, str] = {}
    for header in ("reply-to", "return-path"):
        dom = extract_domain(headers.get(header, ""))
        if dom and is_free_provider(dom) and dom != from_domain:
            redirect_targets[header] = dom

    if not redirect_targets:
        return RuleResult(score=1, verdict="pass", details={"from_domain": from_domain}, recommendation=None)

    return RuleResult(
        score=-8, verdict="fail",
        details={"from_domain": from_domain, "free_reply_targets": redirect_targets},
        recommendation=(
            f"El remitente usa un dominio corporativo ({from_domain}) pero las respuestas se "
            f"redirigen a un correo gratuito ({', '.join(redirect_targets.values())}). "
            "Es un patrón típico de fraude del CEO (BEC): no respondas ni realices pagos sin "
            "verificar por un canal alternativo."
        ),
    )
