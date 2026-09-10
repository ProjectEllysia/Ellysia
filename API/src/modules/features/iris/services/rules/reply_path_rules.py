"""
Reply-To / Return-Path rules — where does a reply (or a bounce) actually
go, and does that match who the message claims to be from?

- **Reply-To check**: pairwise From vs Reply-To organisational mismatch.
- **Reply-To Free Provider**: the high-signal BEC case — a corporate-
  looking From whose Reply-To/Return-Path is a free webmail account.
- **Return-Path mismatch**: pairwise From vs Return-Path (envelope
  sender) organisational mismatch.
- **Triangulation**: checks all three identity headers *together* — if
  From, Reply-To and Return-Path point to three mutually distinct
  organisational domains, that's a structural phishing/BEC fingerprint
  the pairwise checks above can miss (e.g. From/Return-Path aligned but
  Reply-To elsewhere would already trip "Reply-To check"; this rule adds
  coverage for the case where all three genuinely diverge).

These deliberately overlap in the "all three differ" case — a message can
trip Reply-To check *and* Triangulation at once, and that's intended
layered evidence, not double-counting a single fact: each rule is testing
a different structural claim.
"""

from __future__ import annotations

import re

import src.modules.system.config_reading as CR
from ..registry import iris_rules, RuleResult
from ..wordlists import esp_msgid_domains, esp_tracker_domains
from ..text import extract_domain, is_free_provider, registrable_domain


def _is_esp_domain(domain: str | None) -> bool:
    """True when *domain* is a known ESP infrastructure domain.

    A newsletter sent via Mailchimp/SendGrid legitimately has three
    distinct registrable domains across From/Reply-To/Return-Path — that
    is the ESP's normal architecture, not evidence of anything. Reuses
    the allowlists already trusted for Message-ID and image-tracking
    checks so this doesn't drift into a fourth copy of "is this a known
    ESP domain".
    """
    if not domain:
        return False
    return domain in esp_msgid_domains() or domain in esp_tracker_domains()


@iris_rules.register(
    name="Reply-To check", category="header_analysis", family="reply_path",
    description="Detecta si Reply-To difiere del remitente real",
)
def check_reply_to(headers: dict) -> RuleResult:
    """Detect when ``Reply-To`` points to a different organisation than ``From``.

    Phishing campaigns routinely set Reply-To to an attacker-controlled
    address so that replies bypass the victim's mailbox. Legitimate bulk
    mail (ESP-sent newsletters) commonly uses a *different subdomain of the
    same organisation* for Reply-To (e.g. ``comunicaciones.unir.net`` vs
    ``info.unir.net``), so domains are compared at the registrable-domain
    level rather than as exact strings.

    Returns:
        - ``pass`` (score +3) when Reply-To is absent or organisationally
          aligned with From.
        - ``fail`` (score -10) when the organisational domains differ.
        - ``neutral`` (score 0) when From is missing entirely.
    """
    from_addr = headers.get("from", "")
    reply_to = headers.get("reply-to", "")

    if not reply_to:
        return RuleResult(
            score=3, verdict="pass",
            details={"reply_to": "not present — normal behaviour"},
            recommendation=None,
        )

    if not from_addr:
        return RuleResult(
            score=0, verdict="neutral",
            details={"from": "missing"},
            recommendation="No se encontró cabecera 'From'. El correo está gravemente malformado.",
        )

    from_domain = from_addr.split("@")[-1].rstrip(">").strip() if "@" in from_addr else from_addr
    reply_domain = reply_to.split("@")[-1].rstrip(">").strip() if "@" in reply_to else reply_to

    if _is_esp_domain(registrable_domain(reply_domain)):
        return RuleResult(
            score=1, verdict="pass",
            details={"from": from_addr, "reply_to": reply_to, "esp": True},
            recommendation=None,
        )

    if registrable_domain(from_domain) != registrable_domain(reply_domain):
        # Recalibración de pesos (F3): si además Return-Path diverge, las
        # tres cabeceras difieren y Triangulation ya puntúa exactamente
        # este mismo hecho con su propio peso -- suprimir aquí evita
        # cobrarlo dos veces. El hallazgo se conserva (verdict "fail") para
        # que el informe siga mostrándolo, solo deja de restar.
        if _triangulation_would_fire(headers):
            return RuleResult(
                score=0, verdict="fail",
                details={
                    "from": from_addr, "reply_to": reply_to,
                    "from_domain": from_domain, "reply_domain": reply_domain,
                    "suppressed_by": "triangulation",
                },
                recommendation=None,
            )
        return RuleResult(
            score=CR.get_iris_scoring_weight("reply_to.mismatch", -6), verdict="fail",
            details={
                "from": from_addr,
                "reply_to": reply_to,
                "from_domain": from_domain,
                "reply_domain": reply_domain,
            },
            recommendation="La dirección Reply-To apunta a un dominio diferente al remitente. "
                           "En ataques de phishing, las respuestas se redirigen al atacante. "
                           "Verifica que esta diferencia sea intencionada.",
        )

    return RuleResult(
        score=3, verdict="pass",
        details={"from": from_addr, "reply_to": reply_to, "match": True},
        recommendation=None,
    )


@iris_rules.register(
    name="Reply-To Free Provider", category="header_analysis", family="reply_path",
    description="Detecta el patrón BEC: remitente con dominio corporativo pero Reply-To/Return-Path apuntando a un correo gratuito",
)
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
        score=CR.get_iris_scoring_weight("reply_to_free_provider.fail", -8), verdict="fail",
        details={"from_domain": from_domain, "free_reply_targets": redirect_targets},
        recommendation=(
            f"El remitente usa un dominio corporativo ({from_domain}) pero las respuestas se "
            f"redirigen a un correo gratuito ({', '.join(redirect_targets.values())}). "
            "Es un patrón típico de fraude del CEO (BEC): no respondas ni realices pagos sin "
            "verificar por un canal alternativo."
        ),
    )


@iris_rules.register(
    name="Return-Path mismatch", category="header_analysis", family="reply_path",
    description="Detecta si el dominio en Return-Path difiere del remitente visible",
)
def check_return_path(headers: dict) -> RuleResult:
    return_path = headers.get("return-path", "") or headers.get("envelope-from", "") or headers.get("sender", "")
    from_addr = headers.get("from", "")

    if not return_path:
        return RuleResult(
            score=0, verdict="neutral",
            details={"return_path": "not present"},
            recommendation="No se encontró cabecera Return-Path. Sin ella no se puede verificar la ruta de entrega.",
        )

    if not from_addr:
        return RuleResult(
            score=0, verdict="neutral",
            details={"from": "missing"},
            recommendation=None,
        )

    # F4: compared at the registrable-domain level, matching check_reply_to's
    # sibling logic — a full-hostname compare flags every ESP/bounce
    # subdomain (``bounce.mail.paypal.com`` vs ``paypal.com``) as a mismatch,
    # which is the normal shape of transactional/bulk mail, not spoofing.
    rp_domain = registrable_domain(extract_domain(return_path))
    from_domain = registrable_domain(extract_domain(from_addr))

    if rp_domain and from_domain and rp_domain != from_domain and not _is_esp_domain(rp_domain):
        # Recalibración de pesos (F3): igual que Reply-To check, se suprime
        # cuando Triangulation ya puntúa el mismo hecho de fondo.
        if _triangulation_would_fire(headers):
            return RuleResult(
                score=0, verdict="fail",
                details={
                    "return_path_domain": rp_domain, "from_domain": from_domain,
                    "return_path": return_path, "from": from_addr,
                    "suppressed_by": "triangulation",
                },
                recommendation=None,
            )
        return RuleResult(
            score=CR.get_iris_scoring_weight("return_path.mismatch", -4), verdict="fail",
            details={
                "return_path_domain": rp_domain,
                "from_domain": from_domain,
                "return_path": return_path,
                "from": from_addr,
            },
            recommendation="El dominio en Return-Path no coincide con el dominio remitente. "
                           "Indica que el mensaje pudo ser generado por un servidor no autorizado.",
        )

    return RuleResult(
        score=2, verdict="pass",
        details={
            "return_path_domain": rp_domain, "from_domain": from_domain,
            "match": rp_domain == from_domain,
        },
        recommendation=None,
    )


def _email_domain(header_value: str) -> str | None:
    if not header_value:
        return None
    match = re.search(r"[\w.+-]+@([\w.-]+)", header_value)
    if not match:
        return None
    return registrable_domain(extract_domain(match.group(0)))


def _triangulation_would_fire(headers: dict) -> bool:
    """True cuando From/Reply-To/Return-Path apuntan a tres dominios
    organizativos distintos y ninguno es un ESP -- la misma condición que
    dispara ``check_triangulation`` más abajo. ``check_reply_to`` y
    ``check_return_path`` la consultan para suprimirse cuando triangula:
    Triangulation ya puntúa ese mismo hecho con su propio peso (F3), así
    que los pairwise no vuelven a cobrarlo.
    """
    from_dom = _email_domain(headers.get("from", ""))
    if not from_dom:
        return False
    reply_dom = _email_domain(headers.get("reply-to", ""))
    return_dom = _email_domain(
        headers.get("return-path", "") or headers.get("envelope-from", "") or headers.get("sender", "")
    )
    distinct = {domain for domain in (from_dom, reply_dom, return_dom) if domain}
    esp_involved = _is_esp_domain(reply_dom) or _is_esp_domain(return_dom)
    return len(distinct) >= 3 and not esp_involved


@iris_rules.register(
    name="From Reply-To Return-Path Triangulation",
    category="header_analysis", family="reply_path",
    description=(
        "Detecta mensajes donde From, Reply-To y Return-Path apuntan a tres "
        "dominios organizativos diferentes, una firma estructural de "
        "phishing/BEC que los chequeos de a pares no detectan."
    ),
)
def check_triangulation(headers: dict) -> RuleResult:
    from_dom = _email_domain(headers.get("from", ""))
    reply_dom = _email_domain(headers.get("reply-to", ""))
    return_dom = _email_domain(
        headers.get("return-path", "")
        or headers.get("envelope-from", "")
        or headers.get("sender", "")
    )

    if not from_dom:
        return RuleResult(score=0, verdict="neutral", details={}, recommendation=None)

    present = [domain for domain in (from_dom, reply_dom, return_dom) if domain]
    distinct = set(present)

    # A Reply-To/Return-Path on a known ESP domain is exactly what
    # legitimate bulk mail looks like (From=company.com, Reply-To on the
    # ESP's reply infra, Return-Path on the ESP's bounce infra) — three
    # distinct domains by design, not a triangulation attack.
    esp_involved = _is_esp_domain(reply_dom) or _is_esp_domain(return_dom)

    if len(distinct) < 3 or esp_involved:
        return RuleResult(
            score=0, verdict="neutral",
            details={
                "from_domain": from_dom,
                "reply_to_domain": reply_dom,
                "return_path_domain": return_dom,
                "distinct_count": len(distinct),
                "esp": esp_involved,
            },
            recommendation=None,
        )

    return RuleResult(
        score=CR.get_iris_scoring_weight("triangulation.fail", -10), verdict="fail",
        details={
            "from_domain": from_dom,
            "reply_to_domain": reply_dom,
            "return_path_domain": return_dom,
            "distinct_count": len(distinct),
        },
        recommendation=(
            f"Las tres cabeceras de identidad apuntan a tres dominios "
            f"organizativos distintos: From={from_dom}, Reply-To={reply_dom}, "
            f"Return-Path={return_dom}. En un correo legítimo estos dominios "
            "suelen coincidir o pertenecer a la misma organización (con "
            "subdominios del ESP como excepción). Esta triangulación es una "
            "firma estructural de phishing/BEC: el mensaje atraviesa o imita "
            "infraestructuras no relacionadas."
        ),
    )
