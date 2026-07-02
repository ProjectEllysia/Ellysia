"""
Return-Path mismatch rule — detects when the envelope sender domain
differs from the From header domain.

Phishing often uses a forged From address while the actual delivery
path reveals the true (malicious) origin in Return-Path.
"""

from ..registry import iris_rules, RuleResult
from ..shared import extract_domain


@iris_rules.register(name="Return-Path mismatch", category="header_analysis",
                     description="Detecta si el dominio en Return-Path difiere del remitente visible")
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

    rp_domain = extract_domain(return_path)
    from_domain = extract_domain(from_addr)

    if rp_domain and from_domain and rp_domain != from_domain:
        return RuleResult(
            score=-8, verdict="fail",
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
        details={"return_path_domain": rp_domain, "from_domain": from_domain, "match": True},
        recommendation=None,
    )
