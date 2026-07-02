"""
DKIM rule — validates DomainKeys Identified Mail signature.

Checks Authentication-Results for the DKIM status and verifies the
DKIM-Signature header exists.
"""

from ..registry import iris_rules, RuleResult


@iris_rules.register(name="DKIM", category="authentication",
                     description="Verifica la firma DKIM del correo")
def check_dkim(headers: dict) -> RuleResult:
    """Evaluate the DKIM result from ``Authentication-Results`` and check for a DKIM-Signature.

    Returns:
        - ``pass`` (score +5) when DKIM verifies (weak positive evidence).
        - ``fail`` (score -15) when the signature is invalid.
        - ``missing`` (score -3) when no DKIM-Signature header exists.
        - ``neutral`` (score 0) when a signature is present but the status is unknown.
    """
    auth_results = headers.get("authentication-results", "")
    dkim_header = headers.get("dkim-signature", "")

    combined = (auth_results + " " + dkim_header).lower()

    if "dkim=pass" in combined:
        return RuleResult(
            score=5, verdict="pass",
            details={"dkim": "pass", "source": auth_results},
            recommendation=None,
        )

    if "dkim=fail" in combined:
        return RuleResult(
            score=-15, verdict="fail",
            details={"dkim": "fail", "source": auth_results},
            recommendation="La firma DKIM no es válida. El mensaje pudo haber sido alterado después de su envío original.",
        )

    if not dkim_header:
        # A missing DKIM signature (or auth header not captured in the paste)
        # is not evidence of risk on its own — only a DKIM *fail* is. Neutral.
        return RuleResult(
            score=0, verdict="missing",
            details={"dkim": "no DKIM-Signature header"},
            recommendation="El correo no incluye firma DKIM. No se pudo verificar la integridad del mensaje.",
        )

    return RuleResult(
        score=0, verdict="neutral",
        details={"dkim": "DKIM present but status unknown"},
        recommendation=None,
    )
