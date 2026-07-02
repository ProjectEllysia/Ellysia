"""
SPF rule — validates Sender Policy Framework alignment.

Looks for Received-SPF and Authentication-Results headers to determine
whether the sending server is authorized by the domain owner.
"""

from ..registry import iris_rules, RuleResult


@iris_rules.register(name="SPF", category="authentication",
                     description="Verifica que el servidor remitente esté autorizado por el SPF del dominio")
def check_spf(headers: dict) -> RuleResult:
    """Evaluate the SPF result from ``Authentication-Results`` or ``Received-SPF`` headers.

    Returns:
        - ``pass`` (score +5) when SPF passes.  A passing result only proves
          the sending server is authorised — it is weak positive evidence,
          not proof of legitimacy, so the bonus is intentionally small.
        - ``fail``/``hardfail`` (score -20) when SPF clearly fails.
        - ``softfail``/``neutral`` (score -5) for non-strict results.
        - ``error`` (score -3) for DNS lookup errors.
        - ``missing`` (score -3) when no SPF information is present — absence
          of authentication is itself mildly suspicious.
    """
    auth_results = headers.get("authentication-results", "")
    received_spf = headers.get("received-spf", "")

    auth_lower = auth_results.lower()
    received_lower = received_spf.lower().split()[0] if received_spf.strip() else ""

    spf_status = ""

    if "spf=pass" in auth_lower:
        spf_status = "pass"
    elif "spf=fail" in auth_lower:
        spf_status = "fail"
    elif "spf=hardfail" in auth_lower:
        spf_status = "hardfail"
    elif "spf=softfail" in auth_lower:
        spf_status = "softfail"
    elif "spf=neutral" in auth_lower:
        spf_status = "neutral"
    elif "spf=permerror" in auth_lower:
        spf_status = "permerror"
    elif "spf=temperror" in auth_lower:
        spf_status = "temperror"
    elif received_lower in ("pass", "fail", "softfail", "neutral", "hardfail", "permerror", "temperror"):
        spf_status = received_lower

    if spf_status == "pass":
        return RuleResult(
            score=5, verdict="pass",
            details={"spf": "pass", "source": auth_results or received_spf},
            recommendation=None,
        )

    if spf_status in ("fail", "hardfail"):
        return RuleResult(
            score=-20, verdict="fail",
            details={"spf": spf_status, "source": auth_results or received_spf},
            recommendation="El servidor de envío no está autorizado por el registro SPF del dominio remitente. Esto es un fuerte indicador de suplantación (spoofing).",
        )

    if spf_status in ("softfail", "neutral"):
        return RuleResult(
            score=-5, verdict=spf_status,
            details={"spf": spf_status, "source": auth_results or received_spf},
            recommendation="El SPF no está configurado de forma estricta (softfail/neutral). El correo podría no ser legítimo.",
        )

    if spf_status in ("permerror", "temperror"):
        return RuleResult(
            score=-3, verdict="error",
            details={"spf": spf_status, "source": auth_results or received_spf},
            recommendation="Error al consultar el registro SPF del dominio (error temporal o permanente de DNS).",
        )

    # Absence of SPF data (common when headers are pasted/exported partially)
    # is not itself evidence of risk under the subtractive model — only an
    # actual SPF *fail* indicates spoofing. Stay neutral.
    return RuleResult(
        score=0, verdict="missing",
        details={"spf": "no SPF information found"},
        recommendation="No se encontraron cabeceras SPF. No se pudo verificar la autenticación del remitente.",
    )
