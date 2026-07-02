"""
DMARC rule — validates Domain-based Message Authentication, Reporting & Conformance.

DMARC builds on SPF and DKIM to provide domain alignment policies.
"""

from ..registry import iris_rules, RuleResult


@iris_rules.register(name="DMARC", category="authentication",
                     description="Verifica la política DMARC del dominio remitente")
def check_dmarc(headers: dict) -> RuleResult:
    """Evaluate the DMARC result from the ``Authentication-Results`` header.

    DMARC ties SPF and DKIM together under a domain policy.

    Returns:
        - ``pass`` (score +5) when DMARC passes (weak positive evidence).
        - ``fail`` (score -20) when it fails (strong phishing indicator).
        - ``bestguess`` (score +3) for an approximate pass.
        - ``none`` (score -3) when the domain publishes ``p=none``.
        - ``policy`` (score +3) when ``reject`` or ``quarantine`` is advertised.
        - ``missing`` (score -3) when no DMARC data is found.
    """
    auth_results = headers.get("authentication-results", "")

    combined = auth_results.lower()

    if "dmarc=pass" in combined:
        return RuleResult(
            score=5, verdict="pass",
            details={"dmarc": "pass", "source": auth_results},
            recommendation=None,
        )

    if "dmarc=fail" in combined:
        return RuleResult(
            score=-20, verdict="fail",
            details={"dmarc": "fail", "source": auth_results},
            recommendation="DMARC ha fallado. Esto significa que ni SPF ni DKIM están alineados con el dominio 'De' (From). Fuerte indicador de phishing.",
        )

    if "dmarc=bestguesspass" in combined:
        return RuleResult(
            score=3, verdict="bestguess",
            details={"dmarc": "bestguesspass", "source": auth_results},
            recommendation="DMARC pasó por aproximación (best guess). No es concluyente pero es positivo.",
        )

    if "dmarc=none" in combined:
        return RuleResult(
            score=-3, verdict="none",
            details={"dmarc": "none", "source": auth_results},
            recommendation="La política DMARC del dominio remitente es 'none' (sin protección). El dominio puede ser suplantado sin consecuencias.",
        )

    if "dmarc=reject" in combined or "dmarc=quarantine" in combined:
        return RuleResult(
            score=3, verdict="policy",
            details={"dmarc": "policy present", "source": auth_results},
            recommendation=None,
        )

    # No DMARC line found — often just absent from a partial header paste.
    # Not a risk signal by itself under the subtractive model; only a
    # dmarc=fail / dmarc=none is. Stay neutral.
    return RuleResult(
        score=0, verdict="missing",
        details={"dmarc": "no DMARC information found"},
        recommendation="No se encontró información DMARC en las cabeceras proporcionadas.",
    )
