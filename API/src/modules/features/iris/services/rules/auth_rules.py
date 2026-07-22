"""
Email authentication rules — SPF, DKIM, DMARC, Domain Alignment, and ARC.

The first four work together to answer "did this email really come from
who it claims to be?":

- **SPF** authenticates the envelope sender (``MAIL FROM``) — is the
  delivering server authorized by the domain owner?
- **DKIM** authenticates message integrity and the *signing* domain via a
  cryptographic signature.
- **DMARC** ties SPF/DKIM together by requiring the authenticated domain
  to *align* with the visible ``From`` domain, and layers a policy on top.
- **Domain Alignment** closes the gap DMARC leaves when DMARC itself is
  absent: SPF/DKIM can both report ``pass`` while authenticating a domain
  that has nothing to do with the visible ``From`` (e.g. DKIM-signed by
  ``d=sendgrid.net`` while ``From: ceo@victima.com``) — this rule
  reproduces DMARC-style alignment directly from the SPF/DKIM identities.

All four only read the receiving MTA's ``Authentication-Results`` (and,
for SPF/DKIM, their own headers) — none of them perform independent
DNS/cryptographic verification. See ROADMAP.md for the accepted scope
of this limitation.

- **ARC Chain** (Authenticated Received Chain, RFC 8617) is different in
  kind: it doesn't authenticate the sender itself, it lets a legitimate
  intermediary (mailing list, forwarder) preserve *evidence* of the
  original SPF/DKIM/DMARC results before its own relaying inevitably
  breaks them. ``managers._extract_verdict_signals`` uses its verdict to
  soften the SPF/DMARC/alignment gates for genuinely ARC-validated
  forwards (``cv=pass``) — see there for how the two interact.
"""

from __future__ import annotations

import re

from ..registry import iris_rules, RuleResult
from ..shared import extract_domain, registrable_domain


@iris_rules.register(
    name="SPF", category="authentication",
    description="Verifica que el servidor remitente esté autorizado por el SPF del dominio",
)
def check_spf(headers: dict) -> RuleResult:
    """Evaluate the SPF result from ``Authentication-Results`` or ``Received-SPF`` headers.

    Returns:
        - ``pass`` (score +5) when SPF passes. A passing result only proves
          the sending server is authorised — it is weak positive evidence,
          not proof of legitimacy, so the credit is intentionally small.
          NOTE (C1): under the subtractive model every rule's score is
          clamped to <= 0 when the analysis aggregates its total (see
          ``IrisManager._run_analysis``), so this +5 never actually raises
          the total — it exists only so a caller/test inspecting this
          rule's result *in isolation* can tell "passed cleanly" apart
          from "neutral, nothing to evaluate" (score 0 below).
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


@iris_rules.register(
    name="DKIM", category="authentication",
    description="Verifica la firma DKIM del correo",
)
def check_dkim(headers: dict) -> RuleResult:
    """Evaluate the DKIM result from ``Authentication-Results`` and check for a DKIM-Signature.

    Returns:
        - ``pass`` (score +5) when DKIM verifies (weak positive evidence).
        - ``fail`` (score -15) when the signature is invalid.
        - ``missing`` (score -3) when no DKIM-Signature header exists.
        - ``neutral`` (score 0) when a signature is present but the status is unknown.
    """
    auth_lower = headers.get("authentication-results", "").lower()
    dkim_header = headers.get("dkim-signature", "")

    if "dkim=pass" in auth_lower:
        return RuleResult(
            score=5, verdict="pass",
            details={"dkim": "pass", "source": headers.get("authentication-results", "")},
            recommendation=None,
        )

    if "dkim=fail" in auth_lower:
        return RuleResult(
            score=-15, verdict="fail",
            details={"dkim": "fail", "source": headers.get("authentication-results", "")},
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


@iris_rules.register(
    name="DMARC", category="authentication",
    description="Verifica la política DMARC del dominio remitente",
)
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


def _dkim_domain(headers: dict) -> str | None:
    """Extract the DKIM signing domain (``d=``) from the signature or auth header."""
    for source in (headers.get("dkim-signature", ""), headers.get("authentication-results", "")):
        match = re.search(r"\b(?:header\.)?d=([\w.-]+)", source)
        if match:
            return match.group(1).lower()
    return None


def _spf_mailfrom_domain(headers: dict) -> str | None:
    """Extract the SPF-authenticated envelope domain (``smtp.mailfrom``)."""
    auth = headers.get("authentication-results", "")
    match = re.search(r"smtp\.mailfrom=([^\s;]+)", auth)
    if not match:
        return None
    value = match.group(1)
    return value.split("@")[-1].lower() if "@" in value else value.lower()


@iris_rules.register(
    name="Domain Alignment", category="authentication",
    description="Comprueba que el dominio autenticado por SPF/DKIM coincide con el dominio del remitente (alineación DMARC)",
)
def check_domain_alignment(headers: dict) -> RuleResult:
    """Verify SPF/DKIM authenticated domains align with the From domain.

    Returns:
        - ``pass`` (score +3) when at least one passing mechanism aligns.
        - ``fail`` (score -15) when SPF/DKIM pass but none align with From.
        - ``neutral`` (score 0) when there is nothing to compare.
    """
    from_domain = registrable_domain(extract_domain(headers.get("from", "")))
    if not from_domain:
        return RuleResult(
            score=0, verdict="neutral",
            details={"reason": "no parseable From domain"},
            recommendation=None,
        )

    auth = headers.get("authentication-results", "").lower()

    # DMARC pass already proves alignment — nothing to add.
    if "dmarc=pass" in auth:
        return RuleResult(
            score=3, verdict="pass",
            details={"from_domain": from_domain, "reason": "dmarc=pass"},
            recommendation=None,
        )

    # DMARC fail already means "SPF/DKIM don't align with From" — that's
    # the exact fact this rule exists to reconstruct when DMARC is absent
    # (see module docstring). Evaluating alignment again here on top of a
    # dmarc=fail double-counts the same non-alignment as a second, separate
    # -15 penalty (F3): the realistic case is DKIM passing on the signing
    # infrastructure's own domain while DMARC fails precisely because that
    # domain isn't aligned with From, so this rule's own logic below would
    # otherwise flag it too. DMARC's own check_dmarc rule already scores
    # dmarc=fail; defer to it entirely.
    if "dmarc=fail" in auth:
        return RuleResult(
            score=0, verdict="neutral",
            details={"from_domain": from_domain, "reason": "dmarc=fail ya determinó la desalineación"},
            recommendation=None,
        )

    candidates: dict[str, str] = {}
    if "dkim=pass" in auth:
        d = _dkim_domain(headers)
        if d:
            candidates["dkim"] = d
    if "spf=pass" in auth:
        mf = _spf_mailfrom_domain(headers)
        if mf:
            candidates["spf"] = mf

    if not candidates:
        return RuleResult(
            score=0, verdict="neutral",
            details={"from_domain": from_domain, "reason": "no passing SPF/DKIM identity to compare"},
            recommendation=None,
        )

    aligned = {mech: dom for mech, dom in candidates.items()
               if registrable_domain(dom) == from_domain}

    if aligned:
        return RuleResult(
            score=3, verdict="pass",
            details={"from_domain": from_domain, "aligned": aligned},
            recommendation=None,
        )

    return RuleResult(
        score=-15, verdict="fail",
        details={
            "from_domain": from_domain,
            "authenticated_domains": candidates,
        },
        recommendation=(
            "SPF/DKIM autentican un dominio que NO coincide con el remitente visible "
            f"({from_domain}). La autenticación no garantiza que el correo provenga de "
            "quien dice ser: un atacante puede firmar con su propio dominio (o el de un "
            "proveedor de envío) mientras falsifica el campo 'De'. Trátalo como sospechoso."
        ),
    )


# ``cv=`` (chain validation) as declared in the newest ARC-Seal header.
# ``i=`` is the hop index but the flat ``headers`` dict (like every other
# rule here) only ever keeps one occurrence of a repeated header name — a
# second/third ARC hop is rare enough (most forwarded mail has exactly one
# ARC-sealing intermediary) that this stays a header-only rule rather than
# needing the full ``needs_context`` Received-style hop list.
_ARC_CV_RE = re.compile(r"\bcv=(\w+)", re.IGNORECASE)


@iris_rules.register(
    name="ARC Chain", category="authentication",
    description="Evalúa la validez declarada (cv=) de la cadena ARC (Authenticated Received Chain, RFC 8617)",
)
def check_arc_chain(headers: dict) -> RuleResult:
    """Evaluate the ``cv=`` (chain validation) status of an ARC seal.

    ARC lets a legitimate intermediary (mailing list, forwarding service)
    preserve the *original* SPF/DKIM/DMARC verdict before its own
    relaying inevitably breaks alignment. This rule only reports what the
    chain *declares* — it does not re-verify the ARC cryptographic
    signatures itself (same accepted limitation as SPF/DKIM/DMARC above).

    Returns:
        - ``pass`` (score +2) when ``cv=pass`` — a prior legitimate hop's
          authentication validated correctly; consumed by
          ``managers._extract_verdict_signals`` to soften the SPF/DMARC/
          alignment gates for genuine forwards.
        - ``fail`` (score -8) when ``cv=fail`` — the chain itself declares
          a previous hop's authentication broken.
        - ``missing`` (score 0) when no ARC headers are present at all
          (the overwhelming majority of mail — absence is not a signal).
        - ``neutral`` (score 0) for ``cv=none`` (the first hop in the
          chain — genuinely uninformative, not suspicious) or any other
          value.
    """
    arc_seal = headers.get("arc-seal", "")
    arc_msg_sig = headers.get("arc-message-signature", "")
    arc_auth_results = headers.get("arc-authentication-results", "")

    if not arc_seal and not arc_msg_sig and not arc_auth_results:
        return RuleResult(
            score=0, verdict="missing",
            details={"arc": "no ARC headers found"},
            recommendation=None,
        )

    match = _ARC_CV_RE.search(arc_seal) or _ARC_CV_RE.search(arc_auth_results)
    cv = match.group(1).lower() if match else None

    if cv == "pass":
        return RuleResult(
            score=2, verdict="pass",
            details={"cv": cv},
            recommendation=None,
        )

    if cv == "fail":
        return RuleResult(
            score=-8, verdict="fail",
            details={"cv": cv},
            recommendation=(
                "La cadena ARC (Authenticated Received Chain) declara que la "
                "autenticación de un salto anterior falló (cv=fail). Un intermediario "
                "legítimo (lista de correo, reenviador) certificó que el mensaje ya "
                "llegaba con problemas de autenticación antes de reenviarlo."
            ),
        )

    return RuleResult(
        score=0, verdict="neutral",
        details={"cv": cv or "unknown"},
        recommendation=None,
    )
