"""
Compromised Legitimate Domain rule — detects links to a *legitimate*
domain that hosts an open-redirector or a long opaque hash path typical
of phishing payloads.

Most phishing uses a lookalike domain that ``body_links`` already flags.
But a growing share of attacks compromise legitimate websites and abuse
their open redirects (``/redirect?url=evil.com``) or use opaque short
paths (``/AbCdEf12XyZ``) that resolve to credential-harvesting pages.

We can NOT know for sure whether a given path is malicious without
runtime analysis, but the *combination* of:
- trusted domain
- redirect-style query string, OR
- long opaque single-segment path, OR
- mismatch between the visible text domain and the actual host (handled
  by ``body_links`` already)

is enough to add a soft signal — the analyst can investigate further.
"""

from urllib.parse import urlparse, parse_qs

from ..registry import iris_rules, RuleResult
from ..shared import redirect_params, url_host


def _looks_opaque_path(path: str) -> bool:
    """Long single-segment alphanumeric path, no slashes/dots — typical
    of generated short-URLs used by phishing kits hosted on compromised sites."""
    if not path or "/" in path.lstrip("/"):
        return False
    cleaned = path.lstrip("/")
    if len(cleaned) < 12:
        return False
    if "." in cleaned:
        return False
    alnum_ratio = sum(c.isalnum() for c in cleaned) / len(cleaned)
    return alnum_ratio >= 0.95


@iris_rules.register(
    name="Compromised Legitimate Domain",
    category="content_analysis",
    description=(
        "Detecta enlaces a dominios legítimos que probablemente han sido "
        "comprometidos: open redirectors, paths opacos generados por kits "
        "de phishing, o combinaciones de ambos."
    ),
    needs_context=True,
)
def check_compromised_legitimate_domain(context) -> RuleResult:
    links = context.links or []
    if not links:
        return RuleResult(score=0, verdict="neutral", details={"link_count": 0})

    findings: list[dict] = []
    score = 0

    redirect_param_names = redirect_params()

    for link in links:
        href = link.href or ""
        host = url_host(href)
        if not host or not href.startswith(("http://", "https://")):
            continue

        try:
            parsed = urlparse(href)
        except ValueError:
            continue

        evidence: list[str] = []
        qs = parse_qs(parsed.query, keep_blank_values=True)
        for param, values in qs.items():
            if param.lower() in redirect_param_names and values:
                target = values[0]
                if target.startswith(("http://", "https://")):
                    target_host = url_host(target)
                    if target_host and target_host != host:
                        evidence.append(f"redirect_param:{param}=>{target_host}")

        if _looks_opaque_path(parsed.path):
            evidence.append(f"opaque_path:{parsed.path}")

        if evidence:
            findings.append({
                "href": href,
                "host": host,
                "evidence": evidence,
            })
            score -= 6 if len(evidence) == 1 else 9

    if not findings:
        return RuleResult(score=0, verdict="pass", details={"link_count": len(links)})

    return RuleResult(
        score=score, verdict="fail",
        details={"link_count": len(links), "findings": findings},
        recommendation=(
            "Se detectaron enlaces a dominios aparentemente legítimos con "
            "patrones típicos de sitios comprometidos (open redirectors o "
            "paths opacos generados por kits). Verifica el destino real antes "
            "de hacer clic: el dominio puede haber sido hackeado o abusado."
        ),
    )
