"""
Subdomain Impersonation rule — detects subdomain tricks where a brand
name is embedded as a subdomain of an attacker-controlled domain.

Examples:
    ``paypal.com.secure-login.tk`` — brand as third+ label
    ``secure-paypal.com``           — brand combined with action words
    ``paypal-login.xyz``            — brand + dash + action word
    ``account-microsoft-verify.com`` — multiple brand/action tokens

This is distinct from ``Lookalike Sender Domain``, which only inspects
the registrable label. Here we look at the *full* domain from the right
and flag any well-known brand name appearing in a non-registrable label.
"""

import re

from ..registry import iris_rules, RuleResult
from ..shared import (
    canonical_brands, extract_domain, multi_level_tlds, registrable_label,
    subdomain_action_words,
)


def _is_trusted_brand_domain(domain: str) -> bool:
    return registrable_label(domain) in canonical_brands()


@iris_rules.register(
    name="Subdomain Impersonation",
    category="header_analysis",
    description=(
        "Detecta trucos de subdominio donde un nombre de marca conocido aparece "
        "como subdominio o combinado con action-words en un dominio controlado "
        "por el atacante (paypal.com.secure-login.tk, secure-microsoft-verify.com)."
    ),
)
def check_subdomain_impersonation(headers: dict) -> RuleResult:
    domain = extract_domain(headers.get("from", ""))
    if not domain:
        return RuleResult(
            score=0, verdict="neutral",
            details={"from": headers.get("from", "")},
            recommendation=None,
        )

    if _is_trusted_brand_domain(domain):
        return RuleResult(score=1, verdict="pass", details={"domain": domain}, recommendation=None)

    if "xn--" in domain:
        return RuleResult(
            score=-10, verdict="fail",
            details={"domain": domain, "type": "punycode_in_subdomain"},
            recommendation=(
                f"El dominio {domain} usa codificación punycode. Combinado con la "
                "imposible coincidencia con un subdominio, es muy probable phishing."
            ),
        )

    brands = canonical_brands()
    action_words = subdomain_action_words()

    labels = domain.lower().split(".")
    reg_label = registrable_label(domain)
    if reg_label in brands:
        return RuleResult(score=0, verdict="neutral", details={"domain": domain}, recommendation=None)

    pre_labels = [l for l in labels[:-2] if l] if ".".join(labels[-2:]) in multi_level_tlds() \
        else [l for l in labels[:-1] if l]

    findings: list[dict] = []

    if len(labels) >= 3:
        for lbl in pre_labels:
            tokens = re.split(r"[^a-z0-9]+", lbl)
            for token in tokens:
                if not token:
                    continue
                if token in brands:
                    findings.append({"subdomain_label": lbl, "token": token, "type": "brand_in_subdomain"})

    all_left_labels = pre_labels + [reg_label]
    for lbl in all_left_labels:
        if "-" not in lbl:
            continue
        if lbl in brands:
            continue
        tokens = re.split(r"-+", lbl)
        brand_hits = [t for t in tokens if t in brands]
        action_hits = [t for t in tokens if t in action_words]
        if brand_hits and action_hits:
            if not any(f.get("label") == lbl and f.get("type") == "brand_action_combo" for f in findings):
                findings.append({
                    "label": lbl, "brand": brand_hits[0], "action": action_hits[0],
                    "type": "brand_action_combo",
                })

    if not findings:
        return RuleResult(score=0, verdict="neutral", details={"domain": domain}, recommendation=None)

    types = sorted({f["type"] for f in findings})
    score = -12 if any(f["type"] == "brand_in_subdomain" for f in findings) else -8

    return RuleResult(
        score=score, verdict="fail",
        details={"domain": domain, "registrable_label": reg_label, "findings": findings},
        recommendation=(
            f"El dominio {domain} usa un truco de subdominio para imitar a una "
            f"marca conocida ({', '.join(types)}). El dominio real del remitente "
            "NO pertenece a la marca; el atacante solo usa la marca como "
            "etiqueta para aparentar legitimidad."
        ),
    )
