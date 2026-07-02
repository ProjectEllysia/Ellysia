"""
Display Name Spoofing rule — detects when the From display name mimics a
well-known brand but the actual email domain is not owned by that brand.

Phishing attacks commonly set a display name like "Microsoft Support" or
"PayPal Customer Service" while using a free email provider (gmail.com,
outlook.com) or an obviously unrelated domain.
"""

import re

from ..registry import iris_rules, RuleResult
from ..shared import brand_trusted_domains, extract_display_name, is_free_provider


def _extract_email(from_header: str) -> str:
    match = re.search(r"[\w.+-]+@[\w.-]+", from_header)
    return match.group(0) if match else ""


def _domain_matches_trusted(domain: str, trusted_domains: list[str]) -> bool:
    domain = domain.lower()
    for trusted in trusted_domains:
        if domain == trusted or domain.endswith("." + trusted):
            return True
    return False


@iris_rules.register(name="Display Name Spoofing", category="header_analysis",
                     description="Detecta si el nombre del remitente suplanta a una marca conocida pero el dominio del correo no pertenece a ella")
def check_display_name_spoof(headers: dict) -> RuleResult:
    from_addr = headers.get("from", "")
    display_name = extract_display_name(from_addr)
    email = _extract_email(from_addr)

    if not email:
        return RuleResult(
            score=0, verdict="neutral",
            details={"from": from_addr},
            recommendation=None,
        )

    if not display_name:
        return RuleResult(
            score=0, verdict="neutral",
            details={"from": from_addr, "email": email},
            recommendation=None,
        )

    domain = email.split("@")[-1].lower()
    display_lower = display_name.lower()
    display_words = set(re.findall(r"[\w']+", display_lower))

    matched_brands: list[str] = []
    brand_entries = brand_trusted_domains()

    for keywords, trusted_domains in brand_entries:
        for kw in keywords:
            if kw in display_lower:
                matched_brands.append(kw)
                break

    if not matched_brands:
        return RuleResult(
            score=2, verdict="pass",
            details={"from": from_addr, "email": email, "display_name": display_name},
            recommendation=None,
        )

    for keywords, trusted_domains in brand_entries:
        if any(kw in matched_brands for kw in keywords):
            if _domain_matches_trusted(domain, trusted_domains):
                return RuleResult(
                    score=5, verdict="pass",
                    details={
                        "from": from_addr, "email": email,
                        "display_name": display_name,
                        "found_brand": matched_brands,
                    },
                    recommendation=None,
                )
            break

    free_provider = is_free_provider(domain)

    if free_provider:
        score = -12
        recommendation = (
            f"El nombre del remitente contiene '{', '.join(matched_brands)}' pero el correo "
            f"proviene de un proveedor de correo gratuito ({domain}). "
            "Las marcas legítimas no envían correos desde direcciones de Gmail, Outlook, etc. "
            "Esto es un fuerte indicador de suplantación (phishing)."
        )
    else:
        score = -8
        recommendation = (
            f"El nombre del remitente contiene '{', '.join(matched_brands)}' pero el dominio "
            f"real del correo ({domain}) no pertenece a la marca. "
            "Verifica que esta diferencia sea intencionada antes de responder o hacer clic."
        )

    return RuleResult(
        score=score, verdict="spoof",
        details={
            "from": from_addr, "email": email,
            "display_name": display_name,
            "domain": domain,
            "matched_brands": matched_brands,
            "is_free_provider": free_provider,
        },
        recommendation=recommendation,
    )
