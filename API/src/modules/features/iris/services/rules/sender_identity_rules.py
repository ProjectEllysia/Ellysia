"""
Sender identity rules — is the visible ``From`` what it claims to be?

Covers the surface area an attacker controls directly (the header text
itself, not cryptographic authentication):

- **From header check**: is there even a well-formed sender address?
- **Display Name Spoofing**: display name claims a known brand, but the
  email domain doesn't belong to it.
- **Display Name Email Mismatch**: display name claims an organisation,
  but the address is a random/auto-generated local-part on an unrelated
  domain (BEC footprint).
- **Lookalike Sender Domain**: the *registrable* From domain itself is a
  typosquat/homoglyph/cousin/punycode imitation of a known brand.
- **Subdomain Impersonation**: a brand name is embedded as a *subdomain*
  label (or combined with action words) of an attacker-controlled domain.
- **Misspelled Brand Names**: homoglyph/typo brand names in Subject or
  display name (content-level, not domain-level).
- **Suspicious TLD**: sender/reply-to/return-path domains use TLDs
  disproportionately abused in phishing (.tk, .xyz, .top, ...).

These are deliberately layered rather than merged into one mega-check:
each inspects a different field/technique, so a message can trip several
independently and each contributes its own evidence to the report.
"""

from __future__ import annotations

import re

from ..registry import iris_rules, RuleResult
from ..shared import (
    brand_trusted_domains, canonical_brands, extract_display_name,
    extract_domain, is_free_provider, levenshtein, multi_level_tlds,
    normalize_homoglyphs, registrable_label, subdomain_action_words,
    suspicious_tlds,
)
from ..parsers import decode_mime_words


@iris_rules.register(
    name="From header check", category="header_analysis",
    description="Verifica que la cabecera From esté presente y no esté vacía",
)
def check_from_header(headers: dict) -> RuleResult:
    from_addr = headers.get("from", "")

    if not from_addr or "<>" in from_addr:
        return RuleResult(
            score=-10, verdict="fail",
            details={"from": from_addr or "missing"},
            recommendation="La cabecera From está vacía o es inválida. "
                           "Un correo legítimo siempre tiene un remitente identificable.",
        )

    return RuleResult(
        score=1, verdict="pass",
        details={"from": from_addr},
        recommendation=None,
    )


def _extract_email(from_header: str) -> str:
    match = re.search(r"[\w.+-]+@[\w.-]+", from_header)
    return match.group(0) if match else ""


def _domain_matches_trusted(domain: str, trusted_domains: tuple[str, ...]) -> bool:
    domain = domain.lower()
    for trusted in trusted_domains:
        if domain == trusted or domain.endswith("." + trusted):
            return True
    return False


@iris_rules.register(
    name="Display Name Spoofing", category="header_analysis",
    description="Detecta si el nombre del remitente suplanta a una marca conocida pero el dominio del correo no pertenece a ella",
)
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


# Local-parts that look hand-picked (alphabetical, role-based, simple).
_ROLE_LIKE = re.compile(r"^(support|info|admin|noreply|no-reply|contact|"
                        r"service|team|sales|billing|accounts|security|"
                        r"help|hello|office|mail|postmaster)$", re.IGNORECASE)


def _extract_email_lower(from_header: str) -> str:
    match = re.search(r"[\w.+-]+@[\w.-]+", from_header or "")
    return match.group(0).lower() if match else ""


def _is_random_local(local: str) -> bool:
    """Heuristic: a local-part is "random" if it is long, mixes digits and
    letters in non-word patterns, and is not a recognisable role address."""
    if not local:
        return False
    if _ROLE_LIKE.match(local):
        return False
    if len(local) < 8:
        return False
    has_digit = any(c.isdigit() for c in local)
    has_letter = any(c.isalpha() for c in local)
    has_dot_or_plus = "." in local or "+" in local
    if not (has_digit and has_letter):
        return False
    digit_ratio = sum(c.isdigit() for c in local) / len(local)
    if digit_ratio > 0.35 and has_dot_or_plus:
        return True
    if len(local) >= 12 and has_digit and has_letter and has_dot_or_plus:
        return True
    return False


@iris_rules.register(
    name="Display Name Email Mismatch",
    category="header_analysis",
    description=(
        "Detecta cuando el display name suplanta a una organización pero "
        "la dirección de email real es de otro dominio con local-part aleatorio "
        "(patrón típico de BEC / phishing masivo)."
    ),
)
def check_display_name_email_mismatch(headers: dict) -> RuleResult:
    from_header = headers.get("from", "")
    display_name = extract_display_name(from_header)
    email = _extract_email_lower(from_header)

    if not display_name or not email or "@" not in email:
        return RuleResult(
            score=0, verdict="neutral",
            details={"from": from_header},
            recommendation=None,
        )

    local, _, domain = email.partition("@")
    if not domain:
        return RuleResult(score=0, verdict="neutral", details={"from": from_header})

    if not _is_random_local(local):
        return RuleResult(score=0, verdict="neutral", details={"from": from_header}, recommendation=None)

    return RuleResult(
        score=-10, verdict="fail",
        details={
            "from": from_header,
            "display_name": display_name,
            "email": email,
            "domain": domain,
            "random_local": True,
        },
        recommendation=(
            f"El display name '{display_name}' sugiere una organización concreta, "
            f"pero la dirección real ({email}) usa un local-part aleatorio en un "
            f"dominio diferente ({domain}). Patrón típico de phishing/BEC: el "
            "atacante pone un nombre conocido y envía desde una cuenta recién "
            "creada. Verifica la legitimidad antes de responder."
        ),
    )


@iris_rules.register(
    name="Lookalike Sender Domain", category="header_analysis",
    description="Detecta si el dominio real del remitente imita a una marca conocida (typosquatting, homóglifos, cousin domain o punycode/IDN)",
)
def check_lookalike_domain(headers: dict) -> RuleResult:
    """Flag From domains that imitate a known brand.

    Returns:
        - ``fail`` (score -15) for homoglyph / typo / cousin / punycode imitations.
        - ``pass`` (score +1) for ordinary domains and legitimate brand domains.
        - ``neutral`` (score 0) when there is no parseable From domain.
    """
    domain = extract_domain(headers.get("from", ""))
    if not domain:
        return RuleResult(
            score=0, verdict="neutral",
            details={"from": headers.get("from", "")},
            recommendation=None,
        )

    # Punycode / IDN homograph — any xn-- label is inherently suspicious.
    if any(label.startswith("xn--") for label in domain.split(".")):
        return RuleResult(
            score=-15, verdict="fail",
            details={"domain": domain, "type": "punycode"},
            recommendation=(
                f"El dominio del remitente ({domain}) usa codificación punycode (IDN, 'xn--'). "
                "Es una técnica habitual para registrar dominios que parecen marcas conocidas "
                "usando caracteres Unicode visualmente idénticos. Trátalo como phishing."
            ),
        )

    label = registrable_label(domain)
    if not label:
        return RuleResult(score=1, verdict="pass", details={"domain": domain}, recommendation=None)

    brands = canonical_brands()

    # Exact legitimate brand domain (e.g. paypal.com, gmail.com) — never flag.
    if label in brands:
        return RuleResult(score=1, verdict="pass", details={"domain": domain}, recommendation=None)

    tokens = [t for t in re.split(r"[^a-z0-9]+", label) if len(t) >= 4]
    findings: list[dict] = []

    for token in tokens:
        if token in brands:
            # Brand name combined with extra words in the registered domain
            # (e.g. "paypal-security") — a cousin/combosquat domain.
            findings.append({"token": token, "brand": token, "type": "cousin"})
            continue
        normalized = normalize_homoglyphs(token)
        if normalized != token and normalized in brands:
            findings.append({"token": token, "brand": normalized, "type": "homoglyph"})
            continue
        for brand in brands:
            if len(brand) < 5 or abs(len(token) - len(brand)) > 1:
                continue
            if levenshtein(token, brand) == 1:
                findings.append({"token": token, "brand": brand, "type": "typo"})
                break

    if not findings:
        return RuleResult(score=1, verdict="pass", details={"domain": domain}, recommendation=None)

    matched_brand_names = ", ".join(sorted({f["brand"] for f in findings}))
    return RuleResult(
        score=-15, verdict="fail",
        details={"domain": domain, "registrable_label": label, "findings": findings},
        recommendation=(
            f"El dominio real del remitente ({domain}) imita a una marca conocida ({matched_brand_names}) "
            "mediante typosquatting, homóglifos o un 'cousin domain'. Aunque pase SPF/DKIM "
            "(el atacante controla su propio dominio), NO es el dominio legítimo de la marca."
        ),
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


def _find_typosquats(text: str) -> list[dict]:
    results: list[dict] = []
    words = set(re.findall(r"[a-zA-Z0-9@$€]{5,}", text.lower()))
    brands = canonical_brands()

    for word in words:
        # Exact match against a known brand — legitimate, skip
        if word in brands:
            continue

        # Check homoglyph-normalized match
        normalized = normalize_homoglyphs(word)
        if normalized != word and normalized in brands:
            results.append({
                "found": word,
                "normalized": normalized,
                "type": "homoglyph",
            })
            continue

        # Check for a genuine single-character typosquat. This branch is kept
        # deliberately strict — a loose Levenshtein threshold matches ordinary
        # words across languages (e.g. Spanish "aviso" is within 2 edits of
        # "visa", "marca" of "amex", etc.), which floods legitimate mail with
        # false positives. A real typosquat keeps the brand's first letter and
        # differs by exactly one edit, so we require all of:
        #   * brand length >= 5 (short brands like visa/ebay/amex/aws are
        #     indistinguishable from common words at edit distance 1),
        #   * same initial character,
        #   * length difference <= 1,
        #   * edit distance exactly 1.
        # Homoglyph substitution (paypa1, g00gle) is handled above and remains
        # the high-signal detector for the digit/symbol evasion technique.
        for brand in brands:
            if len(brand) < 5:
                continue
            if word[0] != brand[0]:
                continue
            if abs(len(word) - len(brand)) > 1:
                continue
            if levenshtein(word, brand) == 1:
                results.append({
                    "found": word,
                    "normalized": brand,
                    "type": "typo",
                })
                break

    return results


@iris_rules.register(
    name="Misspelled Brand Names", category="content_analysis",
    description="Detecta homóglifos y errores tipográficos de marcas conocidas en el asunto y nombre del remitente",
)
def check_misspelled_brands(headers: dict) -> RuleResult:
    subject = decode_mime_words(headers.get("subject", ""))
    from_addr = decode_mime_words(headers.get("from", ""))
    display_name = extract_display_name(from_addr)

    combined = subject + " " + display_name

    if not combined.strip():
        return RuleResult(
            score=0, verdict="neutral",
            details={"subject": subject, "display_name": display_name},
            recommendation=None,
        )

    found = _find_typosquats(combined)

    if not found:
        return RuleResult(
            score=0, verdict="pass",
            details={"subject": subject, "display_name": display_name},
            recommendation=None,
        )

    count = len(found)
    types = set(f["type"] for f in found)
    names = ", ".join(f["found"] for f in found)

    return RuleResult(
        score=-5 * min(count, 2),
        verdict="fail",
        details={
            "subject": subject,
            "display_name": display_name,
            "suspicious_words": found,
            "count": count,
        },
        recommendation=(
            f"Se detectaron palabras sospechosas que se asemejan a marcas conocidas: {names}. "
            f"El uso de homóglifos ({'sí' if 'homoglyph' in types else 'no'}) o errores "
            f"tipográficos ({'sí' if 'typo' in types else 'no'}) es común en ataques de "
            f"phishing para evadir filtros de seguridad. "
            "No confíes en la apariencia visual del nombre del remitente."
        ),
    )


@iris_rules.register(
    name="Suspicious TLD", category="header_analysis",
    description="Detecta si el dominio del remitente usa TLDs frecuentemente asociados con phishing",
)
def check_suspicious_tld(headers: dict) -> RuleResult:
    from_addr = headers.get("from", "")
    reply_to = headers.get("reply-to", "")
    return_path = headers.get("return-path", "") or headers.get("envelope-from", "") or ""

    emails_to_check = []
    if from_addr:
        emails_to_check.append(from_addr)
    if reply_to:
        emails_to_check.append(reply_to)
    if return_path:
        emails_to_check.append(return_path)

    found_tlds: list[dict] = []

    for raw in emails_to_check:
        match = re.search(r"[\w.+-]+@([\w.-]+)", raw)
        if not match:
            continue
        domain = match.group(1).lower()
        for tld in suspicious_tlds():
            if domain.endswith(tld):
                found_tlds.append({"domain": domain, "tld": tld, "header_source": raw})
                break

    if not found_tlds:
        return RuleResult(
            score=1, verdict="pass",
            details={"suspicious_tlds_found": []},
            recommendation=None,
        )

    # Dedupe by domain before scoring (B4): the same domain in From,
    # Reply-To *and* Return-Path is one suspicious fact, not three — the
    # loop above appends one entry per header it appears in, so a single
    # domain could otherwise cost -15 instead of -5.
    unique_domains = {d["domain"]: d for d in found_tlds}
    found_tlds = list(unique_domains.values())
    count = len(found_tlds)
    domains_str = ", ".join(d["domain"] for d in found_tlds)
    tlds_str = ", ".join(d["tld"] for d in found_tlds)

    return RuleResult(
        score=-5 * count,
        verdict="fail",
        details={
            "suspicious_tlds_found": found_tlds,
            "count": count,
        },
        recommendation=(
            f"Se detectaron dominios con TLDs sospechosos ({tlds_str}) en las cabeceras del correo: "
            f"{domains_str}. Estos TLDs son utilizados desproporcionadamente en campañas de phishing "
            f"debido a su bajo costo y falta de verificación."
        ),
    )
