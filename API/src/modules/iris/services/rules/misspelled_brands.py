"""
Misspelled Brand Names rule — detects homoglyph attacks and common
typosquatting of well-known brands in the Subject and From display name.

Phishing campaigns use deceptive spellings (e.g., "Micr0soft", "PayPa1",
"Netfl1x") to bypass brand filters while visually mimicking legitimate
companies.
"""

import re

from ..registry import iris_rules, RuleResult
from ..shared import canonical_brands, extract_display_name, levenshtein, normalize_homoglyphs
from ..parsers import decode_mime_words


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


@iris_rules.register(name="Misspelled Brand Names", category="content_analysis",
                     description="Detecta homóglifos y errores tipográficos de marcas conocidas en el asunto y nombre del remitente")
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
