"""
Encoded-Word Abuse rule (D5) — misuse of RFC 2047 "encoded-word" syntax
(``=?charset?encoding?text?=``) in Subject/From to evade naive keyword
scanners.

Legitimate international mail uses encoded-words to carry non-ASCII text
in a handful of large blocks (one per contiguous run of special
characters). This rule looks for three shapes that legitimate MTAs almost
never produce:

- **Chained atomization**: many small encoded-word blocks (each just a
  few decoded characters) instead of few long ones — a way to split a
  keyword across blocks so a scanner matching cleartext substrings never
  sees the whole word at once.
- **Exotic charsets** (UTF-7 and aliases): rarely used in modern mail
  (everything genuinely multilingual is UTF-8 today) and historically
  abused as a filter/XSS evasion vector.
- **Decoding reveals a URL**: the raw (undecoded) header has no visible
  "http" substring, but the decoded text does — the header only looks
  innocuous because a URL is hidden inside the encoding.
"""

from __future__ import annotations

import re

from ..registry import iris_rules, RuleResult
from ..shared import exotic_charsets
from ..parsers import decode_mime_words

MAX_SCORE_FLOOR = -30

# ``=?charset?B|Q?encoded-text?=`` per RFC 2047 §2.
_ENCODED_WORD_RE = re.compile(r"=\?([^?]+)\?([bBqQ])\?([^?]*)\?=")

_URL_RE = re.compile(r"https?://", re.IGNORECASE)

# Below this many blocks we don't even consider "chaining" — a couple of
# encoded-words for a genuinely long international subject is normal.
_MIN_BLOCKS_FOR_CHAINING = 4
# Average decoded length (in raw encoded characters, a rough but cheap
# proxy) below which many small blocks look like deliberate atomization
# rather than natural line-wrapping of one continuous phrase.
_CHAIN_AVG_LEN_THRESHOLD = 8


def _encoded_word_matches(header_value: str) -> list[re.Match]:
    return list(_ENCODED_WORD_RE.finditer(header_value or ""))


def _is_suspiciously_chained(matches: list[re.Match]) -> bool:
    if len(matches) < _MIN_BLOCKS_FOR_CHAINING:
        return False
    avg_len = sum(len(m.group(3)) for m in matches) / len(matches)
    return avg_len < _CHAIN_AVG_LEN_THRESHOLD


def _inspect_header(field_name: str, raw_value: str) -> list[dict]:
    matches = _encoded_word_matches(raw_value)
    if not matches:
        return []

    findings: list[dict] = []

    if _is_suspiciously_chained(matches):
        findings.append({
            "type": "chained_encoded_words", "field": field_name,
            "block_count": len(matches),
        })

    charsets_used = {m.group(1).lower() for m in matches}
    exotic = charsets_used & set(exotic_charsets())
    if exotic:
        findings.append({
            "type": "exotic_charset", "field": field_name,
            "charsets": sorted(exotic),
        })

    if len(charsets_used) > 1:
        findings.append({
            "type": "mixed_charsets", "field": field_name,
            "charsets": sorted(charsets_used),
        })

    decoded = decode_mime_words(raw_value)
    if not _URL_RE.search(raw_value) and _URL_RE.search(decoded):
        findings.append({
            "type": "decoded_reveals_url", "field": field_name,
            "decoded_preview": decoded[:200],
        })

    return findings


_FINDING_SCORES = {
    "chained_encoded_words": -8,
    "exotic_charset": -10,
    "mixed_charsets": -6,
    "decoded_reveals_url": -12,
}


@iris_rules.register(
    name="Encoded-Word Abuse", category="content_analysis",
    description=(
        "Detecta abuso de encoded-words RFC 2047 en Subject/From: bloques "
        "encadenados para evadir filtros de keywords, charsets exoticos "
        "(UTF-7), y URLs que solo aparecen tras decodificar."
    ),
)
def check_encoded_word_abuse(headers: dict) -> RuleResult:
    findings: list[dict] = []
    for field_name in ("subject", "from"):
        findings.extend(_inspect_header(field_name, headers.get(field_name, "")))

    if not findings:
        return RuleResult(score=1, verdict="pass", details={})

    score = sum(_FINDING_SCORES[f["type"]] for f in findings)
    types = sorted({f["type"] for f in findings})

    return RuleResult(
        score=max(score, MAX_SCORE_FLOOR), verdict="fail",
        details={"findings": findings, "types": types},
        recommendation=(
            "El correo usa codificacion RFC 2047 (encoded-words) de forma "
            "atipica en Subject/From -- bloques fragmentados, charsets "
            "raramente legitimos, o contenido que solo se revela al "
            "decodificar. Es una tecnica conocida para evadir filtros "
            "automaticos; revisa el contenido decodificado con atencion."
        ),
    )
