"""
Unicode Evasion rule (D4) - RLO/bidi control-character spoofing and
mixed-script (Cyrillic/Greek + Latin) confusable characters in the
Subject, From display name, sender domain, and attachment filenames.

Two independent evasion techniques share this module because they're both
"the visible text lies about what characters are actually there" and both
live in the same small set of fields:

- Bidi/override control characters (U+202E and friends) let an attacker
  make a filename *display* as ``invoice.pdf`` while the real extension is
  ``.exe`` (the classic right-to-left-override extension spoof:
  ``invoice[U+202E]fdp.exe`` renders as ``invoice`` + ``exe.pdf`` reversed).
- Mixed-script text (e.g. Cyrillic "a" U+0430 mixed with Latin "pple" to
  spell something that renders identically to "apple") is a well-known
  homograph attack vector, independent of any specific brand list -- it's
  a structural signal, not a lookup against known brands.

The Unicode codepoints/ranges here are spec constants, not tunable
configuration (see the transversal rules in ROADMAP.md), so they stay in
code rather than SecOpsConfig.json. Codepoints are written as explicit
``\\uXXXX`` escapes rather than literal glyphs -- these are invisible
formatting characters and embedding them verbatim in source is unsafe to
read/diff.
"""

from __future__ import annotations

import re

from ..registry import iris_rules, RuleResult
from ..shared import extract_display_name, extract_domain
from ..parsers import decode_mime_words

MAX_SCORE_FLOOR = -30

# Bidirectional format/override control characters. U+202E (RLO) is the
# one abused for filename spoofing; the rest are included because any of
# them appearing in a Subject/From/filename is equally suspicious --
# legitimate mail essentially never uses directional overrides. Built from
# ``chr(codepoint)`` rather than embedding the (invisible) glyphs directly
# in source, since those render as nothing and are unsafe to eyeball/diff.
_BIDI_CONTROLS = {
    chr(0x200E): "LRM", chr(0x200F): "RLM",
    chr(0x202A): "LRE", chr(0x202B): "RLE", chr(0x202C): "PDF",
    chr(0x202D): "LRO", chr(0x202E): "RLO",
    chr(0x2066): "LRI", chr(0x2067): "RLI", chr(0x2068): "FSI", chr(0x2069): "PDI",
}


def _find_bidi_controls(text: str) -> list[str]:
    return sorted({_BIDI_CONTROLS[ch] for ch in text if ch in _BIDI_CONTROLS})


# Script ranges used to detect mixed-script (homograph) text. Only the
# scripts most commonly abused for Latin lookalikes are checked -- CJK,
# Arabic, etc. mixed with Latin is usually just multilingual content, not
# a spoofing pattern, and would create noisy false positives.
_LATIN_RE = re.compile(r"[A-Za-zÀ-ÿ]")
_CYRILLIC_RE = re.compile(r"[Ѐ-ӿ]")
_GREEK_RE = re.compile(r"[Ͱ-Ͽ]")


def _mixed_script(text: str) -> str | None:
    """Return the confusable script name when *text* mixes Latin with it."""
    if not text or not _LATIN_RE.search(text):
        return None
    if _CYRILLIC_RE.search(text):
        return "cyrillic"
    if _GREEK_RE.search(text):
        return "greek"
    return None


@iris_rules.register(
    name="Unicode Evasion", category="content_analysis",
    description=(
        "Detecta caracteres de control bidireccional (RLO/LRO - spoofing de "
        "extension de archivo) y mezcla de scripts confusables (cirilico/"
        "griego con latino) en Subject, remitente, dominio y adjuntos."
    ),
    needs_context=True,
)
def check_unicode_evasion(context) -> RuleResult:
    headers = context.headers
    subject = decode_mime_words(headers.get("subject", ""))
    from_header = decode_mime_words(headers.get("from", ""))
    display_name = extract_display_name(from_header)
    domain = extract_domain(from_header) or ""

    findings: list[dict] = []
    score = 0

    for field_name, value in (("subject", subject), ("from", from_header)):
        controls = _find_bidi_controls(value)
        if controls:
            findings.append({"type": "bidi_control", "field": field_name, "controls": controls})
            score -= 15

    for att in context.attachments:
        filename = att.filename or ""
        controls = _find_bidi_controls(filename)
        if controls:
            findings.append({
                "type": "bidi_control", "field": "filename",
                "filename": filename, "controls": controls,
            })
            score -= 15

    for field_name, value in (("display_name", display_name), ("subject", subject)):
        script = _mixed_script(value)
        if script:
            findings.append({"type": "mixed_script", "field": field_name, "script": script, "value": value})
            score -= 10

    domain_script = _mixed_script(domain)
    if domain_script:
        findings.append({"type": "mixed_script", "field": "domain", "script": domain_script, "value": domain})
        score -= 12

    if not findings:
        return RuleResult(score=1, verdict="pass", details={})

    types = sorted({f["type"] for f in findings})
    return RuleResult(
        score=max(score, MAX_SCORE_FLOOR), verdict="fail",
        details={"findings": findings, "types": types},
        recommendation=(
            "Se detectaron caracteres Unicode sospechosos (controles de "
            "override direccional o mezcla de alfabetos) - tecnica usada para "
            "disfrazar la extension real de un archivo o falsificar visualmente "
            "un nombre de dominio/remitente. Verifica con atencion el nombre "
            "real del archivo o dominio antes de confiar en el."
        ),
    )
