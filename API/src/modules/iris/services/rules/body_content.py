"""
Body content scanning rule (Fase 2).

Extends the subject/display-name keyword scan to the actual message
body, where most phishing pretexts (credential requests, payment
redirection, urgency) live. Also flags classic hidden-text evasion
(zero/near-zero font-size, display:none, opacity:0) used to dodge
plain-text keyword scanners while still rendering normally to victims.
"""

from __future__ import annotations

import re

from ..registry import iris_rules, RuleResult
from ..shared import credential_phrases, strip_html

_STYLE_BLOCK_RE = re.compile(r"<style\b[^>]*>.*?</style>", re.IGNORECASE | re.DOTALL)

# Tags whose opening attributes carry an inline hidden-text style, captured
# together with their content so we can judge *what* is being hidden.
_HIDDEN_TAG_RE = re.compile(
    r'<(?P<tag>\w+)\b(?P<attrs>[^>]*?style\s*=\s*"[^"]*'
    r"(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:px)?\b|opacity\s*:\s*0\b)"
    r'[^"]*"[^>]*)>(?P<inner>.*?)</\1>',
    re.IGNORECASE | re.DOTALL,
)

_HIDDEN_LINK_RE = re.compile(r"<a\b[^>]*\bhref\s*=", re.IGNORECASE)


def _strip_style_blocks(html: str) -> str:
    """Remove ``<style>...</style>`` blocks.

    Responsive HTML emails define show/hide breakpoints as plain CSS rules
    (``.mobile-hidden { display: none !important; }``). Those are stylesheet
    *definitions*, not evasive hidden text, and must not feed the hidden-text
    heuristic below — only inline ``style="..."`` on actual content should.
    """
    return _STYLE_BLOCK_RE.sub(" ", html)


def _has_evasive_hidden_text(body_html: str) -> bool:
    """Detect inline-hidden tags that hide *malicious* content.

    Hiding markup is not, by itself, a phishing signal — virtually every
    marketing email does it: the inbox preview/preheader snippet and its
    zero-width-space spacer are wrapped in ``display:none``, responsive
    layouts toggle ``display:none`` per breakpoint, and tracking pixels are
    sized to zero. Flagging any hidden text produced constant false
    positives on legitimate ESP mail.

    So we only treat hidden content as evasive when it hides something that
    matters: a **hyperlink** (a hidden link the victim can't see is a real
    cloaking technique) or a **credential/payment phrase** (keyword-stuffed
    or scanner-evading body text). Hidden prose, whitespace, ZWNJ padding or
    images alone are ignored.
    """
    for match in _HIDDEN_TAG_RE.finditer(body_html):
        inner = match.group("inner")
        if _HIDDEN_LINK_RE.search(inner):
            return True
        inner_text = strip_html(inner).lower()
        if any(phrase in inner_text for phrase in credential_phrases()):
            return True
    return False


@iris_rules.register(
    name="Body Content", category="content_analysis",
    description=(
        "Escanea el cuerpo del correo en busca de frases de phishing "
        "(credenciales/pago) y técnicas de texto oculto."
    ),
    needs_context=True,
)
def check_body_content(context) -> RuleResult:
    body_html = context.body_html or ""
    text = (context.body_text or "") + " " + strip_html(body_html)
    text_lower = text.lower()

    if not text_lower.strip():
        return RuleResult(score=0, verdict="neutral", details={"reason": "empty body"})

    found = [p for p in credential_phrases() if p in text_lower]
    hidden = _has_evasive_hidden_text(_strip_style_blocks(body_html))

    if not found and not hidden:
        return RuleResult(score=0, verdict="pass", details={})

    score = 0
    if found:
        score -= 5 * min(len(found), 3)
    if hidden:
        score -= 10

    return RuleResult(
        score=score, verdict="fail",
        details={"phrases_found": found, "hidden_text": hidden},
        recommendation=(
            "El cuerpo del correo contiene frases típicas de phishing"
            + (" y texto oculto." if hidden else ".")
        ),
    )
