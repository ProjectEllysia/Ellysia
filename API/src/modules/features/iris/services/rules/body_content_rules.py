"""
Message content rules — the text of the email itself (Subject, From
display name, and body) is scanned for the language, structure and
encoding patterns typical of phishing.

- **Alarming Keywords**: urgent/pressuring language in Subject/From.
- **Body Content**: credential/payment phrases in the body, plus evasive
  hidden-text techniques (zero font-size, display:none) that hide a link
  or phrase from the victim while dodging plain-text scanners.
- **BEC Wire Transfer Pattern**: the classic Business Email Compromise
  payload (wire transfer, gift cards, crypto, banking-detail change)
  weighted against sender-domain legitimacy.
- **Generic Greeting**: the mass-phishing combo of a generic greeting
  ("Dear customer") *and* a risky action verb ("verify", "confirm") —
  either alone is weak, the combination is the strong signal.
- **URL in Subject**: URLs embedded directly in the Subject line.
- **Unicode Evasion**: RLO/bidi control characters (filename/extension
  spoofing) and mixed-script (Cyrillic/Greek + Latin) confusable text.
- **Encoded-Word Abuse**: RFC 2047 encoded-word chaining, exotic
  charsets, or content that only reveals a URL once decoded — all ways
  to evade scanners that only match cleartext substrings.
"""

from __future__ import annotations

import re

import src.modules.system.config_reading as CR
from ..registry import iris_rules, RuleResult
from ..evidence import attachment_evidence, header_evidence, unique_evidence
from ..wordlists import alarming_emojis, exotic_charsets, phrase_matches, suspicious_tlds
from ..text import (
    extract_display_name, extract_domain, is_free_provider,
    registrable_domain, strip_html,
)
from ..parsers import decode_mime_words


def _score_by_weight(weight: int) -> tuple[float, str, str | None]:
    """Map a weighted keyword score to (score, severity, recommendation).

    ``weight`` counts each high-signal hit as 2 and each low-signal hit
    (and alarming emoji) as 1.
    """
    # Recalibración de pesos: la urgencia es lenguaje estándar en banca y
    # marketing legítimos; el tramo "low" era ruido puro (bajado a 0), y
    # "high"/"medium" bajan porque la detección real recae en el combo
    # `alarming_strong ∧ (auth_fail ∨ spoof)` → Phishing, no en este score.
    if weight >= 5:
        return (CR.get_iris_scoring_weight("alarming_keywords.high", -10), "high",
                "El asunto y/o nombre del remitente contiene múltiples palabras o frases "
                         "alarmantes que son características de campañas de phishing con alta urgencia.")
    if weight >= 3:
        return (CR.get_iris_scoring_weight("alarming_keywords.medium", -5), "medium",
                "Se detectaron varias palabras o frases alarmantes en el asunto o "
                         "nombre del remitente. Esto es común en correos de phishing que buscan "
                         "provocar una reacción impulsiva.")
    if weight >= 1:
        return (0, "low", "Se detectó lenguaje de urgencia en el asunto o nombre del remitente. "
                         "Podría ser legítimo (marketing), pero merece atención.")
    return (0, "pass", None)


@iris_rules.register(
    name="Alarming Keywords", evidence_headers=("subject", "from"), category="content_analysis", family="content",
    description="Detecta palabras y frases alarmantes en el asunto y nombre del remitente (inglés/español)",
)
def check_alarming_keywords(headers: dict) -> RuleResult:
    subject = decode_mime_words(headers.get("subject", ""))
    from_addr = decode_mime_words(headers.get("from", ""))
    display_name = extract_display_name(from_addr)

    combined = (subject + " " + display_name).lower()

    high_found = phrase_matches("high_signal_keywords", combined)
    low_found = phrase_matches("low_signal_keywords", combined)
    emoji_found = [repr(emoji) for emoji in alarming_emojis() if emoji in combined]

    weight = 2 * len(high_found) + len(low_found) + len(emoji_found)
    score, severity, recommendation = _score_by_weight(weight)

    found_keywords = high_found + low_found + emoji_found

    if severity == "pass":
        return RuleResult(
            score=1, verdict="pass",
            details={"subject": subject, "display_name": display_name, "alarming_keywords_found": []},
            recommendation=None,
        )

    return RuleResult(
        score=score, verdict=f"alarming_{severity}",
        details={
            "subject": subject,
            "display_name": display_name,
            "alarming_keywords_found": found_keywords,
            "high_signal": high_found,
            "low_signal": low_found,
            "weight": weight,
        },
        recommendation=recommendation,
    )


_STYLE_BLOCK_RE = re.compile(r"<style\b[^>]*>.*?</style>", re.IGNORECASE | re.DOTALL)

# Tags whose opening attributes carry an inline hidden-text style, captured
# together with their content so we can judge *what* is being hidden.
def _hidden_tag_re(style_alternation: str) -> re.Pattern:
    return re.compile(
        r'<(?P<tag>\w+)\b(?P<attrs>[^>]*?style\s*=\s*"[^"]*'
        rf"(?:{style_alternation})"
        r'[^"]*"[^>]*)>(?P<inner>.*?)</\1>',
        re.IGNORECASE | re.DOTALL,
    )


# Estilos que ocultan el elemento COMPLETO (texto, imágenes y enlaces).
_HIDDEN_TAG_RE = _hidden_tag_re(
    r"display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0\b"
)

# `font-size:0` solo oculta TEXTO: un enlace con una imagen dentro sigue
# perfectamente visible. Y es, además, el truco de maquetación estándar de
# MJML/Outlook — todo generador de correo HTML lo pone en los `<td>`/`<div>`
# contenedores para eliminar el espacio entre columnas inline-block, con el
# botón y su enlace visibles dentro. Tratarlo como "enlace oculto" marcaba
# como evasión cualquier newsletter maquetada. Se conserva solo para el caso
# que sí es evasión real: texto de credenciales/pago invisible al usuario
# (keyword stuffing / envenenamiento de scanners).
_ZERO_FONT_TAG_RE = _hidden_tag_re(r"font-size\s*:\s*0(?:px)?\b")

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

    Y el enlace solo cuenta bajo un estilo que oculte el elemento entero
    (``display:none``/``visibility:hidden``/``opacity:0``): ``font-size:0``
    es maquetación normal y no esconde el enlace (ver ``_ZERO_FONT_TAG_RE``),
    así que ahí solo pesa la frase de credenciales/pago.
    """
    for match in _HIDDEN_TAG_RE.finditer(body_html):
        inner = match.group("inner")
        if _HIDDEN_LINK_RE.search(inner):
            return True
        inner_text = strip_html(inner).lower()
        if phrase_matches("credential_phrases", inner_text):
            return True
    for match in _ZERO_FONT_TAG_RE.finditer(body_html):
        inner_text = strip_html(match.group("inner")).lower()
        if phrase_matches("credential_phrases", inner_text):
            return True
    return False


@iris_rules.register(
    name="Body Content", unanchorable_reason=(
        "La regla evalúa el cuerpo en conjunto y no registra la posición exacta de lo que encuentra, así que no hay un fragmento concreto que señalar."
    ), is_body_dependent=True, category="content_analysis", family="content",
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

    matched_phrases = phrase_matches("credential_phrases", text_lower)
    hidden = _has_evasive_hidden_text(_strip_style_blocks(body_html))

    if not matched_phrases and not hidden:
        return RuleResult(score=0, verdict="pass", details={})

    # Recalibración de pesos: "verifique su cuenta" es lenguaje de banca
    # legítima real, no solo de phishing -- se suaviza. El texto oculto SÍ
    # es evasión estructural deliberada (nadie esconde texto por accidente)
    # y se mantiene en -10; el gate body_content_fail también distingue los
    # dos casos (ver managers._extract_verdict_signals).
    score = 0
    if matched_phrases:
        score += CR.get_iris_scoring_weight("body_content.phrase_match", -3) * min(len(matched_phrases), 2)
    if hidden:
        score += CR.get_iris_scoring_weight("body_content.hidden_text", -10)

    # El mensaje describe solo lo que de verdad disparó -- antes afirmaba
    # "frases típicas de phishing" incluso en la rama donde solo se detectó
    # texto oculto (matched_phrases == [], hidden == True), contradiciendo el
    # propio `phrases_found` vacío que se muestra en el mismo resultado.
    clauses = []
    if matched_phrases:
        clauses.append("frases típicas de phishing")
    if hidden:
        clauses.append("texto oculto")

    return RuleResult(
        score=score, verdict="fail",
        details={"phrases_found": matched_phrases, "hidden_text": hidden},
        recommendation=f"El cuerpo del correo contiene {' y '.join(clauses)}.",
    )


@iris_rules.register(
    name="BEC Wire Transfer Pattern", unanchorable_reason=(
        "La regla evalúa el cuerpo en conjunto y no registra la posición exacta de lo que encuentra, así que no hay un fragmento concreto que señalar."
    ), is_body_dependent=True,
    category="content_analysis", family="content",
    description=(
        "Detecta el patrón típico de BEC (Business Email Compromise): "
        "remitente con dominio corporativo y cuerpo pidiendo wire transfer, "
        "cripto, tarjetas de regalo, o cambio de cuenta bancaria."
    ),
    needs_context=True,
)
def check_bec_wire_pattern(context) -> RuleResult:
    headers = context.headers
    body_html = context.body_html or ""
    body_text = context.body_text or ""
    text = (body_text + " " + strip_html(body_html)).lower()

    from_domain = registrable_domain(extract_domain(headers.get("from", "")))
    reply_domain = registrable_domain(extract_domain(headers.get("reply-to", "")))

    if not from_domain:
        return RuleResult(score=0, verdict="neutral", details={}, recommendation=None)

    matches = phrase_matches("bec_phrases", text)

    if not matches:
        return RuleResult(score=0, verdict="neutral",
                          details={"from_domain": from_domain, "matches": []}, recommendation=None)

    suspicious_redirect = (
        reply_domain and reply_domain != from_domain
    )

    # Recalibración de pesos: el peso ya no sostiene el veredicto -- BEC
    # desde webmail gratuito gatea vía `bec_free`→Phishing y BEC corporativo
    # con redirect gatea vía `bec_corporate_redirect`→Phishing (ambos en
    # managers._evaluate_gates); el score solo ordena severidad relativa.
    base = CR.get_iris_scoring_weight("bec_wire.base", -8)
    if len(matches) >= 2:
        base += CR.get_iris_scoring_weight("bec_wire.multi_match_bonus", -3)
    if suspicious_redirect:
        base += CR.get_iris_scoring_weight("bec_wire.redirect_bonus", -2)

    # B2: the rule's own recommendation used to assert "sender uses a
    # corporate domain" unconditionally — from_domain is just whatever's
    # parseable from From, gmail.com included. is_free_provider is already
    # what managers._extract_verdict_signals uses to derive bec_free from
    # this same rule's details; use it here too so the message told to the
    # analyst matches what the engine actually knows.
    is_corporate = not is_free_provider(from_domain)

    return RuleResult(
        score=base, verdict="fail",
        details={
            "from_domain": from_domain,
            "reply_domain": reply_domain,
            "matches": matches,
            "redirect_to_external_reply": suspicious_redirect,
            "is_corporate_domain": is_corporate,
        },
        recommendation=(
            f"El cuerpo contiene {len(matches)} frase(s) típica(s) de fraude BEC "
            f"({', '.join(matches[:3])}). El remitente "
            + (f"usa un dominio corporativo ({from_domain}), lo que hace este "
               "patrón especialmente peligroso: si el dominio es legítimo, la "
               "cuenta puede estar comprometida; si es suplantado, es un "
               "ataque dirigido. "
               if is_corporate else
               f"usa un proveedor de correo gratuito ({from_domain}), el patrón "
               "clásico de fraude del CEO/BEC desde una cuenta creada para la "
               "ocasión — no hay dominio corporativo que comprometer. ")
            + "Verifica "
            "por un canal alternativo (teléfono, en persona) ANTES de "
            "realizar cualquier pago o cambio de datos bancarios."
        ),
    )


@iris_rules.register(
    name="Generic Greeting", unanchorable_reason=(
        "La regla evalúa el cuerpo en conjunto y no registra la posición exacta de lo que encuentra, así que no hay un fragmento concreto que señalar."
    ), is_body_dependent=True,
    category="content_analysis", family="content",
    description=(
        "Detecta el patrón clásico de phishing masivo: saludo genérico "
        "('Dear customer') combinado con un verbo de acción sospechoso "
        "('verify', 'confirm', 'update') en el cuerpo del correo."
    ),
    needs_context=True,
)
def check_generic_greeting(context) -> RuleResult:
    body_html = context.body_html or ""
    body_text = context.body_text or ""
    text = (body_text + " " + strip_html(body_html)).lower()
    if not text.strip():
        return RuleResult(score=0, verdict="neutral", details={"reason": "empty body"})

    first_chunk = text[:600]

    greeting_hits = phrase_matches("generic_greetings", first_chunk)
    action_hits = phrase_matches("action_verbs", text)

    if not greeting_hits or not action_hits:
        return RuleResult(
            score=0, verdict="neutral",
            details={"greeting_hits": greeting_hits, "action_hits": action_hits},
            recommendation=None,
        )

    # Recalibración de pesos: el contaminante nº1 identificado por el
    # consejo -- "Estimado cliente/usuario" + un verbo de acción está en
    # casi todo correo transaccional/de cuenta legítimo (RRHH, banca,
    # e-commerce). Baja fuerte; sigue siendo señal, no ruido a 0, porque
    # corrobora otras familias.
    score = CR.get_iris_scoring_weight("generic_greeting.base", -3)
    if len(action_hits) >= 2:
        score += CR.get_iris_scoring_weight("generic_greeting.multi_action_bonus", -2)

    return RuleResult(
        score=score, verdict="fail",
        details={
            "greeting_hits": greeting_hits,
            "action_hits": action_hits,
        },
        recommendation=(
            "El correo usa un saludo genérico "
            f"('{greeting_hits[0]}') y un verbo de acción sospechoso "
            f"('{action_hits[0]}'). Esta combinación es típica del phishing "
            "masivo: los remitentes legítimos que tienen tu dirección suelen "
            "personalizar el saludo. Verifica la legitimidad antes de actuar."
        ),
    )


def _contains_url(text: str) -> list[str]:
    # The third pattern (bare domain + suspicious TLD, no scheme/www) is
    # built from the shared ``suspicious_tlds`` dataset rather than a
    # separately hardcoded list, so it can't drift out of sync with the
    # canonical TLD list used everywhere else (found duplicated verbatim
    # during this refactor -- Suspicious TLD's own list had since grown to
    # 37 entries while this one was stuck at 24).
    tld_alternation = "|".join(re.escape(tld.lstrip(".")) for tld in suspicious_tlds())
    patterns = [
        r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(?::\d+)?(?:/[\w\-./?%&+=~#!@]*)?",
        r"(?:www\.)[\w\-]+(?:\.[\w\-]+)+(?::\d+)?(?:/[\w\-./?%&+=~#!@]*)?",
        rf"[\w\-.]+\.(?:{tld_alternation})(?:/[\w\-./?%&+=~#!@]*)?",
    ]
    urls: list[str] = []
    for pattern in patterns:
        urls.extend(re.findall(pattern, text, re.IGNORECASE))
    return urls


@iris_rules.register(
    name="URL in Subject", evidence_headers=("subject",), category="content_analysis", family="content",
    description="Detecta si el asunto del correo contiene URLs (común en phishing)",
)
def check_url_in_subject(headers: dict) -> RuleResult:
    subject = decode_mime_words(headers.get("subject", ""))

    if not subject:
        return RuleResult(
            score=0, verdict="neutral",
            details={"subject": ""},
            recommendation=None,
        )

    urls_found = _contains_url(subject)

    if not urls_found:
        return RuleResult(
            score=1, verdict="pass",
            details={"subject": subject, "urls_found": []},
            recommendation=None,
        )

    count = len(urls_found)

    return RuleResult(
        score=CR.get_iris_scoring_weight("url_in_subject.per_url", -3) * min(count, 2),
        verdict="fail",
        details={
            "subject": subject,
            "urls_found": urls_found,
            "url_count": count,
        },
        recommendation=(
            "El asunto del correo contiene enlaces (URLs). "
            "Los correos legítimos rara vez incluyen URLs en el asunto; "
            "esta es una táctica común en phishing para atraer clics compulsivos. "
            "No hagas clic en enlaces del asunto sin verificar antes la legitimidad del correo."
        ),
    )


# recalibración de pesos -- gatea (unicode_evasion), floor menor
def _unicode_evasion_score_floor() -> float:
    return CR.get_iris_scoring_weight("unicode_evasion.floor", -20)

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
    return sorted({_BIDI_CONTROLS[character] for character in text if character in _BIDI_CONTROLS})


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
    name="Unicode Evasion", is_self_anchoring=True, is_body_dependent=True, category="content_analysis", family="content",
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
    anchored_evidence: list[dict] = []

    for field_name, value in (("subject", subject), ("from", from_header)):
        controls = _find_bidi_controls(value)
        if controls:
            findings.append({"type": "bidi_control", "field": field_name, "controls": controls})
            anchored_evidence.extend(header_evidence(headers, (field_name,)))
            score += CR.get_iris_scoring_weight("unicode_evasion.bidi_control", -15)

    for attachment_index, att in enumerate(context.attachments):
        filename = att.filename or ""
        controls = _find_bidi_controls(filename)
        if controls:
            findings.append({
                "type": "bidi_control", "field": "filename",
                "filename": filename, "controls": controls,
            })
            anchored_evidence.append(attachment_evidence(attachment_index, att))
            score += CR.get_iris_scoring_weight("unicode_evasion.bidi_control_filename", -15)

    for field_name, value in (("display_name", display_name), ("subject", subject)):
        script = _mixed_script(value)
        if script:
            findings.append({"type": "mixed_script", "field": field_name, "script": script, "value": value})
            header_name = "from" if field_name == "display_name" else field_name
            anchored_evidence.extend(header_evidence(headers, (header_name,)))
            score += CR.get_iris_scoring_weight("unicode_evasion.mixed_script", -10)

    domain_script = _mixed_script(domain)
    if domain_script:
        findings.append({"type": "mixed_script", "field": "domain", "script": domain_script, "value": domain})
        anchored_evidence.extend(header_evidence(headers, ("from",)))
        score += CR.get_iris_scoring_weight("unicode_evasion.mixed_script_domain", -12)

    if not findings:
        return RuleResult(score=1, verdict="pass", details={})

    types = sorted({finding["type"] for finding in findings})
    return RuleResult(
        score=max(score, _unicode_evasion_score_floor()), verdict="fail",
        details={"findings": findings, "types": types},
        evidence=unique_evidence(anchored_evidence),
        recommendation=(
            "Se detectaron caracteres Unicode sospechosos (controles de "
            "override direccional o mezcla de alfabetos) - tecnica usada para "
            "disfrazar la extension real de un archivo o falsificar visualmente "
            "un nombre de dominio/remitente. Verifica con atencion el nombre "
            "real del archivo o dominio antes de confiar en el."
        ),
    )


# recalibración de pesos -- ya promovida a gate (encoded_word_abuse), floor menor
def _encoded_word_score_floor() -> float:
    return CR.get_iris_scoring_weight("encoded_word_abuse.floor", -15)

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
    avg_len = sum(len(match.group(3)) for match in matches) / len(matches)
    return avg_len < _CHAIN_AVG_LEN_THRESHOLD


def _inspect_encoded_header(field_name: str, raw_value: str) -> list[dict]:
    matches = _encoded_word_matches(raw_value)
    if not matches:
        return []

    findings: list[dict] = []

    if _is_suspiciously_chained(matches):
        findings.append({
            "type": "chained_encoded_words", "field": field_name,
            "block_count": len(matches),
        })

    charsets_used = {match.group(1).lower() for match in matches}
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


def _encoded_word_finding_scores() -> dict[str, float]:
    return {
        "chained_encoded_words": CR.get_iris_scoring_weight("encoded_word_abuse.chained_encoded_words", -8),
        "exotic_charset": CR.get_iris_scoring_weight("encoded_word_abuse.exotic_charset", -10),
        "mixed_charsets": CR.get_iris_scoring_weight("encoded_word_abuse.mixed_charsets", -6),
        "decoded_reveals_url": CR.get_iris_scoring_weight("encoded_word_abuse.decoded_reveals_url", -12),
    }


@iris_rules.register(
    name="Encoded-Word Abuse", evidence_headers=("subject", "from"), category="content_analysis", family="content",
    description=(
        "Detecta abuso de encoded-words RFC 2047 en Subject/From: bloques "
        "encadenados para evadir filtros de keywords, charsets exoticos "
        "(UTF-7), y URLs que solo aparecen tras decodificar."
    ),
)
def check_encoded_word_abuse(headers: dict) -> RuleResult:
    findings: list[dict] = []
    for field_name in ("subject", "from"):
        findings.extend(_inspect_encoded_header(field_name, headers.get(field_name, "")))

    if not findings:
        return RuleResult(score=1, verdict="pass", details={})

    finding_scores = _encoded_word_finding_scores()
    score = sum(finding_scores[finding["type"]] for finding in findings)
    types = sorted({finding["type"] for finding in findings})

    return RuleResult(
        score=max(score, _encoded_word_score_floor()), verdict="fail",
        details={"findings": findings, "types": types},
        recommendation=(
            "El correo usa codificacion RFC 2047 (encoded-words) de forma "
            "atipica en Subject/From -- bloques fragmentados, charsets "
            "raramente legitimos, o contenido que solo se revela al "
            "decodificar. Es una tecnica conocida para evadir filtros "
            "automaticos; revisa el contenido decodificado con atencion."
        ),
    )


# Heurística laxa de teléfono: prefijo internacional opcional + grupos de
# dígitos separados por espacio/guion/paréntesis, con al menos 9 dígitos en
# total (filtra fechas y números de factura cortos, aplicado tras el match).
_PHONE_RE = re.compile(r"(?:\+\d{1,3}[\s.-]?)?\(?\d{2,4}\)?[\s.-]?\d{3,4}[\s.-]?\d{2,4}\b")


@iris_rules.register(
    name="TOAD Callback Pattern", unanchorable_reason=(
        "La regla evalúa el cuerpo en conjunto y no registra la posición exacta de lo que encuentra, así que no hay un fragmento concreto que señalar."
    ), is_body_dependent=True,
    category="content_analysis", family="content",
    description=(
        "Detecta el patron TOAD (Telephone-Oriented Attack Delivery): un "
        "numero de telefono combinado con lenguaje de pago/factura/"
        "suscripcion/soporte, sin enlaces, sin adjuntos y sin hilo de "
        "conversacion previo -- una clase de ataque invisible al resto de "
        "reglas porque nunca hay un enlace ni un adjunto que analizar."
    ),
    needs_context=True,
)
def check_toad_callback_pattern(context) -> RuleResult:
    headers = context.headers
    body_html = context.body_html or ""
    body_text = context.body_text or ""
    text = (body_text + " " + strip_html(body_html)).lower()

    if not text.strip():
        return RuleResult(score=0, verdict="neutral", details={"reason": "empty body"})

    has_thread = bool(headers.get("in-reply-to", "").strip()) or bool(headers.get("references", "").strip())
    if has_thread:
        return RuleResult(score=0, verdict="neutral", details={"reason": "has prior thread"})

    phones = [phone for phone in _PHONE_RE.findall(text) if sum(character.isdigit() for character in phone) >= 9]
    if not phones:
        return RuleResult(score=0, verdict="pass", details={"phones_found": 0})

    keyword_hits = phrase_matches("toad_phrases", text)
    if not keyword_hits:
        return RuleResult(score=0, verdict="pass", details={"phones_found": len(phones), "keywords_found": []})

    # El patron es especificamente para el caso SIN enlaces ni adjuntos --
    # si los hay, Body Links/Suspicious Attachments ya cubren el mensaje.
    if context.links or context.attachments:
        return RuleResult(
            score=0, verdict="pass",
            details={
                "phones_found": len(phones), "keywords_found": keyword_hits,
                "reason": "has links/attachments, other rules cover it",
            },
        )

    return RuleResult(
        score=CR.get_iris_scoring_weight("toad_callback.fail", -8), verdict="fail",
        details={"phones_found": phones[:3], "keywords_found": keyword_hits},
        recommendation=(
            "El correo combina un numero de telefono con lenguaje de pago, factura, "
            "suscripcion o soporte, sin enlaces, sin adjuntos y sin ser parte de una "
            "conversacion previa. Es el patron TOAD (Telephone-Oriented Attack "
            "Delivery): en vez de un enlace de phishing, el ataque continua por "
            "telefono. No llames al numero del correo; busca el telefono oficial "
            "por otro medio (la web oficial, el reverso de tu tarjeta, etc.)."
        ),
    )
