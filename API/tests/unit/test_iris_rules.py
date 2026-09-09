"""Tests unitarios de reglas de detección de phishing (Iris).

Las reglas son funciones puras: reciben un dict de cabeceras y devuelven
un ``RuleResult`` con score/verdict. No requieren BD ni red.
"""

import base64

import pytest

from src.modules.features.iris.services.rules.auth_rules import (
    check_spf, check_dkim, check_dmarc, check_domain_alignment, check_arc_chain,
)
from src.modules.features.iris.services.rules.sender_identity_rules import check_suspicious_tld
from src.modules.features.iris.services.rules.body_content_rules import check_url_in_subject
from src.modules.features.iris.services.rules.sender_identity_rules import check_lookalike_domain
from src.modules.features.iris.services.rules.reply_path_rules import check_reply_to_free_provider
from src.modules.features.iris.services.rules.reply_path_rules import check_reply_to
from src.modules.features.iris.services.rules.thread_rules import check_msgid_domain
from src.modules.features.iris.services.rules.content_trust_rules import check_list_unsubscribe
from src.modules.features.iris.services.rules.body_content_rules import check_alarming_keywords
from src.modules.features.iris.services.rules.sender_identity_rules import check_misspelled_brands
from src.modules.features.iris.services.registry import RuleResult
from src.modules.features.iris.managers import IrisManager

pytestmark = pytest.mark.unit


# --------------------------------------------------------------------------- SPF

def test_spf_pass_is_positive():
    result = check_spf({"authentication-results": "mx.google.com; spf=pass smtp.mailfrom=a@b.com"})
    assert result.verdict == "pass"
    assert result.score > 0


def test_spf_fail_is_strongly_negative():
    # Recalibración de pesos: subordinado a DMARC (que ya integra SPF+DKIM,
    # RFC 7489) -- el peso bajó, la detección real la sostiene el gate
    # spf_fail→Suspicious, no el score en solitario.
    result = check_spf({"authentication-results": "spf=fail smtp.mailfrom=evil@b.com"})
    assert result.verdict == "fail"
    assert result.score <= -8


def test_spf_softfail_is_mildly_negative():
    result = check_spf({"authentication-results": "spf=softfail"})
    assert result.verdict == "softfail"
    assert -10 < result.score < 0


def test_spf_missing_is_neutral():
    # Under the subtractive model, *absence* of SPF data (e.g. a partial
    # header paste) is not evidence of risk — only an SPF fail is. Neutral.
    result = check_spf({})
    assert result.verdict == "missing"
    assert result.score == 0


def test_spf_pass_bonus_is_small():
    # The authentication bonus must not dominate the score (no +45 buffer).
    result = check_spf({"authentication-results": "spf=pass smtp.mailfrom=a@b.com"})
    assert 0 < result.score <= 5


def test_spf_reads_received_spf_header():
    result = check_spf({"received-spf": "pass (google.com: domain of a@b.com)"})
    assert result.verdict == "pass"


# -------------------------------------------------------------------------- DKIM
# (previously untested at the unit level -- gap found while regrouping
# rules into auth_rules.py)

def test_dkim_pass_is_positive():
    result = check_dkim({"authentication-results": "mx; dkim=pass header.d=example.com"})
    assert result.verdict == "pass"
    assert 0 < result.score <= 5


def test_dkim_fail_is_strongly_negative():
    # Recalibración de pesos: subordinado a DMARC, ver test_spf_fail arriba.
    result = check_dkim({"authentication-results": "mx; dkim=fail header.d=example.com"})
    assert result.verdict == "fail"
    assert result.score <= -8


def test_dkim_missing_signature_is_neutral():
    result = check_dkim({})
    assert result.verdict == "missing"
    assert result.score == 0


def test_dkim_present_but_status_unknown_is_neutral():
    result = check_dkim({"dkim-signature": "v=1; a=rsa-sha256; d=example.com; s=s1"})
    assert result.verdict == "neutral"
    assert result.score == 0


# ------------------------------------------------------------------------- DMARC
# (previously untested at the unit level -- same gap as DKIM above)

def test_dmarc_pass_is_positive():
    result = check_dmarc({"authentication-results": "mx; dmarc=pass"})
    assert result.verdict == "pass"
    assert 0 < result.score <= 5


def test_dmarc_fail_is_strongly_negative():
    # Recalibración de pesos: DMARC sigue siendo el ancla del cluster auth
    # (el peso más alto de los cuatro), pero bajo el techo de familia -25.
    result = check_dmarc({"authentication-results": "mx; dmarc=fail"})
    assert result.verdict == "fail"
    assert result.score <= -15


def test_dmarc_none_policy_is_mildly_negative():
    result = check_dmarc({"authentication-results": "mx; dmarc=none"})
    assert result.verdict == "none"
    assert -5 < result.score < 0


def test_dmarc_missing_is_neutral():
    result = check_dmarc({})
    assert result.verdict == "missing"
    assert result.score == 0


# -------------------------------------------------------------------- ARC (D7)

class _ArcContext:
    """Contexto mínimo para ``check_arc_chain``.

    B06 pasó la regla a ``needs_context=True``: ya no le basta con las
    cabeceras, necesita la cadena Received para saber si quien dice haber
    validado la cadena ARC está por encima de la frontera de confianza.
    """

    def __init__(self, headers, received_headers=()):
        self.headers = headers
        self.received_headers = list(received_headers)


def test_arc_missing_is_neutral_missing_verdict():
    result = check_arc_chain(_ArcContext({}))
    assert result.verdict == "missing"
    assert result.score == 0


def test_arc_cv_pass_is_positive():
    result = check_arc_chain(_ArcContext(
        {"arc-seal": "i=1; a=rsa-sha256; cv=pass; d=example.com; s=s1; b=xyz"}))
    assert result.verdict == "pass"
    assert result.score > 0


def test_arc_cv_pass_alone_is_not_verified():
    """B06: `cv=pass` es lo que el mensaje dice de sí mismo.

    Iris no verifica firmas criptográficas, así que esa declaración no puede
    valer como prueba — cualquiera puede escribirla. La regla sigue
    reportándola, pero marcada como no verificada.
    """
    result = check_arc_chain(_ArcContext(
        {"arc-seal": "i=1; a=rsa-sha256; cv=pass; d=reenviador.example; s=s1; b=xyz"}))
    assert result.verdict == "pass"
    assert result.details["verified"] is False
    assert result.recommendation  # y se le explica al usuario por qué


def test_arc_cv_pass_is_verified_when_a_trusted_hop_confirms_it():
    """Quien sí valida la cadena es el MTA receptor, que lo apunta como
    `arc=pass` en su propio Authentication-Results."""
    result = check_arc_chain(_ArcContext(
        headers={
            "arc-seal": "i=1; a=rsa-sha256; cv=pass; d=reenviador.example; s=s1; b=xyz",
            "authentication-results": "mx.destino.example; arc=pass; spf=fail; dmarc=fail",
        },
        received_headers=["from relay.example by mx.destino.example; Mon, 1 Jan 2026 10:00:00 +0000"],
    ))
    assert result.verdict == "pass"
    assert result.details["verified"] is True
    assert result.recommendation is None


def test_arc_confirmation_from_an_untrusted_hop_does_not_count():
    """Un `arc=pass` firmado por un servidor que solo aparece por debajo de la
    frontera lo pudo escribir el propio remitente: no verifica nada."""
    result = check_arc_chain(_ArcContext(
        headers={
            "arc-seal": "i=1; a=rsa-sha256; cv=pass; d=malo.example; s=s1; b=xyz",
            "authentication-results": "mx.malo.example; arc=pass; spf=pass; dmarc=pass",
        },
        received_headers=[
            "from relay.example by mx.destino.example; Mon, 1 Jan 2026 10:00:00 +0000",
            "from origen.example by mx.malo.example; Mon, 1 Jan 2026 09:59:00 +0000",
        ],
    ))
    assert result.details["verified"] is False


def test_arc_cv_fail_is_negative():
    result = check_arc_chain(_ArcContext(
        {"arc-seal": "i=1; a=rsa-sha256; cv=fail; d=example.com; s=s1; b=xyz"}))
    assert result.verdict == "fail"
    assert result.score < 0


def test_arc_cv_none_is_neutral_first_hop():
    # cv=none just means "I'm the first ARC seal in the chain" -- not suspicious.
    result = check_arc_chain(_ArcContext(
        {"arc-seal": "i=1; a=rsa-sha256; cv=none; d=example.com; s=s1; b=xyz"}))
    assert result.verdict == "neutral"
    assert result.score == 0


# ------------------------------------------------------------------ Suspicious TLD

def test_suspicious_tld_flags_freenom_domain():
    result = check_suspicious_tld({"from": "Support <help@paypa1.tk>"})
    assert result.verdict == "fail"
    assert result.score < 0
    assert result.details["count"] >= 1


def test_legitimate_tld_passes():
    result = check_suspicious_tld({"from": "billing@example.com"})
    assert result.verdict == "pass"
    assert result.score >= 0


def test_suspicious_tld_score_scales_with_count():
    one = check_suspicious_tld({"from": "a@evil.tk"})
    two = check_suspicious_tld({"from": "a@evil.tk", "reply-to": "b@bad.xyz"})
    assert two.score < one.score


# ------------------------------------------------------------------ URL in subject

def test_url_in_subject_is_flagged():
    result = check_url_in_subject({"subject": "Verify now at http://evil.example.com/login"})
    assert result.verdict == "fail"
    assert result.score < 0


def test_clean_subject_passes():
    result = check_url_in_subject({"subject": "Tu factura de mayo"})
    assert result.verdict == "pass"
    assert result.score >= 0


def test_empty_subject_is_neutral():
    result = check_url_in_subject({"subject": ""})
    assert result.verdict == "neutral"
    assert result.score == 0


# ----------------------------------------------------------------- Domain alignment

def test_domain_alignment_flags_misaligned_dkim():
    # DKIM passes but signs a third-party domain, not the visible From.
    # Recalibración de pesos: -15→-12, dentro del techo de familia auth.
    result = check_domain_alignment({
        "from": "CEO <ceo@victima.com>",
        "authentication-results": "mx; dkim=pass header.d=sendgrid.net",
        "dkim-signature": "v=1; a=rsa-sha256; d=sendgrid.net; s=s1",
    })
    assert result.verdict == "fail"
    assert result.score <= -12


def test_domain_alignment_passes_when_aligned():
    result = check_domain_alignment({
        "from": "Billing <billing@paypal.com>",
        "authentication-results": "mx; dkim=pass header.d=paypal.com",
        "dkim-signature": "v=1; d=mail.paypal.com; s=s1",
    })
    assert result.verdict == "pass"
    assert result.score > 0


def test_domain_alignment_dmarc_pass_is_aligned():
    result = check_domain_alignment({
        "from": "a@example.com",
        "authentication-results": "mx; dmarc=pass",
    })
    assert result.verdict == "pass"


# ----------------------------------------------------------------- Lookalike domain

def test_lookalike_homoglyph_domain_is_flagged():
    result = check_lookalike_domain({"from": "Support <help@paypa1.com>"})
    assert result.verdict == "fail"
    assert result.score <= -15


def test_lookalike_cousin_domain_is_flagged():
    result = check_lookalike_domain({"from": "Security <no-reply@paypal-security.com>"})
    assert result.verdict == "fail"


def test_lookalike_punycode_domain_is_flagged():
    result = check_lookalike_domain({"from": "a@xn--pypal-4ve.com"})
    assert result.verdict == "fail"
    assert result.details["type"] == "punycode"


def test_lookalike_legitimate_brand_domain_passes():
    result = check_lookalike_domain({"from": "billing@paypal.com"})
    assert result.verdict == "pass"


def test_lookalike_ordinary_domain_passes():
    result = check_lookalike_domain({"from": "jane@some-small-business.com"})
    assert result.verdict == "pass"


def test_lookalike_typo_requires_keyboard_adjacent_substitution():
    # Calibración FP: "email" está a distancia de edición 1 de "gmail" (e->g)
    # por pura coincidencia de diccionario -- 'e' y 'g' ni siquiera son
    # vecinas en un teclado QWERTY, así que nadie la teclea por error. Una
    # sustitución de un solo carácter solo cuenta como typo plausible cuando
    # las dos teclas SÍ son vecinas (ver shared.is_plausible_typo).
    result = check_lookalike_domain({"from": "MANGO <news@email.mango>"})
    assert result.verdict == "pass"


def test_lookalike_typo_still_flags_keyboard_adjacent_substitution():
    # Control negativo: "gnail" (m->n, vecinas en QWERTY) debe seguir
    # detectándose -- la calibración no debe debilitar el typo real.
    result = check_lookalike_domain({"from": "a@gnail.com"})
    assert result.verdict == "fail"
    assert result.details["findings"][0]["type"] == "typo"


# ------------------------------------------------------- Reply-To free provider (BEC)

def test_reply_to_free_provider_flags_bec_pattern():
    result = check_reply_to_free_provider({
        "from": "CEO <ceo@company.com>",
        "reply-to": "ceo.private@gmail.com",
    })
    assert result.verdict == "fail"
    assert result.score < 0


def test_reply_to_free_provider_ignores_free_sender():
    result = check_reply_to_free_provider({
        "from": "jane@gmail.com",
        "reply-to": "jane.alt@gmail.com",
    })
    assert result.verdict == "pass"


# --------------------------------------------------------------------- Reply-To check

def test_reply_to_check_flags_unrelated_domain():
    result = check_reply_to({
        "from": "Attacker <ceo@company.com>",
        "reply-to": "attacker@evil-domain.com",
    })
    assert result.verdict == "fail"
    assert result.score < 0


def test_reply_to_check_allows_same_organisation_subdomain():
    # ESP/bulk-mail pattern: From and Reply-To use different subdomains of
    # the same organisational domain (e.g. UNIR newsletters via SendGrid-style
    # infra) — this is legitimate and must not be flagged.
    result = check_reply_to({
        "from": "UNIR <unir@comunicaciones.unir.net>",
        "reply-to": "reply-ABC123.510008@info.unir.net",
    })
    assert result.verdict == "pass"
    assert result.score >= 0


# ----------------------------------------------------------------- Message-ID domain

def test_msgid_domain_mismatch_is_flagged():
    result = check_msgid_domain({
        "from": "a@company.com",
        "message-id": "<abc123@unrelated-server.ru>",
    })
    assert result.verdict == "fail"


def test_msgid_domain_match_passes():
    result = check_msgid_domain({
        "from": "a@company.com",
        "message-id": "<abc123@mail.company.com>",
    })
    assert result.verdict == "pass"


def test_msgid_domain_known_esp_not_penalised():
    # Legit ESP (Amazon SES) stamps its own Message-ID domain — not spoofing.
    result = check_msgid_domain({
        "from": "duolingo <hello@duolingo.com>",
        "message-id": "<0100019f@email.amazonses.com>",
    })
    assert result.verdict == "pass"
    assert result.score == 0


# ------------------------------------------------------------- Misspelled brands

def test_misspelled_brand_homoglyph_is_flagged():
    # Real evasion technique: digit/symbol substitution.
    result = check_misspelled_brands({"subject": "Your PayPa1 account", "from": "x@y.com"})
    assert result.verdict == "fail"


def test_misspelled_brand_ignores_common_word_aviso():
    # "Aviso" (Spanish for "notice") must NOT be flagged as a typo of "visa".
    result = check_misspelled_brands({
        "subject": "Aviso: Nueva calificación publicada en el TFG",
        "from": '"Campus Virtual UNIR" <notificaciones@unir.net>',
    })
    assert result.verdict == "pass"
    assert result.score == 0


# ----------------------------------------------------------------- List-Unsubscribe

def test_list_unsubscribe_is_legitimacy_signal():
    result = check_list_unsubscribe({"list-unsubscribe": "<https://x.com/u>, <mailto:u@x.com>"})
    assert result.verdict == "pass"
    assert result.score > 0


def test_missing_list_unsubscribe_is_neutral():
    result = check_list_unsubscribe({})
    assert result.score == 0


# ------------------------------------------------- RFC 2047 encoded-subject bypass (B5)

def test_encoded_subject_does_not_bypass_keyword_scan():
    # "Account Suspended - Verify Now" Base64-encoded as an RFC 2047 word.
    raw = "Account Suspended - Verify Now"
    encoded = "=?UTF-8?B?" + base64.b64encode(raw.encode()).decode() + "?="
    result = check_alarming_keywords({"subject": encoded, "from": "x@y.com"})
    assert result.score < 0
    assert result.verdict.startswith("alarming_")


# ----------------------------------------------------------------- Verdict gating (B3)

def _rr(verdict, **details):
    return RuleResult(score=0, verdict=verdict, details=details)


def _gated(base_verdict, named):
    """Final verdict of the gates (ignores the reasons list)."""
    verdict, _ = IrisManager._apply_verdict_gates(base_verdict, named)
    return verdict


def test_gating_forces_phishing_on_free_provider_brand_spoof():
    # Authenticated Gmail phishing impersonating PayPal: additive score may be
    # positive, but gating must override it to Phishing.
    named = {
        "Display Name Spoofing": _rr("spoof", is_free_provider=True),
        "SPF": _rr("pass"),
        "DKIM": _rr("pass"),
    }
    assert _gated("Legitimate", named) == "Phishing"


def test_gating_forces_phishing_on_lookalike_domain():
    named = {"Lookalike Sender Domain": _rr("fail")}
    assert _gated("Legitimate", named) == "Phishing"


def test_gating_caps_at_suspicious_on_domain_misalignment():
    named = {"Domain Alignment": _rr("fail")}
    assert _gated("Legitimate", named) == "Suspicious"


def test_gating_verified_arc_pass_softens_spf_dmarc_alignment_gates():
    # D7: a legitimate forward validated by ARC (cv=pass) must not trip
    # the SPF/DMARC/alignment gates that exist to catch spoofing --
    # mailing lists/forwarders routinely break raw SPF/alignment as a
    # side effect of legitimate relaying.
    #
    # B06 añade la condición que faltaba: la validación tiene que venir
    # confirmada por un verificador de confianza (`verified`), no del propio
    # sello del mensaje.
    named = {
        "SPF": _rr("fail"),
        "DMARC": _rr("fail"),
        "Domain Alignment": _rr("fail"),
        "ARC Chain": _rr("pass", verified=True),
    }
    assert _gated("Legitimate", named) == "Legitimate"


def test_gating_unverified_arc_pass_no_longer_softens_the_gates():
    """B06, el bypass que se cierra.

    Antes bastaba con escribir `ARC-Seal: cv=pass` en el propio correo para
    desactivar de golpe los tres gates que cazan suplantación. Ahora un ARC sin
    confirmar es contexto: aparece en el informe, pero no da permisos.
    """
    named = {
        "SPF": _rr("fail"),
        "DMARC": _rr("fail"),
        "Domain Alignment": _rr("fail"),
        "ARC Chain": _rr("pass", verified=False),
    }
    assert _gated("Legitimate", named) == "Suspicious"


def test_gating_arc_fail_escalates_to_suspicious():
    named = {"ARC Chain": _rr("fail")}
    assert _gated("Legitimate", named) == "Suspicious"


def test_gating_spf_fail_without_arc_still_gates_as_before():
    # No ARC header at all (the common case) must behave exactly as
    # before D7 -- SPF/DMARC failure alone still gates to Suspicious.
    named = {"SPF": _rr("fail")}
    assert _gated("Legitimate", named) == "Suspicious"


def test_gating_never_improves_verdict():
    # A clean result set must not upgrade a Phishing baseline.
    named = {"SPF": _rr("pass"), "DKIM": _rr("pass"), "DMARC": _rr("pass")}
    assert _gated("Phishing", named) == "Phishing"


def test_gating_forces_phishing_on_bec_from_free_provider():
    # Clean-auth BEC (gmail sender, bank-change request) passes SPF/DKIM/DMARC
    # trivially; the BEC + free-provider gate must override to Phishing.
    named = {
        "BEC Wire Transfer Pattern": _rr("fail", from_domain="gmail.com", reply_domain=None),
        "SPF": _rr("pass"), "DKIM": _rr("pass"), "DMARC": _rr("pass"),
    }
    assert _gated("Legitimate", named) == "Phishing"


def test_gating_does_not_flag_corporate_bec_without_redirect_or_auth_fail():
    # Recalibración de pesos: un BEC corporativo (dominio propio, autentica
    # limpio) que solo dispara por texto -- sin redirect de Reply-To/Return-
    # Path ni fallo de auth -- dependía al 100% de la lista de frases; correo
    # interno legítimo de nómina/facturación la dispara con la misma
    # frecuencia. Sin corroboración estructural, ya no gatea en solitario.
    named = {"BEC Wire Transfer Pattern": _rr("fail", from_domain="acme.com", reply_domain="acme.com")}
    assert _gated("Legitimate", named) == "Legitimate"


def test_gating_forces_phishing_on_corporate_bec_with_redirect():
    # El mismo BEC corporativo, pero con Reply-To/Return-Path redirigiendo a
    # otro dominio -- la misma intención de desvío que bec_free, solo que sin
    # el tell de webmail gratuito. Esa corroboración estructural gatea igual
    # de fuerte que bec_free: a Phishing, no solo a Suspicious.
    named = {
        "BEC Wire Transfer Pattern": _rr(
            "fail", from_domain="acme.com", reply_domain="external.com",
            redirect_to_external_reply=True,
        ),
    }
    assert _gated("Legitimate", named) == "Phishing"


def test_gating_caps_at_suspicious_on_corporate_bec_with_auth_fail():
    # Idem, pero la corroboración es un fallo de autenticación en vez de un
    # redirect de reply-path.
    named = {
        "BEC Wire Transfer Pattern": _rr("fail", from_domain="acme.com", reply_domain="acme.com"),
        "SPF": _rr("fail"),
    }
    assert _gated("Legitimate", named) == "Suspicious"


def test_gating_forces_phishing_on_link_brand_impersonation():
    # A fully-authenticated message whose body link impersonates a brand via
    # subdomain trick (github.com.evil.com) must be gated to Phishing.
    named = {
        "Body Links": _rr("fail", types=["brand_impersonation"]),
        "SPF": _rr("pass"), "DKIM": _rr("pass"), "DMARC": _rr("pass"),
    }
    assert _gated("Legitimate", named) == "Phishing"


def test_gating_forces_phishing_on_suspicious_qr_code():
    # D1: a QR code decoding to a suspicious URL is a strong evasion
    # signal on its own -- it never appears as text/link anywhere.
    named = {
        "QR Code Links": _rr("fail"),
        "SPF": _rr("pass"), "DKIM": _rr("pass"), "DMARC": _rr("pass"),
    }
    assert _gated("Legitimate", named) == "Phishing"


def test_gating_returns_human_readable_reasons():
    # S1: the reasons that fired must be surfaced (not just logged) so the
    # report can explain WHY the verdict was gated.
    named = {"Lookalike Sender Domain": _rr("fail")}
    verdict, reasons = IrisManager._apply_verdict_gates("Legitimate", named)
    assert verdict == "Phishing"
    assert reasons and any("lookalike" in r for r in reasons)


def test_gating_returns_empty_reasons_when_clean():
    named = {"SPF": _rr("pass"), "DKIM": _rr("pass")}
    verdict, reasons = IrisManager._apply_verdict_gates("Legitimate", named)
    assert verdict == "Legitimate"
    assert reasons == []


# --------------------------------------------------------------- Top signals (S2)

def _rd(rule_name, score, category="header_analysis"):
    return {"ruleName": rule_name, "category": category, "score": score,
            "verdict": "fail" if score < 0 else "pass", "details": {},
            "recommendation": None}


def test_top_signals_ranks_most_negative_first():
    rules_data = [
        _rd("SPF", -20),
        _rd("Lookalike Sender Domain", -15),
        _rd("Display Name Spoofing", 0),
        _rd("Body Links", -25),
    ]
    signals = IrisManager._top_signals(rules_data)
    assert [s["ruleName"] for s in signals] == ["Body Links", "SPF", "Lookalike Sender Domain"]
    assert [s["score"] for s in signals] == [-25, -20, -15]


def test_top_signals_excludes_passing_rules():
    rules_data = [_rd("SPF", 0), _rd("DKIM", 5)]
    assert IrisManager._top_signals(rules_data) == []


def test_top_signals_caps_at_limit_and_keeps_original_index():
    rules_data = [_rd(f"Rule{i}", -1 * (i + 1)) for i in range(8)]
    signals = IrisManager._top_signals(rules_data)
    assert len(signals) == IrisManager._TOP_SIGNALS_LIMIT
    # Rule7 has the most negative score (-8) and sits at index 7 in rules_data.
    assert signals[0]["ruleName"] == "Rule7"
    assert signals[0]["index"] == 7


# ----------------------------------------------------- Subtractive scoring model

def _unfamilied_defs(count: int) -> list[dict]:
    # No `family` key -> passes through _aggregate_score's family-cap logic
    # untouched, matching these tests' original (pre-§18) intent.
    return [{"name": f"Rule{i}", "family": ""} for i in range(count)]


def test_aggregate_score_clamps_positive_credits():
    # Passing rules (positive scores) contribute nothing; only penalties count.
    results = [
        RuleResult(score=5, verdict="pass", details={}),
        RuleResult(score=3, verdict="pass", details={}),
        RuleResult(score=-15, verdict="fail", details={}),
        RuleResult(score=-5, verdict="fail", details={}),
    ]
    # 100 + min(0,5) + min(0,3) + (-15) + (-5) == 80
    assert IrisManager._aggregate_score(_unfamilied_defs(len(results)), results) == 80


def test_aggregate_score_clean_message_stays_at_ceiling():
    results = [RuleResult(score=5, verdict="pass", details={}) for _ in range(10)]
    assert IrisManager._aggregate_score(_unfamilied_defs(len(results)), results) == 100


def test_aggregate_score_floored_at_zero():
    results = [RuleResult(score=-80, verdict="fail", details={}) for _ in range(3)]
    assert IrisManager._aggregate_score(_unfamilied_defs(len(results)), results) == 0


# ----------------------------------------------------------- IOC extraction (O1)

def _iocs_for(monkeypatch, raw_message):
    from types import SimpleNamespace
    fake_analysis = SimpleNamespace(id=42, raw_headers=raw_message)
    monkeypatch.setattr(
        IrisManager, "assert_analysis_ownership",
        classmethod(lambda cls, analysis_id, user_id: fake_analysis),
    )
    return IrisManager().get_analysis_iocs(analysis_id=42, user_id=1)


def test_iocs_extracts_domains_emails_from_headers(monkeypatch):
    raw = (
        "From: Attacker <phisher@evil-domain.tk>\r\n"
        "Reply-To: reply@another-evil.io\r\n"
        "Subject: Hi\r\n\r\n"
    )
    result = _iocs_for(monkeypatch, raw)
    assert result["analysisId"] == 42
    assert "evil-domain.tk" in result["domains"]
    assert "another-evil.io" in result["domains"]
    assert "phisher@evil-domain.tk" in result["emails"]
    assert "reply@another-evil.io" in result["emails"]
    assert result["urls"] == []
    assert result["ips"] == []


def test_iocs_extracts_urls_and_hosts_from_body_links(monkeypatch):
    raw = (
        "From: a@b.com\r\nSubject: Hi\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
        "<a href=\"http://sketchy-host.tk/login\">click</a>\r\n"
    )
    result = _iocs_for(monkeypatch, raw)
    assert "http://sketchy-host.tk/login" in result["urls"]
    assert "sketchy-host.tk" in result["domains"]


def test_iocs_extracts_ips_from_received_chain(monkeypatch):
    raw = (
        "From: a@b.com\r\nSubject: Hi\r\n"
        "Received: from mail.evil.tk (mail.evil.tk [203.0.113.9])\r\n"
        "    by mx.example.com with ESMTP id abc123;\r\n"
        "    Wed, 25 Jun 2026 10:00:00 +0000\r\n\r\n"
    )
    result = _iocs_for(monkeypatch, raw)
    assert "203.0.113.9" in result["ips"]


def test_iocs_empty_lists_when_headers_only_and_clean(monkeypatch):
    raw = "From: a@trusted.com\r\nSubject: Hi\r\n\r\n"
    result = _iocs_for(monkeypatch, raw)
    assert result["domains"] == ["trusted.com"]
    assert result["urls"] == []
    assert result["ips"] == []
    assert result["emails"] == ["a@trusted.com"]
    assert result["hashes"] == []


def test_iocs_includes_attachment_sha256(monkeypatch):
    # D8: every attachment's hash is surfaced as an IOC, not just ones a
    # rule flagged as suspicious.
    import base64
    import hashlib
    content = b"fake-attachment-bytes"
    encoded = base64.b64encode(content).decode()
    raw = (
        "From: a@b.com\r\nSubject: Hi\r\n"
        "Content-Type: multipart/mixed; boundary=\"BOUND\"\r\n\r\n"
        "--BOUND\r\nContent-Type: text/plain\r\n\r\nhello\r\n"
        "--BOUND\r\nContent-Type: application/octet-stream\r\n"
        "Content-Disposition: attachment; filename=\"file.bin\"\r\n"
        "Content-Transfer-Encoding: base64\r\n\r\n"
        f"{encoded}\r\n--BOUND--\r\n"
    )
    result = _iocs_for(monkeypatch, raw)
    assert result["hashes"] == [hashlib.sha256(content).hexdigest()]


# ------------------------------------------------------------- Reanalyze (O5)

class _FakeTaskQueue:
    def __init__(self):
        self.submitted = None

    def submit(self, **kwargs):
        self.submitted = kwargs


def test_reanalyze_submits_the_same_stored_raw_input(monkeypatch):
    """reanalyze() delega en analyze() con el raw_headers guardado -- sus
    propios internos (cuota, outbox, TaskQueue) ya tienen cobertura directa
    en test_iris_quota_idempotency.py y test_iris.py, así que aquí basta con
    comprobar qué le pasa reanalyze() a analyze()."""
    from types import SimpleNamespace

    raw = "From: a@b.com\r\nSubject: Hi\r\n\r\n"
    fake_analysis = SimpleNamespace(id=5, title="Correo sospechoso", raw_headers=raw)
    monkeypatch.setattr(
        IrisManager, "assert_analysis_ownership",
        classmethod(lambda cls, analysis_id, user_id: fake_analysis),
    )

    captured = {}

    def _fake_analyze(self, raw_headers, user_id, title=None, **kwargs):
        captured["raw_headers"] = raw_headers
        captured["user_id"] = user_id
        return 99

    monkeypatch.setattr(IrisManager, "analyze", _fake_analyze)

    new_id = IrisManager().reanalyze(analysis_id=5, user_id=1)

    assert new_id == 99
    assert captured["raw_headers"] == raw
    assert captured["user_id"] == 1


def test_reanalyze_title_references_the_original():
    from types import SimpleNamespace

    captured_titles = []

    class _Manager(IrisManager):
        def analyze(self, raw_headers, user_id, title=None, **kwargs):
            captured_titles.append(title)
            return 100

    fake_analysis = SimpleNamespace(id=7, title="Factura pendiente", raw_headers="From: a@b.com\r\n\r\n")
    _Manager.assert_analysis_ownership = classmethod(lambda cls, analysis_id, user_id: fake_analysis)

    _Manager().reanalyze(analysis_id=7, user_id=1)

    assert captured_titles == ["Factura pendiente (reanálisis)"]


# ------------------------------------------------------- AI summary (IA1)

def test_generate_ai_summary_rejects_unfinished_analysis(monkeypatch):
    from types import SimpleNamespace
    fake_analysis = SimpleNamespace(id=9, status="running")
    monkeypatch.setattr(
        IrisManager, "assert_analysis_ownership",
        classmethod(lambda cls, analysis_id, user_id: fake_analysis),
    )
    from src.modules.features.iris.exceptions import IrisAnalysisNotReadyError
    with pytest.raises(IrisAnalysisNotReadyError):
        IrisManager(task_queue=_FakeTaskQueue()).generate_ai_summary(analysis_id=9, user_id=1)


def test_generate_ai_summary_submits_task_for_finished_analysis(monkeypatch):
    """B10 añadió dos pasos con estado a esta función —reclamar la fila y
    cobrar cuota— que un test sin base de datos no puede ejercitar.

    Aquí se sustituyen los dos por dobles para que el test siga siendo lo que
    era: la comprobación de que el trabajo se encola con los argumentos y la
    categoría correctos. La idempotencia y el reembolso, que son lo que esos
    pasos aportan, se prueban contra la base de datos real en
    ``tests/integration/test_iris_ai_summary.py``.
    """
    from types import SimpleNamespace
    import src.modules.features.iris.managers.analysis as analysis_mod

    fake_analysis = SimpleNamespace(id=10, status="finished", ai_summary=None)
    monkeypatch.setattr(
        IrisManager, "assert_analysis_ownership",
        classmethod(lambda cls, analysis_id, user_id: fake_analysis),
    )
    monkeypatch.setattr(
        IrisManager, "_claim_ai_summary",
        staticmethod(lambda analysis_id, regenerate=False: True),
    )
    monkeypatch.setattr(IrisManager, "_update_analysis",
                        lambda self, analysis_id, **fields: True)

    class _FreeQuota:
        def consume(self, user_id, key, amount=1): pass
        def consume_many(self, user_id, keys, amount=1): pass
        def refund(self, user_id, key, amount=1): pass

    monkeypatch.setattr(analysis_mod, "QuotaManager", _FreeQuota)

    fake_queue = _FakeTaskQueue()
    IrisManager(task_queue=fake_queue).generate_ai_summary(analysis_id=10, user_id=1)

    assert fake_queue.submitted["args"] == (10, 1)
    assert fake_queue.submitted["category"] == "iris.ai_summary"


def test_execute_ai_summary_generation_degrades_cleanly_on_ai_failure(monkeypatch):
    # The AI backend failing (misconfigured/unreachable/circuit-breaker open)
    # must not raise -- it's a background task attached to an already
    # finished analysis; failing loudly would be worse than just leaving
    # ai_summary unset.
    monkeypatch.setattr(
        IrisManager, "get_analysis_results",
        lambda self, analysis_id: {"verdict": "Phishing", "totalScore": 10, "gateReasons": [], "rules": []},
    )

    class _BrokenWriter:
        def generate(self, report):
            raise RuntimeError("AI backend unavailable")

    monkeypatch.setattr("src.modules.features.iris.managers.analysis.IrisAIWriter", _BrokenWriter)

    # Should not raise.
    IrisManager.execute_ai_summary_generation(analysis_id=11)
