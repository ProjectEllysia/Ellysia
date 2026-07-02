"""Tests unitarios de reglas de detección de phishing (Iris).

Las reglas son funciones puras: reciben un dict de cabeceras y devuelven
un ``RuleResult`` con score/verdict. No requieren BD ni red.
"""

import base64

import pytest

from src.modules.iris.services.rules.spf import check_spf
from src.modules.iris.services.rules.suspicious_tld import check_suspicious_tld
from src.modules.iris.services.rules.url_in_subject import check_url_in_subject
from src.modules.iris.services.rules.domain_alignment import check_domain_alignment
from src.modules.iris.services.rules.lookalike_domain import check_lookalike_domain
from src.modules.iris.services.rules.reply_to_free_provider import check_reply_to_free_provider
from src.modules.iris.services.rules.reply_to import check_reply_to
from src.modules.iris.services.rules.msgid_domain import check_msgid_domain
from src.modules.iris.services.rules.list_unsubscribe import check_list_unsubscribe
from src.modules.iris.services.rules.alarming_keywords import check_alarming_keywords
from src.modules.iris.services.rules.misspelled_brands import check_misspelled_brands
from src.modules.iris.services.rules.content_type_check import check_content_type
from src.modules.iris.services.registry import RuleResult
from src.modules.iris.managers import IrisManager

pytestmark = pytest.mark.unit


# --------------------------------------------------------------------------- SPF

def test_spf_pass_is_positive():
    result = check_spf({"authentication-results": "mx.google.com; spf=pass smtp.mailfrom=a@b.com"})
    assert result.verdict == "pass"
    assert result.score > 0


def test_spf_fail_is_strongly_negative():
    result = check_spf({"authentication-results": "spf=fail smtp.mailfrom=evil@b.com"})
    assert result.verdict == "fail"
    assert result.score <= -20


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
    result = check_domain_alignment({
        "from": "CEO <ceo@victima.com>",
        "authentication-results": "mx; dkim=pass header.d=sendgrid.net",
        "dkim-signature": "v=1; a=rsa-sha256; d=sendgrid.net; s=s1",
    })
    assert result.verdict == "fail"
    assert result.score <= -15


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


# -------------------------------------------------------------- Content-Type check

def test_content_type_plain_text_not_penalised():
    # Plain-text-only is common in legit transactional mail — no penalty.
    result = check_content_type({"content-type": "text/plain; charset=UTF-8"})
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


def test_gating_forces_phishing_on_free_provider_brand_spoof():
    # Authenticated Gmail phishing impersonating PayPal: additive score may be
    # positive, but gating must override it to Phishing.
    named = {
        "Display Name Spoofing": _rr("spoof", is_free_provider=True),
        "SPF": _rr("pass"),
        "DKIM": _rr("pass"),
    }
    assert IrisManager._apply_verdict_gates("Legitimate", named) == "Phishing"


def test_gating_forces_phishing_on_lookalike_domain():
    named = {"Lookalike Sender Domain": _rr("fail")}
    assert IrisManager._apply_verdict_gates("Legitimate", named) == "Phishing"


def test_gating_caps_at_suspicious_on_domain_misalignment():
    named = {"Domain Alignment": _rr("fail")}
    assert IrisManager._apply_verdict_gates("Legitimate", named) == "Suspicious"


def test_gating_never_improves_verdict():
    # A clean result set must not upgrade a Phishing baseline.
    named = {"SPF": _rr("pass"), "DKIM": _rr("pass"), "DMARC": _rr("pass")}
    assert IrisManager._apply_verdict_gates("Phishing", named) == "Phishing"


def test_gating_forces_phishing_on_bec_from_free_provider():
    # Clean-auth BEC (gmail sender, bank-change request) passes SPF/DKIM/DMARC
    # trivially; the BEC + free-provider gate must override to Phishing.
    named = {
        "BEC Wire Transfer Pattern": _rr("fail", from_domain="gmail.com", reply_domain=None),
        "SPF": _rr("pass"), "DKIM": _rr("pass"), "DMARC": _rr("pass"),
    }
    assert IrisManager._apply_verdict_gates("Legitimate", named) == "Phishing"


def test_gating_caps_at_suspicious_on_corporate_bec():
    # A BEC from a corporate (non-free) sender is at least Suspicious.
    named = {"BEC Wire Transfer Pattern": _rr("fail", from_domain="acme.com", reply_domain="acme.com")}
    assert IrisManager._apply_verdict_gates("Legitimate", named) == "Suspicious"


def test_gating_forces_phishing_on_link_brand_impersonation():
    # A fully-authenticated message whose body link impersonates a brand via
    # subdomain trick (github.com.evil.com) must be gated to Phishing.
    named = {
        "Body Links": _rr("fail", types=["brand_impersonation"]),
        "SPF": _rr("pass"), "DKIM": _rr("pass"), "DMARC": _rr("pass"),
    }
    assert IrisManager._apply_verdict_gates("Legitimate", named) == "Phishing"


# ----------------------------------------------------- Subtractive scoring model

def test_aggregate_score_clamps_positive_credits():
    # Passing rules (positive scores) contribute nothing; only penalties count.
    results = [
        RuleResult(score=5, verdict="pass", details={}),
        RuleResult(score=3, verdict="pass", details={}),
        RuleResult(score=-15, verdict="fail", details={}),
        RuleResult(score=-5, verdict="fail", details={}),
    ]
    # 100 + min(0,5) + min(0,3) + (-15) + (-5) == 80
    assert IrisManager._aggregate_score(results) == 80


def test_aggregate_score_clean_message_stays_at_ceiling():
    results = [RuleResult(score=5, verdict="pass", details={}) for _ in range(10)]
    assert IrisManager._aggregate_score(results) == 100


def test_aggregate_score_floored_at_zero():
    results = [RuleResult(score=-80, verdict="fail", details={}) for _ in range(3)]
    assert IrisManager._aggregate_score(results) == 0
