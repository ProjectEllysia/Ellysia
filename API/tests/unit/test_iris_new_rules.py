"""Tests unitarios de las 10 reglas añadidas en Fase 1.

Cubre señales forenses observables en el correo:
- Display name vs. email local aleatorio
- Subdomain impersonation (paypal.com.fishing.tk, etc.)
- Dominios legítimos comprometidos (open redirectors)
- BEC wire-transfer pattern
- Generic greeting + action verb
- From/Reply-To/Return-Path triangulación
- Image-only email
- Received-chain temporal inversion
- Self-referencing In-Reply-To
- External image tracking (no-ESP)
"""

from __future__ import annotations

import pytest

from src.modules.iris.services.parsers import MessageContext
from src.modules.iris.services.rules.sender_identity_rules import (
    check_display_name_email_mismatch,
)
from src.modules.iris.services.rules.sender_identity_rules import (
    check_subdomain_impersonation,
)
from src.modules.iris.services.rules.body_links_rules import (
    check_compromised_legitimate_domain,
)
from src.modules.iris.services.rules.body_content_rules import (
    check_bec_wire_pattern,
)
from src.modules.iris.services.rules.body_content_rules import check_generic_greeting
from src.modules.iris.services.rules.reply_path_rules import check_triangulation
from src.modules.iris.services.rules.attachment_media_rules import check_image_only_email
from src.modules.iris.services.rules.received_timing_rules import (
    check_received_chain_temporal_inconsistency,
)
from src.modules.iris.services.rules.thread_rules import (
    check_self_referencing_in_reply_to,
)
from src.modules.iris.services.rules.attachment_media_rules import (
    check_external_image_tracking,
)

pytestmark = pytest.mark.unit


# ----------------------------------------- Display Name Email Mismatch

def test_display_name_email_mismatch_flags_random_local():
    result = check_display_name_email_mismatch({
        "from": "PayPal Support <x8hd92kj.thx@gmail.com>",
    })
    assert result.verdict == "fail"
    assert result.score <= -10
    assert result.details["domain"] == "gmail.com"


def test_display_name_email_mismatch_allows_role_address():
    result = check_display_name_email_mismatch({
        "from": "PayPal Support <support@paypal.com>",
    })
    assert result.verdict == "neutral"
    assert result.score == 0


def test_display_name_email_mismatch_allows_short_local():
    result = check_display_name_email_mismatch({
        "from": "PayPal <info@paypal-corp.com>",
    })
    assert result.verdict == "neutral"


def test_display_name_email_mismatch_no_display_name():
    result = check_display_name_email_mismatch({"from": "x9d2h3@gmail.com"})
    assert result.verdict == "neutral"


# ------------------------------------------------- Subdomain Impersonation

def test_subdomain_impersonation_flags_brand_in_subdomain():
    result = check_subdomain_impersonation({
        "from": "PayPal <noreply@paypal.com.secure-login.tk>",
    })
    assert result.verdict == "fail"
    assert result.score < 0
    assert any(
        f["type"] == "brand_in_subdomain" for f in result.details["findings"]
    )


def test_subdomain_impersonation_flags_brand_action_combo():
    result = check_subdomain_impersonation({
        "from": "Microsoft <noreply@account-microsoft-verify.com>",
    })
    assert result.verdict == "fail"
    assert any(
        f["type"] == "brand_action_combo" for f in result.details["findings"]
    )


def test_subdomain_impersonation_passes_legitimate_brand():
    result = check_subdomain_impersonation({
        "from": "billing@paypal.com",
    })
    assert result.verdict == "pass"


def test_subdomain_impersonation_passes_ordinary_subdomain():
    result = check_subdomain_impersonation({
        "from": "a@mail.smallbusiness.com",
    })
    assert result.verdict == "neutral"


def test_subdomain_impersonation_passes_no_from():
    result = check_subdomain_impersonation({})
    assert result.verdict == "neutral"


# -------------------------------------- Compromised Legitimate Domain

def _ctx_with_links(links):
    return MessageContext(
        headers={"from": "a@b.com"},
        body_html="",
        links=links,
    )


def test_compromised_domain_flags_open_redirect():
    from src.modules.iris.services.parsers import Link
    ctx = _ctx_with_links([
        Link(href="https://legit-site.com/redirect?url=https://evil.tk/login",
             text="click"),
    ])
    result = check_compromised_legitimate_domain(ctx)
    assert result.verdict == "fail"
    assert result.score < 0


def test_compromised_domain_flags_opaque_path():
    from src.modules.iris.services.parsers import Link
    ctx = _ctx_with_links([
        Link(href="https://legit-site.com/aB3dEf12XyZ9Pq", text="open"),
    ])
    result = check_compromised_legitimate_domain(ctx)
    assert result.verdict == "fail"


def test_compromised_domain_passes_clean_legit_link():
    from src.modules.iris.services.parsers import Link
    ctx = _ctx_with_links([
        Link(href="https://legit-site.com/account/settings", text="settings"),
    ])
    result = check_compromised_legitimate_domain(ctx)
    assert result.verdict == "pass"


def test_compromised_domain_neutral_when_no_links():
    result = check_compromised_legitimate_domain(_ctx_with_links([]))
    assert result.verdict == "neutral"


# ------------------------------------------------------- BEC Wire Pattern

def test_bec_flags_wire_with_corporate_sender():
    ctx = MessageContext(
        headers={"from": "CFO <cfo@victim-corp.com>"},
        body_text=(
            "Hi, I need you to initiate a wire transfer of $87,000 "
            "to our new vendor today. Please do not notify accounting."
        ),
    )
    result = check_bec_wire_pattern(ctx)
    assert result.verdict == "fail"
    assert result.score <= -12


def test_bec_flags_banking_change_pattern():
    ctx = MessageContext(
        headers={"from": "AP <ap@victim-corp.com>"},
        body_text=(
            "Please update our banking details for the upcoming invoice. "
            "Use the new wire instructions below."
        ),
    )
    result = check_bec_wire_pattern(ctx)
    assert result.verdict == "fail"


def test_bec_neutral_for_normal_business_email():
    ctx = MessageContext(
        headers={"from": "manager@victim-corp.com"},
        body_text=(
            "Could you send me last quarter's report? Let me know when "
            "you have a moment to review it together."
        ),
    )
    result = check_bec_wire_pattern(ctx)
    assert result.verdict == "neutral"


def test_bec_handles_spanish_payload():
    ctx = MessageContext(
        headers={"from": "a@empresa.es"},
        body_text=(
            "Necesito que realices una transferencia bancaria urgente "
            "y no informar a contabilidad hasta mañana."
        ),
    )
    result = check_bec_wire_pattern(ctx)
    assert result.verdict == "fail"


def test_bec_handles_html_body():
    ctx = MessageContext(
        headers={"from": "a@victim-corp.com"},
        body_html=(
            "<p>Please <b>send the payment</b> via wire transfer today, "
            "this is <i>confidential</i>.</p>"
        ),
        body_text="",
    )
    result = check_bec_wire_pattern(ctx)
    assert result.verdict == "fail"


# --------------------------------------------------------- Generic Greeting

def test_generic_greeting_flags_dear_customer_with_action():
    ctx = MessageContext(
        headers={},
        body_text=(
            "Dear Customer,\n\n"
            "We have detected unusual activity. Please verify your account "
            "by clicking the link below within 24 hours."
        ),
    )
    result = check_generic_greeting(ctx)
    assert result.verdict == "fail"
    assert result.score < 0


def test_generic_greeting_flags_spanish_pattern():
    ctx = MessageContext(
        headers={},
        body_text=(
            "Estimado cliente, confirma los datos de su cuenta para "
            "evitar el bloqueo de la misma."
        ),
    )
    result = check_generic_greeting(ctx)
    assert result.verdict == "fail"


def test_generic_greeting_passes_with_personalised_greeting():
    ctx = MessageContext(
        headers={},
        body_text=(
            "Hi Maria,\n\n"
            "We detected unusual activity. Please verify your account."
        ),
    )
    result = check_generic_greeting(ctx)
    assert result.verdict == "neutral"


def test_generic_greeting_neutral_when_no_action_verb():
    ctx = MessageContext(
        headers={},
        body_text="Dear customer, here is your monthly newsletter with tips.",
    )
    result = check_generic_greeting(ctx)
    assert result.verdict == "neutral"


# ---------------------------------------- From/Reply-To/Return-Path Triangulation

def test_triangulation_flags_three_distinct_domains():
    result = check_triangulation({
        "from": "CEO <ceo@company-a.com>",
        "reply-to": "ceo.private@gmail.com",
        "return-path": "<bounce@mailer-c.net>",
    })
    assert result.verdict == "fail"
    assert result.score <= -12
    assert result.details["distinct_count"] == 3


def test_triangulation_passes_when_aligned():
    result = check_triangulation({
        "from": "Support <support@company.com>",
        "reply-to": "no-reply@mail.company.com",
        "return-path": "<bounce@mail.company.com>",
    })
    assert result.verdict == "neutral"


def test_triangulation_passes_with_only_two_headers():
    result = check_triangulation({
        "from": "a@company.com",
        "reply-to": "b@company.com",
    })
    assert result.verdict == "neutral"


def test_triangulation_handles_missing_from():
    result = check_triangulation({})
    assert result.verdict == "neutral"


# ----------------------------------------------------- Image-Only Email

def test_image_only_email_flags_single_external_image():
    ctx = MessageContext(
        headers={},
        body_html=(
            '<html><body><img src="https://evil.tk/payload.png" '
            'alt="verify"/></body></html>'
        ),
    )
    result = check_image_only_email(ctx)
    assert result.verdict == "fail"
    assert result.score <= -10


def test_image_only_email_passes_rich_text_newsletter():
    ctx = MessageContext(
        headers={},
        body_text="Welcome to our June newsletter!",
        body_html=(
            "<html><body>"
            "<h1>June Newsletter</h1>"
            "<p>Read about our latest products and offers in this issue.</p>"
            "<img src=\"https://cdn.brand.com/banner.jpg\" alt=\"banner\"/>"
            "</body></html>"
        ),
    )
    result = check_image_only_email(ctx)
    assert result.verdict == "pass"


def test_image_only_email_passes_text_only_email():
    ctx = MessageContext(
        headers={},
        body_text="Hello, this is a plain text email.",
    )
    result = check_image_only_email(ctx)
    assert result.verdict == "pass"


def test_image_only_email_neutral_when_empty():
    result = check_image_only_email(MessageContext(headers={}))
    assert result.verdict == "neutral"


# ---------------------------- Received Chain Temporal Inconsistency

def test_temporal_inconsistency_flags_inverted_hops():
    ctx = MessageContext(
        headers={"from": "a@b.com"},
        received_headers=[
            "from mx.b.com by mx2.b.com; Wed, 25 Jun 2025 10:00:00 +0000",
            "from [10.0.0.1] by mx.b.com; Wed, 25 Jun 2025 10:05:00 +0000",
            "from [192.0.2.1] by internal.b.com; Wed, 25 Jun 2025 09:55:00 +0000",
        ],
    )
    result = check_received_chain_temporal_inconsistency(ctx)
    assert result.verdict == "fail"
    assert result.score < 0
    assert len(result.details["inversions"]) >= 1


def test_temporal_inconsistency_passes_monotonic_chain():
    ctx = MessageContext(
        headers={"from": "a@b.com"},
        received_headers=[
            "from mx.b.com by mx2.b.com; Wed, 25 Jun 2025 10:00:00 +0000",
            "from [192.0.2.1] by mx.b.com; Wed, 25 Jun 2025 09:59:00 +0000",
        ],
    )
    result = check_received_chain_temporal_inconsistency(ctx)
    assert result.verdict == "pass"


def test_temporal_inconsistency_neutral_when_single_hop():
    ctx = MessageContext(
        headers={"from": "a@b.com"},
        received_headers=[
            "from [192.0.2.1] by mx.b.com; Wed, 25 Jun 2025 10:00:00 +0000",
        ],
    )
    result = check_received_chain_temporal_inconsistency(ctx)
    assert result.verdict == "neutral"


def test_temporal_inconsistency_neutral_when_no_chain():
    result = check_received_chain_temporal_inconsistency(
        MessageContext(headers={})
    )
    assert result.verdict == "neutral"


# ------------------------------------------ Self-Referencing In-Reply-To

def test_self_referencing_in_reply_to_flags_self_in_reply_to():
    result = check_self_referencing_in_reply_to({
        "message-id": "<abc.123@evil.tk>",
        "in-reply-to": "<abc.123@evil.tk>",
    })
    assert result.verdict == "fail"
    assert result.score <= -12


def test_self_referencing_in_reply_to_flags_self_in_references():
    result = check_self_referencing_in_reply_to({
        "message-id": "<abc.123@evil.tk>",
        "references": "<abc.123@evil.tk> <other@legit.com>",
    })
    assert result.verdict == "fail"


def test_self_referencing_passes_legitimate_reply():
    result = check_self_referencing_in_reply_to({
        "message-id": "<new.456@legit.com>",
        "in-reply-to": "<prev.123@legit.com>",
        "references": "<prev.123@legit.com> <older.000@legit.com>",
    })
    assert result.verdict == "pass"


def test_self_referencing_neutral_when_no_message_id():
    result = check_self_referencing_in_reply_to({
        "in-reply-to": "<whatever@something.com>",
    })
    assert result.verdict == "neutral"


# ------------------------------------------- External Image Tracking

def test_external_image_tracking_flags_non_esp_external_image():
    ctx = MessageContext(
        headers={"from": "support@company.com"},
        body_html=(
            '<html><body><p>Welcome!</p>'
            '<img src="https://1x1-pixel.suspicious.tk/track.gif" alt=""/>'
            '</body></html>'
        ),
    )
    result = check_external_image_tracking(ctx)
    assert result.verdict == "fail"
    assert "suspicious.tk" in result.details["external_image_hosts"]


def test_external_image_tracking_allows_esp_cdn():
    ctx = MessageContext(
        headers={"from": "marketing@company.com"},
        body_html=(
            '<html><body><p>Newsletter</p>'
            '<img src="https://cdn.sendgrid.net/img/banner.jpg" alt=""/>'
            '</body></html>'
        ),
    )
    result = check_external_image_tracking(ctx)
    assert result.verdict == "pass"


def test_external_image_tracking_allows_own_domain():
    ctx = MessageContext(
        headers={"from": "a@company.com"},
        body_html=(
            '<html><body><img src="https://company.com/img/x.png" alt=""/>'
            '</body></html>'
        ),
    )
    result = check_external_image_tracking(ctx)
    assert result.verdict == "pass"


def test_external_image_tracking_neutral_when_no_html():
    result = check_external_image_tracking(
        MessageContext(headers={"from": "a@b.com"}, body_html="")
    )
    assert result.verdict == "neutral"
