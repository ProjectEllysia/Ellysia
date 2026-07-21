"""Tests unitarios de Fase 2: parser de mensaje completo y reglas que
dependen del cuerpo/enlaces/adjuntos (``needs_context=True``).
"""

from __future__ import annotations

import pytest

from src.modules.features.iris.services.parsers import parse_raw_message, MessageContext, Attachment
from src.modules.features.iris.services.rules.received_timing_rules import check_received_chain
from src.modules.features.iris.services.rules.body_links_rules import check_body_links
from src.modules.features.iris.services.rules.body_content_rules import check_body_content
from src.modules.features.iris.services.rules.attachment_media_rules import check_suspicious_attachments

pytestmark = pytest.mark.unit


# --------------------------------------------------------------- message parser

def test_parse_headers_only_input_has_empty_body():
    raw = "From: a@b.com\nSubject: Hi\nDate: Wed, 25 Jun 2025 10:00:00 +0000\n"
    ctx = parse_raw_message(raw)
    assert ctx.body_text == ""
    assert ctx.body_html == ""
    assert ctx.links == []
    assert ctx.attachments == []
    assert ctx.headers["from"] == "a@b.com"


def test_parse_multipart_message_extracts_html_links_and_attachment():
    raw = (
        "From: a@b.com\r\n"
        "Subject: Hi\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: multipart/mixed; boundary=\"BOUND\"\r\n"
        "\r\n"
        "--BOUND\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "\r\n"
        "<html><body><a href=\"http://evil.example.com/x\">paypal.com</a></body></html>\r\n"
        "--BOUND\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Content-Disposition: attachment; filename=\"invoice.exe\"\r\n"
        "\r\n"
        "binarydata\r\n"
        "--BOUND--\r\n"
    )
    ctx = parse_raw_message(raw)
    assert "evil.example.com" in ctx.body_html
    assert len(ctx.links) == 1
    assert ctx.links[0].href == "http://evil.example.com/x"
    assert ctx.links[0].text == "paypal.com"
    assert len(ctx.attachments) == 1
    assert ctx.attachments[0].filename == "invoice.exe"


# ------------------------------------------------- Nested message/rfc822 forward (I2)

def _forward_with_nested_original(inner_from="PayPal Support <support@paypal-security.tk>",
                                   inner_subject="Urgent Verify Account") -> str:
    return (
        "From: Reporter <reporter@corp.com>\r\n"
        "Subject: FW: Suspicious email\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: multipart/mixed; boundary=\"OUTER\"\r\n"
        "\r\n"
        "--OUTER\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "Please see attached.\r\n"
        "--OUTER\r\n"
        "Content-Type: message/rfc822\r\n"
        "Content-Disposition: attachment; filename=\"original.eml\"\r\n"
        "\r\n"
        f"From: {inner_from}\r\n"
        f"Subject: {inner_subject}\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "\r\n"
        "<html><body><a href=\"http://evil.example.com/verify\">Verify</a></body></html>\r\n"
        "--OUTER--\r\n"
    )


def test_forward_unwraps_nested_original_as_the_analyzed_message():
    ctx = parse_raw_message(_forward_with_nested_original())
    assert ctx.unwrapped_from_forward is True
    # The analyzed headers/body/links must be the INNER message's, not the wrapper's.
    assert ctx.headers["from"] == "PayPal Support <support@paypal-security.tk>"
    assert ctx.headers["subject"] == "Urgent Verify Account"
    assert len(ctx.links) == 1
    assert ctx.links[0].href == "http://evil.example.com/verify"


def test_forward_preserves_wrapper_identity_separately():
    # Regression: a naive line-based re-parse of the whole raw text would
    # pick up the *inner* message's From/Subject here too, since it has no
    # concept of a MIME boundary.
    ctx = parse_raw_message(_forward_with_nested_original())
    assert ctx.wrapper_from == "Reporter <reporter@corp.com>"
    assert ctx.wrapper_subject == "FW: Suspicious email"


def test_plain_message_is_not_marked_as_unwrapped():
    raw = "From: a@b.com\r\nSubject: Hi\r\nContent-Type: text/html\r\n\r\n<p>hello</p>"
    ctx = parse_raw_message(raw)
    assert ctx.unwrapped_from_forward is False
    assert ctx.wrapper_from == ""
    assert ctx.wrapper_subject == ""


def test_multipart_with_regular_attachment_is_not_unwrapped():
    # A normal attachment (application/octet-stream) must not be confused
    # with a message/rfc822 forward.
    raw = (
        "From: a@b.com\r\nSubject: Hi\r\n"
        "Content-Type: multipart/mixed; boundary=\"B\"\r\n\r\n"
        "--B\r\nContent-Type: text/plain\r\n\r\nhi\r\n"
        "--B\r\nContent-Type: application/octet-stream\r\n"
        "Content-Disposition: attachment; filename=\"invoice.pdf\"\r\n\r\n"
        "binarydata\r\n--B--\r\n"
    )
    ctx = parse_raw_message(raw)
    assert ctx.unwrapped_from_forward is False


# --------------------------------------------------------------- Received chain (C3/C8)

def test_received_chain_neutral_when_absent():
    ctx = MessageContext(headers={})
    result = check_received_chain(ctx)
    assert result.verdict == "neutral"
    assert result.score == 0


def test_received_chain_flags_private_origin_ip():
    ctx = MessageContext(
        headers={"date": "Wed, 25 Jun 2025 10:00:00 +0000"},
        received_headers=[
            "from mx.example.com by mx2.example.com; Wed, 25 Jun 2025 10:00:00 +0000",
            "from [10.0.0.5] by mx.example.com; Wed, 25 Jun 2025 09:59:00 +0000",
        ],
    )
    result = check_received_chain(ctx)
    assert result.verdict == "fail"
    assert result.score < 0


def test_received_chain_flags_date_mismatch():
    ctx = MessageContext(
        headers={"date": "Wed, 25 Jun 2025 10:00:00 +0000"},
        received_headers=[
            "from mx.example.com by mx2.example.com; Thu, 26 Jun 2025 20:00:00 +0000",
        ],
    )
    result = check_received_chain(ctx)
    assert result.verdict == "fail"


def test_received_chain_passes_when_consistent():
    ctx = MessageContext(
        headers={"date": "Wed, 25 Jun 2025 10:00:00 +0000"},
        received_headers=[
            "from mx.example.com by mx2.example.com; Wed, 25 Jun 2025 09:59:30 +0000",
        ],
    )
    result = check_received_chain(ctx)
    assert result.verdict == "pass"


# --------------------------------------------------------------- Body links (C10)

def test_body_links_neutral_when_no_links():
    ctx = MessageContext(headers={})
    result = check_body_links(ctx)
    assert result.verdict == "neutral"


def test_body_links_flags_cloaked_link():
    raw = (
        "From: a@b.com\r\nSubject: Hi\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
        "<a href=\"http://attacker.example.net/login\">paypal.com</a>\r\n"
    )
    ctx = parse_raw_message(raw)
    result = check_body_links(ctx)
    assert result.verdict == "fail"
    assert "cloaked_link" in result.details["types"]


def test_body_links_flags_punycode_host():
    raw = (
        "From: a@b.com\r\nSubject: Hi\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
        "<a href=\"http://xn--pypal-4ve.com/x\">click here</a>\r\n"
    )
    ctx = parse_raw_message(raw)
    result = check_body_links(ctx)
    assert result.verdict == "fail"
    assert "punycode" in result.details["types"]


def test_body_links_flags_known_shortener():
    raw = (
        "From: a@b.com\r\nSubject: Hi\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
        "<a href=\"http://bit.ly/abc123\">click here</a>\r\n"
    )
    ctx = parse_raw_message(raw)
    result = check_body_links(ctx)
    assert result.verdict == "fail"
    assert "shortener" in result.details["types"]


def test_body_links_flags_brand_subdomain_impersonation():
    # github.com.<evil> — brand used as a subdomain of an attacker domain.
    # Visible text carries no domain, so only host-based detection catches it.
    raw = (
        "From: GitHub <noreply@github.com>\r\nSubject: Re: token\r\n"
        "Content-Type: text/html; charset=utf-8\r\n\r\n"
        "<a href=\"https://github.com.sessions-security.com/x\">Review and rotate token</a>\r\n"
    )
    ctx = parse_raw_message(raw)
    result = check_body_links(ctx)
    assert result.verdict == "fail"
    assert "brand_impersonation" in result.details["types"]


def test_body_links_legit_brand_subdomain_passes():
    # app.slack.com is a genuine subdomain of the sender's domain — not impersonation.
    raw = (
        "From: Slack <feedback@slack.com>\r\nSubject: Unread\r\n"
        "Content-Type: text/html; charset=utf-8\r\n\r\n"
        "<a href=\"https://app.slack.com/client\">open Slack</a>\r\n"
    )
    ctx = parse_raw_message(raw)
    result = check_body_links(ctx)
    assert result.verdict == "pass"


def test_body_links_passes_when_clean():
    raw = (
        "From: a@b.com\r\nSubject: Hi\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
        "<a href=\"https://some-business.com/notes\">Ver notas</a>\r\n"
    )
    ctx = parse_raw_message(raw)
    result = check_body_links(ctx)
    assert result.verdict == "pass"


# ------------------------------------------------------- Body links deep URL heuristics (D2)

def test_body_links_flags_userinfo_credential_lure():
    # http://paypal.com@evil.io/ — everything before '@' is attacker text;
    # the browser only ever navigates to the real host after it.
    raw = (
        "From: a@b.com\r\nSubject: Hi\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
        "<a href=\"http://paypal.com@evil.io/login\">Sign in</a>\r\n"
    )
    ctx = parse_raw_message(raw)
    result = check_body_links(ctx)
    assert result.verdict == "fail"
    assert "userinfo_credential_lure" in result.details["types"]


def test_body_links_flags_data_uri_link():
    raw = (
        "From: a@b.com\r\nSubject: Hi\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
        "<a href=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\">Open</a>\r\n"
    )
    ctx = parse_raw_message(raw)
    result = check_body_links(ctx)
    assert result.verdict == "fail"
    assert "data_uri_link" in result.details["types"]


def test_body_links_flags_excessive_subdomains():
    raw = (
        "From: a@b.com\r\nSubject: Hi\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
        "<a href=\"https://click.email.notices.secure-portal-x7.info/x\">Open</a>\r\n"
    )
    ctx = parse_raw_message(raw)
    result = check_body_links(ctx)
    assert result.verdict == "fail"
    assert "excessive_subdomains" in result.details["types"]


def test_body_links_flags_dense_percent_encoding():
    obfuscated = "https://sketchy-host.tk/" + "%2e" * 20
    raw = (
        "From: a@b.com\r\nSubject: Hi\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
        f"<a href=\"{obfuscated}\">Open</a>\r\n"
    )
    ctx = parse_raw_message(raw)
    result = check_body_links(ctx)
    assert result.verdict == "fail"
    assert "dense_encoding" in result.details["types"]


def test_body_links_flags_insecure_credential_page():
    # http (not https) + a credential-harvest keyword on a third-party host.
    raw = (
        "From: a@b.com\r\nSubject: Hi\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
        "<a href=\"http://random-host.tk/account/verify\">Verify now</a>\r\n"
    )
    ctx = parse_raw_message(raw)
    result = check_body_links(ctx)
    assert result.verdict == "fail"
    assert "insecure_credential_page" in result.details["types"]


def test_body_links_flags_credential_harvest_path_over_https():
    raw = (
        "From: a@b.com\r\nSubject: Hi\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
        "<a href=\"https://random-host.tk/account/login\">Log in</a>\r\n"
    )
    ctx = parse_raw_message(raw)
    result = check_body_links(ctx)
    assert result.verdict == "fail"
    assert "credential_harvest_path" in result.details["types"]


def test_body_links_does_not_flag_login_on_senders_own_domain():
    # A company legitimately linking to its own login page must not be
    # penalised just for containing "login" in the path.
    raw = (
        "From: Acme <notices@acme.com>\r\nSubject: Hi\r\n"
        "Content-Type: text/html; charset=utf-8\r\n\r\n"
        "<a href=\"https://acme.com/account/login\">Log in</a>\r\n"
    )
    ctx = parse_raw_message(raw)
    result = check_body_links(ctx)
    assert result.verdict == "pass"


def test_body_links_does_not_flag_login_on_known_brand_domain():
    raw = (
        "From: a@b.com\r\nSubject: Hi\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
        "<a href=\"https://paypal.com/signin\">Sign in to PayPal</a>\r\n"
    )
    ctx = parse_raw_message(raw)
    result = check_body_links(ctx)
    assert result.verdict == "pass"


# --------------------------------------------------------------- Body content (C12)

def test_body_content_neutral_when_empty():
    ctx = MessageContext(headers={})
    result = check_body_content(ctx)
    assert result.verdict == "neutral"


def test_body_content_flags_credential_phrase():
    ctx = MessageContext(headers={}, body_text="Please verify your account immediately.")
    result = check_body_content(ctx)
    assert result.verdict == "fail"
    assert result.score < 0


def test_body_content_flags_hidden_link():
    # Hidden text only counts as evasive when it conceals something that
    # matters — here a hidden hyperlink the victim cannot see.
    ctx = MessageContext(
        headers={},
        body_text="Hello, this is a normal message.",
        body_html='<div style="display:none"><a href="http://evil.example/login">x</a></div>',
    )
    result = check_body_content(ctx)
    assert result.verdict == "fail"
    assert result.details["hidden_text"] is True


def test_body_content_flags_hidden_credential_phrase():
    ctx = MessageContext(
        headers={},
        body_text="Hello",
        body_html='<span style="font-size:0px">verify your password now</span>',
    )
    result = check_body_content(ctx)
    assert result.verdict == "fail"


def test_body_content_ignores_hidden_plain_text():
    # Pure hidden prose with no link/phrase is the legitimate preheader
    # pattern used by virtually every ESP — must NOT be flagged.
    ctx = MessageContext(
        headers={},
        body_text="Hello, this is a normal message.",
        body_html='<div style="display:none">Take a look at your weekly stats.</div>',
    )
    result = check_body_content(ctx)
    assert result.verdict == "pass"


def test_body_content_passes_on_benign_text():
    ctx = MessageContext(headers={}, body_text="Notas de la reunión de mayo, gracias.")
    result = check_body_content(ctx)
    assert result.verdict == "pass"


def test_body_content_ignores_preheader_and_tracking_pixel_inline_styles():
    # Real-world ESP pattern: a hidden "preheader" preview snippet, a
    # zero-size tracking pixel, and a responsive show/hide cell — all
    # inline display:none/font-size:0, none of it scanner-evasion.
    html = (
        '<div class="preheader" style="font-size: 1px; display: none !important;">'
        "Te esperamos!</div>"
        '<div style="font-size:0; line-height:0;"><img src="https://track.example.com/open"></div>'
        '<td class="mobile-only" style="display: none;">'
        '<img src="https://example.com/banner.png"></td>'
    )
    ctx = MessageContext(headers={}, body_text="Hola, nos vemos en el evento.", body_html=html)
    result = check_body_content(ctx)
    assert result.verdict == "pass"
    assert result.score == 0


def test_body_content_ignores_responsive_css_in_style_block():
    # Standard ESP responsive-design CSS (show/hide breakpoints) must not be
    # mistaken for evasive hidden text — it's a stylesheet rule, not content.
    html = (
        "<html><head><style>"
        ".lg-hidden { display: none !important; opacity: 0 !important; }"
        ".sm-hidden { display: table !important; opacity: 1 !important; }"
        "</style></head><body><p>Hola equipo, aquí el boletín de mayo.</p></body></html>"
    )
    ctx = MessageContext(headers={}, body_text="Hola equipo, aquí el boletín de mayo.", body_html=html)
    result = check_body_content(ctx)
    assert result.verdict == "pass"
    assert result.score == 0


# --------------------------------------------------------------- Suspicious attachments (C11)

def test_attachments_falls_back_to_headers_when_no_parts():
    ctx = MessageContext(headers={
        "content-type": "application/octet-stream",
        "content-disposition": 'attachment; filename="invoice.exe"',
    })
    result = check_suspicious_attachments(ctx)
    assert result.verdict == "fail"


def test_attachments_flags_real_dangerous_extension():
    ctx = MessageContext(headers={}, attachments=[
        Attachment(filename="invoice.exe", content_type="application/octet-stream", size=10),
    ])
    result = check_suspicious_attachments(ctx)
    assert result.verdict == "fail"
    assert result.details["findings"][0]["reason"] == "dangerous_extension"


def test_attachments_flags_macro_enabled_document():
    ctx = MessageContext(headers={}, attachments=[
        Attachment(filename="report.docm", content_type="application/vnd.ms-word.document.macroEnabled.12", size=10),
    ])
    result = check_suspicious_attachments(ctx)
    assert result.verdict == "fail"
    assert result.details["findings"][0]["reason"] == "macro_enabled"


def test_attachments_flags_zip_with_executable():
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("payload.exe", b"MZ\x00\x00fake-exe")
    zip_bytes = buf.getvalue()

    ctx = MessageContext(headers={}, attachments=[
        Attachment(filename="archive.zip", content_type="application/zip", size=len(zip_bytes), content=zip_bytes),
    ])
    result = check_suspicious_attachments(ctx)
    assert result.verdict == "fail"
    assert result.details["findings"][0]["reason"] == "archive_contains_executable"


def test_attachments_passes_on_benign_pdf():
    ctx = MessageContext(headers={}, attachments=[
        Attachment(filename="invoice.pdf", content_type="application/pdf", size=10),
    ])
    result = check_suspicious_attachments(ctx)
    assert result.verdict == "pass"


def test_attachments_includes_sha256_and_md5_when_content_present():
    # D8: flagged attachments carry hashes so they're pivotable as IOCs.
    import hashlib
    content = b"MZ\x00\x00fake-exe-content"
    ctx = MessageContext(headers={}, attachments=[
        Attachment(filename="invoice.exe", content_type="application/octet-stream",
                   size=len(content), content=content),
    ])
    result = check_suspicious_attachments(ctx)
    finding = result.details["findings"][0]
    assert finding["sha256"] == hashlib.sha256(content).hexdigest()
    assert finding["md5"] == hashlib.md5(content).hexdigest()


def test_attachments_no_hash_keys_when_content_empty():
    ctx = MessageContext(headers={}, attachments=[
        Attachment(filename="invoice.exe", content_type="application/octet-stream", size=0),
    ])
    result = check_suspicious_attachments(ctx)
    finding = result.details["findings"][0]
    assert "sha256" not in finding
    assert "md5" not in finding
