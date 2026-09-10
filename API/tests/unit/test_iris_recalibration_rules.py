"""Tests de las reglas/gates nuevos de la recalibración de pesos de Iris:

- Auth Results Provenance (G-A): authserv-id ↔ último `by` del Received.
- Recipient Domain Lookalike (G-B): lookalike del dominio del destinatario.
- Display Name Foreign Address (G-C): display name que ES una dirección
  de otro dominio.
- TOAD Callback Pattern (G-D): teléfono + lenguaje de pago sin
  enlaces/adjuntos/hilo previo.
- External Login Link (G-E): señal informativa para el combo con
  Alarming Keywords.

Cada regla se prueba en aislamiento (igual que ``test_iris_message_parser.py``)
y los gates de ``managers.py`` que las consumen se prueban con los helpers
``_rr``/``_gated`` de ``test_iris_rules.py``.
"""

from __future__ import annotations

import pytest

from src.modules.features.iris.managers import IrisManager
from src.modules.features.iris.services.parsers import MessageContext, Link
from src.modules.features.iris.services.rules.auth_rules import check_auth_results_provenance
from src.modules.features.iris.services.rules.body_content_rules import check_toad_callback_pattern
from src.modules.features.iris.services.rules.body_links_rules import check_external_login_link
from src.modules.features.iris.services.rules.received_timing_rules import check_origin_helo_coherence
from src.modules.features.iris.services.rules.sender_identity_rules import (
    check_display_name_foreign_address,
    check_recipient_domain_lookalike,
)
from src.modules.features.iris.services.rules.thread_rules import check_msgid_received_correlation

pytestmark = pytest.mark.unit


def _gated(base_verdict, named):
    verdict, reasons = IrisManager._apply_verdict_gates(base_verdict, named)
    return verdict, reasons


# --------------------------------------------------------------- G-A: Auth Results Provenance

def test_auth_provenance_flags_authserv_absent_from_received_chain():
    ctx = MessageContext(
        headers={
            "authentication-results": "attacker.example; spf=pass; dkim=pass; dmarc=pass",
        },
        received_headers=[
            "from mx-in.realcompany.com by mx2.realcompany.com; Wed, 25 Jun 2025 10:00:00 +0000",
            "from smtp.sender.com by mx-in.realcompany.com; Wed, 25 Jun 2025 09:59:00 +0000",
        ],
    )
    result = check_auth_results_provenance(ctx)
    assert result.verdict == "fail"
    assert result.score < 0


def test_auth_provenance_passes_when_authserv_matches_received_by():
    ctx = MessageContext(
        headers={
            "authentication-results": "mx2.realcompany.com; spf=pass; dkim=pass; dmarc=pass",
        },
        received_headers=[
            "from mx-in.realcompany.com by mx2.realcompany.com; Wed, 25 Jun 2025 10:00:00 +0000",
        ],
    )
    result = check_auth_results_provenance(ctx)
    assert result.verdict == "pass"


def test_auth_provenance_neutral_without_received_chain():
    # Sin cadena Received que verificar, no hay base para acusar de forjado.
    ctx = MessageContext(
        headers={"authentication-results": "attacker.example; spf=pass"},
        received_headers=[],
    )
    result = check_auth_results_provenance(ctx)
    assert result.verdict == "neutral"
    assert result.score == 0


def test_auth_provenance_neutral_when_m365_omits_authserv_id():
    # Calibración FP: Exchange Online emite la cabecera SIN authserv-id, así
    # que el token anterior al primer `;` es el propio resultado SPF. Contiene
    # puntos (el dominio del smtp.mailfrom), por lo que se colaba como
    # "hostname" y la regla acusaba de forjada una cabecera legítima.
    ctx = MessageContext(
        headers={
            "authentication-results": (
                "spf=pass (sender ip is 204.220.183.7) "
                "smtp.mailfrom=ops.mg.holistics.io; dkim=pass "
                "header.d=holistics.io; dmarc=pass header.from=holistics.io"
            ),
        },
        received_headers=[
            "from DU7PR01CA0032.eurprd01.prod.exchangelabs.com by "
            "VI0P193MB2694.EURP193.PROD.OUTLOOK.COM; Wed, 25 Jun 2025 10:00:00 +0000",
        ],
    )
    result = check_auth_results_provenance(ctx)
    assert result.verdict == "neutral"
    assert result.score == 0


def test_auth_provenance_neutral_when_nothing_claims_pass():
    ctx = MessageContext(
        headers={"authentication-results": "attacker.example; spf=fail; dmarc=fail"},
        received_headers=["from a by b.example.com; Wed, 25 Jun 2025 10:00:00 +0000"],
    )
    result = check_auth_results_provenance(ctx)
    assert result.verdict == "neutral"


def test_gate_auth_forged_escalates_to_phishing():
    named = {"Auth Results Provenance": type(
        "R", (), {"verdict": "fail", "details": {}, "score": -12},
    )()}
    verdict, reasons = _gated("Legitimate", named)
    assert verdict == "Phishing"
    assert reasons


# --------------------------------------------------------------- G-B: Recipient Domain Lookalike

def test_recipient_lookalike_flags_typo_of_recipient_domain():
    headers = {
        "from": "it-support@exampl.com",
        "to": "employee@example.com",
    }
    result = check_recipient_domain_lookalike(headers)
    assert result.verdict == "fail"
    assert result.details["type"] == "typo"


def test_recipient_lookalike_passes_on_same_domain():
    headers = {"from": "it@example.com", "to": "employee@example.com"}
    result = check_recipient_domain_lookalike(headers)
    assert result.verdict == "neutral"


def test_recipient_lookalike_ignores_free_provider_recipient():
    headers = {"from": "it-support@gmai1.com", "to": "someone@gmail.com"}
    result = check_recipient_domain_lookalike(headers)
    assert result.verdict == "neutral"


def test_gate_recipient_lookalike_escalates_to_phishing():
    named = {"Recipient Domain Lookalike": type("R", (), {"verdict": "fail", "details": {}, "score": -18})()}
    verdict, reasons = _gated("Legitimate", named)
    assert verdict == "Phishing"


# --------------------------------------------------------------- G-C: Display Name Foreign Address

def test_display_name_foreign_address_flags_email_in_display_name():
    headers = {"from": '"ceo@acme.com" <attacker@evil.com>'}
    result = check_display_name_foreign_address(headers)
    assert result.verdict == "fail"
    assert result.details["display_domain"] == "acme.com"
    assert result.details["from_domain"] == "evil.com"


def test_display_name_foreign_address_impersonates_recipient_escalates():
    headers = {
        "from": '"ceo@acme.com" <attacker@evil.com>',
        "to": "employee@acme.com",
    }
    result = check_display_name_foreign_address(headers)
    assert result.verdict == "fail"
    assert result.details["impersonates_target"] is True


def test_display_name_foreign_address_neutral_on_plain_name():
    headers = {"from": '"Acme Support" <support@acme.com>'}
    result = check_display_name_foreign_address(headers)
    assert result.verdict == "neutral"


def test_gate_display_foreign_impersonation_escalates_to_phishing():
    named = {"Display Name Foreign Address": type(
        "R", (), {"verdict": "fail", "details": {"impersonates_target": True}, "score": -10},
    )()}
    verdict, reasons = _gated("Legitimate", named)
    assert verdict == "Phishing"


def test_gate_display_foreign_without_impersonation_only_suspicious():
    named = {"Display Name Foreign Address": type(
        "R", (), {"verdict": "fail", "details": {"impersonates_target": False}, "score": -10},
    )()}
    verdict, reasons = _gated("Legitimate", named)
    assert verdict == "Suspicious"


# --------------------------------------------------------------- G-D: TOAD Callback Pattern

def test_toad_callback_flags_phone_and_billing_language_without_links():
    ctx = MessageContext(
        headers={},
        body_text=(
            "Your subscription has been auto-renewed. If you did not authorize this "
            "unrecognized charge, call us at +1 (800) 555-0134 to cancel."
        ),
    )
    result = check_toad_callback_pattern(ctx)
    assert result.verdict == "fail"
    assert result.score < 0


def test_toad_callback_neutral_with_prior_thread():
    ctx = MessageContext(
        headers={"in-reply-to": "<abc@example.com>"},
        body_text="Your subscription renewed. Call +1 (800) 555-0134 to cancel.",
    )
    result = check_toad_callback_pattern(ctx)
    assert result.verdict == "neutral"


def test_toad_callback_passes_when_links_present():
    ctx = MessageContext(
        headers={},
        body_text="Your subscription renewed. Call +1 (800) 555-0134 to cancel.",
        links=[Link(href="https://example.com/manage", text="Manage subscription")],
    )
    result = check_toad_callback_pattern(ctx)
    assert result.verdict == "pass"


def test_toad_callback_passes_without_billing_keywords():
    ctx = MessageContext(
        headers={},
        body_text="Give us a call sometime at +1 (800) 555-0134, we miss you!",
    )
    result = check_toad_callback_pattern(ctx)
    assert result.verdict == "pass"


# --------------------------------------------------------------- G-E: External Login Link

def test_external_login_link_flags_non_esp_foreign_host():
    ctx = MessageContext(
        headers={"from": "alerts@acme.com"},
        links=[Link(href="https://acme-secure-login.example.net/verify", text="Verify")],
    )
    result = check_external_login_link(ctx)
    assert result.verdict == "fail"
    assert result.score == 0  # informational only, all scoring stays in Body Links


def test_external_login_link_passes_for_sender_domain():
    ctx = MessageContext(
        headers={"from": "alerts@acme.com"},
        links=[Link(href="https://acme.com/account", text="My account")],
    )
    result = check_external_login_link(ctx)
    assert result.verdict == "pass"


def test_gate_external_login_link_only_fires_with_alarming_strong():
    r_fail = type("R", (), {"verdict": "fail", "details": {}, "score": 0})()
    r_alarming = type("R", (), {"verdict": "alarming_high", "details": {}, "score": -15})()
    r_alarming_low = type("R", (), {"verdict": "alarming_low", "details": {}, "score": -5})()

    # Sin urgencia fuerte, el enlace externo por sí solo no gatea.
    verdict, _ = _gated("Legitimate", {"External Login Link": r_fail})
    assert verdict == "Legitimate"

    # Urgencia fuerte sin enlace externo tampoco gatea por esta vía.
    verdict, _ = _gated("Legitimate", {"Alarming Keywords": r_alarming})
    assert verdict == "Legitimate"

    # Los dos juntos sí.
    verdict, reasons = _gated(
        "Legitimate", {"External Login Link": r_fail, "Alarming Keywords": r_alarming},
    )
    assert verdict == "Suspicious"
    assert reasons

    # Urgencia débil (low) no cuenta como alarming_strong.
    verdict, _ = _gated(
        "Legitimate", {"External Login Link": r_fail, "Alarming Keywords": r_alarming_low},
    )
    assert verdict == "Legitimate"


# --------------------------------------------------------------- Message-ID Received Correlation

def test_msgid_correlation_flags_domain_absent_from_chain():
    ctx = MessageContext(
        headers={"message-id": "<abc123@attacker-infra.example>"},
        received_headers=[
            "from mx-in.realcompany.com by mx2.realcompany.com; Wed, 25 Jun 2025 10:00:00 +0000",
        ],
    )
    result = check_msgid_received_correlation(ctx)
    assert result.verdict == "fail"
    assert result.score < 0


def test_msgid_correlation_passes_when_domain_in_chain():
    ctx = MessageContext(
        headers={"message-id": "<abc123@mx2.realcompany.com>"},
        received_headers=[
            "from mx-in.realcompany.com by mx2.realcompany.com; Wed, 25 Jun 2025 10:00:00 +0000",
        ],
    )
    result = check_msgid_received_correlation(ctx)
    assert result.verdict == "pass"


def test_msgid_correlation_exempts_known_esp():
    ctx = MessageContext(
        headers={"message-id": "<abc123@amazonses.com>"},
        received_headers=[
            "from mx-in.realcompany.com by mx2.realcompany.com; Wed, 25 Jun 2025 10:00:00 +0000",
        ],
    )
    result = check_msgid_received_correlation(ctx)
    assert result.verdict == "pass"
    assert result.details.get("esp") is True


# --------------------------------------------------------------- Origin HELO Coherence

def test_origin_helo_flags_domain_matching_nothing_else():
    ctx = MessageContext(
        headers={"from": "billing@realcompany.com", "message-id": "<x@realcompany.com>"},
        received_headers=[
            "from mx-in.realcompany.com by mx2.realcompany.com; Wed, 25 Jun 2025 10:00:00 +0000",
            "from totally-unrelated-infra.example by mx-in.realcompany.com; Wed, 25 Jun 2025 09:59:00 +0000",
        ],
    )
    result = check_origin_helo_coherence(ctx)
    assert result.verdict == "fail"


def test_origin_helo_passes_when_it_matches_from_domain():
    ctx = MessageContext(
        headers={"from": "billing@realcompany.com"},
        received_headers=[
            "from mail.realcompany.com by mx.realcompany.com; Wed, 25 Jun 2025 10:00:00 +0000",
        ],
    )
    result = check_origin_helo_coherence(ctx)
    assert result.verdict == "pass"


def test_gate_origin_helo_mismatch_requires_auth_fail_combo():
    r_fail = type("R", (), {"verdict": "fail", "details": {}, "score": -5})()
    r_spf_fail = type("R", (), {"verdict": "fail", "details": {}, "score": -20})()

    # Sin fallo de auth, el mismatch de HELO por sí solo no gatea (ruidoso).
    verdict, _ = _gated("Legitimate", {"Origin HELO Coherence": r_fail})
    assert verdict == "Legitimate"

    # Combinado con SPF fail, sí.
    verdict, reasons = _gated(
        "Legitimate", {"Origin HELO Coherence": r_fail, "SPF": r_spf_fail},
    )
    assert verdict == "Suspicious"
    assert reasons
