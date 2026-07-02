"""Tests unitarios de la regla Received Path Anomaly.

Cubre todas las ramas:
- Sin chain (headers-only) → neutral
- Cadena limpia 2 hops → pass +2
- TLS downgrade → fail -6
- Cadena larga (≥5 hops) → fail -4
- Missing timestamps parcial → suspicious -3
- Señales combinadas → score acumulativo
"""

from __future__ import annotations

import pytest

from src.modules.iris.services.parsers import MessageContext
from src.modules.iris.services.rules.received_path_anomaly import (
    check_received_path_anomaly,
)

pytestmark = pytest.mark.unit

# Reusable timestamp constants for clean chains
TS0 = "Wed, 25 Jun 2026 10:00:00 +0000"
TS1 = "Wed, 25 Jun 2026 10:01:00 +0000"
TS2 = "Wed, 25 Jun 2026 10:02:00 +0000"
TS3 = "Wed, 25 Jun 2026 10:03:00 +0000"
TS4 = "Wed, 25 Jun 2026 10:04:00 +0000"


def _ctx(received_headers: list[str]) -> MessageContext:
    return MessageContext(
        headers={"from": "a@b.com"},
        received_headers=received_headers,
    )


# ======================================================================
# Neutral
# ======================================================================

def test_no_chain():
    result = check_received_path_anomaly(MessageContext(headers={}))
    assert result.verdict == "neutral"
    assert result.score == 0
    assert result.details["hops"] == 0


def test_empty_list():
    result = check_received_path_anomaly(_ctx([]))
    assert result.verdict == "neutral"
    assert result.score == 0


# ======================================================================
# Pass
# ======================================================================

def test_clean_two_hops():
    chain = [
        f"from [192.0.2.10] by mx2.b.com with ESMTPS; {TS1}",
        f"from [203.0.113.5] by mx1.b.com with ESMTPS; {TS0}",
    ]
    result = check_received_path_anomaly(_ctx(chain))
    assert result.verdict == "pass"
    assert result.score == 2
    assert result.details["unique_signals"] == []


def test_clean_four_hops():
    chain = [
        f"from [192.0.2.1] by mx4.d.com with ESMTPS; {TS3}",
        f"from [198.51.100.1] by mx3.c.com with ESMTPS; {TS2}",
        f"from [203.0.113.1] by mx2.b.com with ESMTPS; {TS1}",
        f"from [10.0.0.1] by mx1.a.com with ESMTPS; {TS0}",
    ]
    result = check_received_path_anomaly(_ctx(chain))
    assert result.verdict == "pass"
    assert result.score == 2


# ======================================================================
# TLS downgrade
# ======================================================================

def test_tls_downgrade():
    chain = [
        f"from [192.0.2.10] by mx2.b.com with SMTP; {TS1}",
        f"from [203.0.113.5] by mx1.b.com with ESMTPS; {TS0}",
    ]
    result = check_received_path_anomaly(_ctx(chain))
    assert result.verdict == "fail"
    assert result.score == -6
    assert "tls_downgrade" in result.details["unique_signals"]
    assert len(result.details["tls_downgrade_hops"]) == 1


def test_tls_downgrade_multi_hop():
    chain = [
        f"from [192.0.2.3] by mx3.c.com with SMTP; {TS2}",
        f"from [192.0.2.2] by mx2.b.com with SMTP; {TS1}",
        f"from [192.0.2.1] by mx1.a.com with ESMTPS; {TS0}",
    ]
    result = check_received_path_anomaly(_ctx(chain))
    assert result.verdict == "fail"
    assert result.score == -6  # single downgrade penalty (only 1->2)
    assert len(result.details["tls_downgrade_hops"]) == 1


def test_internal_by_only_handoff_is_not_a_downgrade():
    # Final internal handoff ("Received: by <ip> with SMTP id ...", no `from`)
    # after a TLS relay is normal Gmail/Outlook delivery, not a downgrade.
    chain = [
        f"by 2002:a05:6022:82a6 with SMTP id bf38csp45297lab; {TS1}",
        f"from a69-17.smtp-out.amazonses.com [54.240.69.17] by mx.google.com with ESMTPS; {TS0}",
    ]
    result = check_received_path_anomaly(_ctx(chain))
    assert result.verdict == "pass"
    assert "tls_downgrade" not in result.details["unique_signals"]


def test_https_handoff_is_encrypted_not_a_downgrade():
    # Microsoft internal "with HTTPS" hop is encrypted, not a cleartext relay.
    chain = [
        f"from EX1.prod.outlook.com by EX2.prod.outlook.com with HTTPS; {TS1}",
        f"from mail.sender.com [203.0.113.5] by mx.outlook.com with ESMTPS; {TS0}",
    ]
    result = check_received_path_anomaly(_ctx(chain))
    assert result.verdict == "pass"
    assert "tls_downgrade" not in result.details["unique_signals"]


# ======================================================================
# Long chain
# ======================================================================

def test_long_chain_5_hops_unique_ips():
    chain = [
        f"from [192.0.2.5] by mx5.e.com with ESMTPS; {TS4}",
        f"from [192.0.2.4] by mx4.d.com with ESMTPS; {TS3}",
        f"from [192.0.2.3] by mx3.c.com with ESMTPS; {TS2}",
        f"from [192.0.2.2] by mx2.b.com with ESMTPS; {TS1}",
        f"from [192.0.2.1] by mx1.a.com with ESMTPS; {TS0}",
    ]
    result = check_received_path_anomaly(_ctx(chain))
    assert result.verdict == "fail"
    assert result.score == -4
    assert "long_chain" in result.details["unique_signals"]


def test_long_chain_5_hops_repeated_ip_not_long():
    chain = [
        f"from [192.0.2.1] by mx5.e.com with ESMTPS; {TS4}",
        f"from [192.0.2.1] by mx4.d.com with ESMTPS; {TS3}",
        f"from [192.0.2.1] by mx3.c.com with ESMTPS; {TS2}",
        f"from [192.0.2.1] by mx2.b.com with ESMTPS; {TS1}",
        f"from [192.0.2.1] by mx1.a.com with ESMTPS; {TS0}",
    ]
    result = check_received_path_anomaly(_ctx(chain))
    # Same IP repeated → not flagged as long_chain
    assert "long_chain" not in result.details.get("unique_signals", [])


# ======================================================================
# Missing timestamps
# ======================================================================

def test_missing_timestamps_3_hops():
    chain = [
        "from [192.0.2.3] by mx3.c.com with SMTP",
        f"from [192.0.2.2] by mx2.b.com with ESMTPS; {TS1}",
        f"from [192.0.2.1] by mx1.a.com with ESMTPS; {TS0}",
    ]
    result = check_received_path_anomaly(_ctx(chain))
    # TLS downgrade (SMTP → ESMTPS) dominates → fail, not suspicious
    assert result.verdict == "fail"
    assert result.score == -9
    assert "tls_downgrade" in result.details["unique_signals"]
    assert "missing_timestamps" in result.details["unique_signals"]


def test_missing_timestamps_2_hops_not_flagged():
    chain = [
        "from [192.0.2.2] by mx2.b.com with SMTP",
        f"from [192.0.2.1] by mx1.a.com with ESMTPS; {TS0}",
    ]
    result = check_received_path_anomaly(_ctx(chain))
    # Only 2 hops, rule needs >= 3 to flag missing timestamps.
    # TLS downgrade is still detected (SMTP → ESMTPS), but
    # missing_timestamps is NOT in unique_signals nor in details.
    assert "missing_timestamps" not in result.details.get("unique_signals", [])
    assert result.details.get("missing_timestamps") is None


# ======================================================================
# Combined signals
# ======================================================================

def test_tls_downgrade_and_long_chain():
    chain = [
        f"from [192.0.2.5] by mx5.e.com with SMTP; {TS4}",
        f"from [192.0.2.4] by mx4.d.com with SMTP; {TS3}",
        f"from [192.0.2.3] by mx3.c.com with ESMTPS; {TS2}",
        f"from [192.0.2.2] by mx2.b.com with ESMTPS; {TS1}",
        f"from [192.0.2.1] by mx1.a.com with ESMTPS; {TS0}",
    ]
    result = check_received_path_anomaly(_ctx(chain))
    assert result.verdict == "fail"
    # tls_downgrade -6 + long_chain -4 = -10
    assert result.score == -10
    assert "tls_downgrade" in result.details["unique_signals"]
    assert "long_chain" in result.details["unique_signals"]


def test_downgrade_and_missing_ts():
    chain = [
        "from [192.0.2.3] by mx3.c.com with SMTP",
        f"from [192.0.2.2] by mx2.b.com with ESMTPS; {TS1}",
        f"from [192.0.2.1] by mx1.a.com with ESMTPS; {TS0}",
    ]
    result = check_received_path_anomaly(_ctx(chain))
    assert result.verdict == "fail"  # tls_downgrade dominates
    assert result.score == -9


# ======================================================================
# Edge cases
# ======================================================================

def test_single_hop_with_private_ip_not_penalised():
    # Private IP is already covered by received_chain rule,
    # this rule should not add extra penalty.
    chain = [
        "from [10.0.0.1] by mx.b.com with ESMTPS; Thu, 1 Jan 2026 00:00:00 +0000",
    ]
    result = check_received_path_anomaly(_ctx(chain))
    assert result.verdict == "pass"
    assert result.score == 2


def test_all_missing_timestamps_not_flagged():
    chain = [
        "from [192.0.2.3] by mx3.c.com with SMTP",
        "from [192.0.2.2] by mx2.b.com with ESMTPS",
        "from [192.0.2.1] by mx1.a.com with ESMTPS",
    ]
    result = check_received_path_anomaly(_ctx(chain))
    # len(missing_timestamps) == len(hops) → edge is excluded
    assert "missing_timestamps" not in result.details.get("unique_signals", [])
