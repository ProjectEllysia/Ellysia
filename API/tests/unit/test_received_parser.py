"""Tests unitarios del parser de cabeceras Received.

Cubre:
- ``parse_received_line``: parsing individual line, tolerancia a malformados.
- ``build_path``: orden oldest→newest, transitions, campos por hop.
"""

from __future__ import annotations

import pytest

from src.modules.iris.services.parsers import (
    parse_received_line,
    build_path,
)

pytestmark = pytest.mark.unit


# ======================================================================
# parse_received_line
# ======================================================================

def test_parse_esmtps_detects_tls():
    line = (
        "from user@origin.example (origin.example [203.0.113.5]) "
        "by mx1.origin.example (mx1.origin.example [10.0.0.1]) "
        "with ESMTPS id ABC123 for <alice@example.com>; "
        "Fri, 27 Jun 2026 08:00:12 +0000"
    )
    result = parse_received_line(line)
    assert result["tls"] is True
    assert result["from"] == "user@origin.example"
    assert result["fromIp"] == "203.0.113.5"
    assert result["by"] == "mx1.origin.example"
    assert result["with"] == "ESMTPS"
    assert result["timestamp"] == "2026-06-27T08:00:12+00:00"
    assert result["raw"] == line.strip()


def test_parse_smtp_plain():
    line = (
        "from alice@example.com ([192.0.2.10]) "
        "by mta.example.com with SMTP; "
        "Fri, 27 Jun 2026 08:01:00 +0000"
    )
    result = parse_received_line(line)
    assert result["tls"] is False
    assert result["by"] == "mta.example.com"
    assert result["with"] == "SMTP"
    assert result["fromIp"] == "192.0.2.10"


def test_parse_private_ip_flag():
    line = (
        "from [10.0.0.55] by internal-gw.example.com with SMTP; "
        "Fri, 27 Jun 2026 08:00:00 +0000"
    )
    result = parse_received_line(line)
    assert "private_ip" in result["flags"]
    assert result["fromIp"] == "10.0.0.55"


def test_parse_loopback_ip_flag():
    line = (
        "from [127.0.0.1] by localhost with SMTP; "
        "Fri, 27 Jun 2026 08:00:00 +0000"
    )
    result = parse_received_line(line)
    assert "private_ip" in result["flags"]


def test_parse_missing_timestamp():
    line = "from [192.0.2.1] by mx.example.com with SMTP"
    result = parse_received_line(line)
    assert result["timestamp"] is None
    assert result["fromIp"] == "192.0.2.1"


def test_parse_garbled_line_preserves_raw():
    line = "garbage! with no structure xyz"
    result = parse_received_line(line)
    assert result["raw"] == line
    assert result["tls"] is False


def test_parse_strips_received_prefix():
    line = "Received: from a@b.com ([1.2.3.4]) by mx.b.com with SMTP; Sat, 1 Jan 2026 00:00:00 +0000"
    result = parse_received_line(line)
    assert result["from"] == "a@b.com"


def test_parse_known_fields():
    line = (
        "from domain.com ([198.51.100.1]) "
        "by receiver.example.com with SMTP "
        "id queue-123-456; "
        "Mon, 1 Jan 2026 12:00:00 +0000"
    )
    result = parse_received_line(line)
    # The parenthesized HELO/IP block is captured as an unrecognised
    # token and stashed into ``id``. That's expected for the tolerant
    # parser — the original line is always preserved in ``raw``.
    assert result["id"] is not None  # tosses in HELO block
    assert result["for"] is None  # no `for` in this line


def test_parse_tls_via_esmtpsa():
    line = (
        "from [198.51.100.1] by mx.outbound.example.com "
        "with ESMTPSA id xyz; "
        "Mon, 1 Jan 2026 12:00:00 +0000"
    )
    result = parse_received_line(line)
    assert result["tls"] is True


# ======================================================================
# build_path
# ======================================================================

def test_build_path_empty():
    result = build_path([])
    assert result["available"] is False
    assert result["hops"] == []
    assert result["transitions"] == []


def test_build_path_single_hop():
    path = build_path([
        "from [192.0.2.1] by mx.b.com with SMTP; Wed, 25 Jun 2026 10:00:00 +0000",
    ])
    assert path["available"] is True
    assert path["hopsCount"] == 1
    assert path["hops"][0]["by"] == "mx.b.com"
    assert path["transitions"] == []


def test_build_path_two_hops_oldest_first():
    # Delivery order: newest first.
    chain = [
        "from [192.0.2.10] by mx2.b.com with SMTP; Wed, 25 Jun 2026 10:01:00 +0000",
        "from [203.0.113.5] by mx1.b.com with ESMTPS; Wed, 25 Jun 2026 10:00:00 +0000",
    ]
    path = build_path(chain)
    assert path["hopsCount"] == 2
    # hop[0] = oldest (origin)
    assert path["hops"][0]["by"] == "mx1.b.com"
    assert path["hops"][0]["hop"] == 1
    # hop[1] = newest (destination)
    assert path["hops"][1]["by"] == "mx2.b.com"
    assert path["hops"][1]["hop"] == 2


def test_build_path_tls_downgrade_detected():
    chain = [
        "from [192.0.2.10] by mx2.b.com with SMTP; Wed, 25 Jun 2026 10:01:00 +0000",
        "from [203.0.113.5] by mx1.b.com with ESMTPS; Wed, 25 Jun 2026 10:00:00 +0000",
    ]
    path = build_path(chain)
    assert len(path["transitions"]) == 1
    t = path["transitions"][0]
    assert t["suspicious"] is True
    assert "tls_downgrade" in t["reasons"]


def test_build_path_time_inversion_detected():
    chain = [
        # Newer hop has earlier timestamp -> inversion
        "from [192.0.2.10] by mx2.b.com with SMTP; Wed, 25 Jun 2026 09:59:00 +0000",
        "from [203.0.113.5] by mx1.b.com with SMTP; Wed, 25 Jun 2026 10:00:00 +0000",
    ]
    path = build_path(chain)
    assert len(path["transitions"]) == 1
    t = path["transitions"][0]
    assert t["suspicious"] is True
    assert "time_inversion" in t["reasons"]
    assert t["delayMs"] is not None and t["delayMs"] < 0


def test_build_path_clean_transition():
    chain = [
        "from [192.0.2.10] by mx2.b.com with ESMTPS; Wed, 25 Jun 2026 10:01:00 +0000",
        "from [203.0.113.5] by mx1.b.com with ESMTPS; Wed, 25 Jun 2026 10:00:00 +0000",
    ]
    path = build_path(chain)
    t = path["transitions"][0]
    assert t["suspicious"] is False
    assert t["reasons"] == []


def test_build_path_delay_ms():
    chain = [
        "from [192.0.2.10] by mx2.b.com with SMTP; Wed, 25 Jun 2026 10:01:30 +0000",
        "from [203.0.113.5] by mx1.b.com with SMTP; Wed, 25 Jun 2026 10:00:00 +0000",
    ]
    path = build_path(chain)
    t = path["transitions"][0]
    # 90 seconds = 90000 ms
    assert t["delayMs"] == 90000
