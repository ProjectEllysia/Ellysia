"""
Timestamp and Received-chain rules — does the mail's timing/routing
evidence hold together?

- **Date Header Anomaly**: the ``Date:`` header itself is missing,
  unparseable, or wildly in the future/past.
- **Received Chain**: hop count, a private/internal origin IP leaking
  through, and a Date-vs-first-hop timestamp mismatch.
- **Received Chain Temporal Inconsistency**: hop timestamps are not
  monotonically increasing origin -> destination (RFC 5321 §4.4
  violation — a hop was fabricated/reordered).
- **Received Path Anomaly**: TLS downgrades between hops, excessively
  long chains, and unparseable timestamps.

The three Received-chain rules are deliberately layered to avoid
double-counting: each docstring below states exactly which signals it
owns so a single anomaly is never scored by more than one rule.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from typing import List

import src.modules.system.config_reading as CR
from ..registry import iris_rules, RuleResult
from ..parsers import _hop_timestamp, _is_private_ip, build_path, parse_received_line
from ..shared import extract_domain, registrable_domain

MAX_FUTURE_DAYS = 1
MAX_PAST_DAYS = 365

# Recalibración de pesos: margen de clock skew entre hops consecutivos de
# la cadena Received antes de considerar una inversión temporal real.
CLOCK_SKEW_TOLERANCE_SECONDS = 300


@iris_rules.register(
    name="Date Header Anomaly", category="header_analysis", family="received",
    description="Detecta si la cabecera Date está ausente, en el futuro lejano o en el pasado remoto",
)
def check_date_anomaly(headers: dict) -> RuleResult:
    date_str = headers.get("date", "")

    if not date_str or not date_str.strip():
        return RuleResult(
            score=CR.get_iris_scoring_weight("date_anomaly.missing", -2), verdict="missing",  # recalibración de pesos
            details={"date": "missing"},
            recommendation="La cabecera Date está ausente. Los correos legítimos siempre incluyen "
                           "una marca de tiempo. Esto puede indicar un correo generado automáticamente "
                           "o malicioso.",
        )

    try:
        parsed = parsedate_to_datetime(date_str)
    except (ValueError, TypeError, OverflowError):
        return RuleResult(
            score=CR.get_iris_scoring_weight("date_anomaly.unparseable", -4), verdict="unparseable",
            details={"date": date_str},
            recommendation=f"No se pudo interpretar la cabecera Date: '{date_str}'. "
                           "Un formato de fecha inválido es sospechoso y puede indicar "
                           "manipulación intencional.",
        )

    now = datetime.now(timezone.utc)

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    if parsed > now + timedelta(days=MAX_FUTURE_DAYS):
        future_days = (parsed - now).days
        return RuleResult(
            score=CR.get_iris_scoring_weight("date_anomaly.future", -4), verdict="future",
            details={
                "date": date_str,
                "parsed": parsed.isoformat(),
                "days_in_future": future_days,
            },
            recommendation=f"La fecha del correo está {future_days} días en el futuro "
                           f"({parsed.strftime('%Y-%m-%d %H:%M UTC')}). "
                           "Los servidores legítimos tienen relojes precisos; "
                           "una fecha futura indica manipulación o spoofing.",
        )

    if parsed < now - timedelta(days=MAX_PAST_DAYS):
        past_days = (now - parsed).days
        return RuleResult(
            score=0, verdict="past",  # recalibración de pesos -- solo "future" es señal real (SOC)
            details={
                "date": date_str,
                "parsed": parsed.isoformat(),
                "days_in_past": past_days,
            },
            recommendation=f"La fecha del correo está hace {past_days} días "
                           f"({parsed.strftime('%Y-%m-%d %H:%M UTC')}). "
                           "Correos legítimos antiguos no son comunes; "
                           "podría ser un intento de phishing con plantillas reutilizadas.",
        )

    return RuleResult(
        score=1, verdict="pass",
        details={"date": date_str, "parsed": parsed.isoformat()},
        recommendation=None,
    )


_IP_RE = re.compile(r"\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?")


@iris_rules.register(
    name="Received Chain", category="header_analysis", family="received",
    description=(
        "Analiza la cadena completa de cabeceras Received: número de saltos, "
        "IP de origen privada/interna, y consistencia temporal con Date."
    ),
    needs_context=True,
)
def check_received_chain(context) -> RuleResult:
    received = context.received_headers
    headers = context.headers

    if not received:
        return RuleResult(
            score=0, verdict="neutral",
            details={"hops": 0, "reason": "no Received chain available"},
        )

    findings: list[str] = []
    score = 0

    # Recalibración de pesos: una cadena que nunca salió de RFC1918 es un
    # relay corporativo interno normal -- un correo interno SIEMPRE nace en
    # un Exchange/relay 10.x, así que una IP de origen privada solo es
    # anómala cuando el resto de la cadena sugiere un origen externo.
    # `check_received_path_anomaly` ya aplica esta misma exención para
    # tls_downgrade/long_chain; replicarla aquí para el mismo hecho evita
    # que las dos reglas se contradigan sobre si "interno" es normal.
    hop_ips = [h.get("fromIp") for h in build_path(received)["hops"] if h.get("fromIp")]
    all_internal = bool(hop_ips) and all(_is_private_ip(ip) for ip in hop_ips)

    origin_hop = received[-1]
    ip_match = _IP_RE.search(origin_hop)
    if ip_match and _is_private_ip(ip_match.group(1)) and not all_internal:
        findings.append(f"IP de origen privada/interna: {ip_match.group(1)}")
        score += CR.get_iris_scoring_weight("received_chain.private_origin_ip", -5)

    date_header = headers.get("date", "")
    top_ts = _hop_timestamp(received[0])
    try:
        date_ts = parsedate_to_datetime(date_header) if date_header else None
    except (TypeError, ValueError, IndexError):
        date_ts = None

    if top_ts is not None and date_ts is not None:
        delta_hours = abs((top_ts - date_ts).total_seconds()) / 3600
        if delta_hours > 6:
            findings.append(
                f"Desfase de {delta_hours:.1f}h entre Date y el primer salto Received"
            )
            score += CR.get_iris_scoring_weight("received_chain.date_mismatch", -3)  # recalibración de pesos

    if not findings:
        return RuleResult(score=1, verdict="pass", details={"hops": len(received)})

    return RuleResult(
        score=score, verdict="fail",
        details={"hops": len(received), "findings": findings},
        recommendation="La cadena Received presenta anomalías: " + "; ".join(findings),
    )


@iris_rules.register(
    name="Received Chain Temporal Inconsistency",
    category="header_analysis", family="received",
    description=(
        "Detecta cadenas Received: con marcas de tiempo no monótonamente "
        "crecientes desde el origen hasta el destino, una firma de "
        "manipulación o fabricación de cabeceras."
    ),
    needs_context=True,
)
def check_received_chain_temporal_inconsistency(context) -> RuleResult:
    """RFC 5321 §4.4: Received lines are prepended, so ``received[0]`` is the
    final (newest) hop and ``received[-1]`` is the origin (oldest) — reading
    from ``[-1]`` to ``[0]`` timestamps must be monotonically increasing.
    A failure means at least one hop forged its line.
    """
    received = context.received_headers or []
    if len(received) < 2:
        return RuleResult(
            score=0, verdict="neutral",
            details={"hops": len(received), "reason": "chain too short"},
        )

    timestamps = [_hop_timestamp(line) for line in received]
    parsed_count = sum(1 for t in timestamps if t is not None)
    if parsed_count < 2:
        return RuleResult(
            score=0, verdict="neutral",
            details={"hops": len(received), "reason": "could not parse enough timestamps"},
        )

    # Origin (oldest) is the last entry; destination (newest) is the first.
    # We expect timestamps[0] >= timestamps[1] >= ... >= timestamps[-1].
    # Recalibración de pesos: tolerancia de 300s -- dos servidores con
    # relojes no perfectamente sincronizados (clock skew) pueden producir
    # una inversión de unos segundos entre hops consecutivos sin que haya
    # manipulación real; solo una inversión que exceda ese margen es señal.
    inversions: list[dict] = []
    for i in range(len(timestamps) - 1):
        a, b = timestamps[i], timestamps[i + 1]
        if a is None or b is None:
            continue
        delta = (b - a).total_seconds()
        if delta >= CLOCK_SKEW_TOLERANCE_SECONDS:
            inversions.append({
                "from_hop": i,
                "to_hop": i + 1,
                "delta_seconds": int(delta),
            })

    if not inversions:
        return RuleResult(
            score=1, verdict="pass",
            details={"hops": len(received), "parsed": parsed_count},
            recommendation=None,
        )

    score = (
        CR.get_iris_scoring_weight("received_chain_temporal.single_inversion", -8)
        if len(inversions) == 1
        else CR.get_iris_scoring_weight("received_chain_temporal.multi_inversion", -12)
    )  # recalibración de pesos -- gatea (received_time_inversion)

    return RuleResult(
        score=score, verdict="fail",
        details={
            "hops": len(received),
            "parsed_timestamps": parsed_count,
            "inversions": inversions,
        },
        recommendation=(
            f"La cadena Received: contiene {len(inversions)} inversión(es) "
            "temporal(es) — los hops no están en orden cronológico "
            "ascendente desde el origen al destino. RFC 5321 §4.4 prohíbe "
            "este patrón, que solo aparece cuando una cabecera ha sido "
            "fabricada o manipulada. Combinado con otras señales, es un "
            "indicador fuerte de spoofing."
        ),
    )


LONG_CHAIN_THRESHOLD = 5
MISSING_TS_MIN_HOPS = 3


@iris_rules.register(
    name="Received Path Anomaly",
    category="header_analysis", family="received",
    description=(
        "Evalúa el recorrido Received: del correo — número de saltos, "
        "downgrades TLS entre hops, cadenas excesivamente largas y "
        "timestamps no parseables. Señales complementarias a las "
        "reglas de Received Chain existentes (no double-counting)."
    ),
    needs_context=True,
)
def check_received_path_anomaly(context) -> RuleResult:
    """Consumes the parsed Received chain and contributes only the signals
    the two rules above do NOT already cover: TLS downgrades between
    consecutive hops, excessively long chains (>= 5 hops with mostly
    unique IPs), and hops with unparseable timestamps when the rest of
    the chain has them. A clean, short, fully-encrypted path earns a
    small positive bonus.
    """
    received = context.received_headers or []
    if not received:
        return RuleResult(
            score=0, verdict="neutral",
            details={"hops": 0, "reason": "no Received chain available"},
        )

    path = build_path(received)
    hops: List[dict] = path["hops"]
    transitions: List[dict] = path["transitions"]
    unique_signals: List[str] = []

    # F3 (Received cluster): a chain that never left RFC1918 space is an
    # internal corporate relay path — 5+ hops through internal load
    # balancers/gateways is completely normal there, and TLS between two
    # hosts on the same private network is not the "downgrade" this rule
    # means to catch. Only exempt tls_downgrade/long_chain (not the
    # missing_timestamps signal below, which is unrelated) when every hop
    # that *does* expose an IP is private; an unparseable/absent IP on
    # some hops shouldn't itself defeat the exemption.
    hop_ips = [h.get("fromIp") for h in hops if h.get("fromIp")]
    all_internal = bool(hop_ips) and all(_is_private_ip(ip) for ip in hop_ips)

    # --- TLS downgrade between consecutive hops ---
    tls_downgrade_pairs: List[dict] = [
        {"from": t["from"], "to": t["to"]}
        for t in transitions
        if "tls_downgrade" in t.get("reasons", [])
    ] if not all_internal else []
    if tls_downgrade_pairs:
        unique_signals.append("tls_downgrade")

    # --- Long chain (>= 5 hops with mostly unique IPs) ---
    long_chain = False
    if not all_internal and len(hops) >= LONG_CHAIN_THRESHOLD:
        ips = [h.get("fromIp") for h in hops if h.get("fromIp")]
        if len(set(ips)) >= max(3, int(0.6 * len(hops))):
            long_chain = True
            unique_signals.append("long_chain")

    # --- Missing timestamps ---
    missing_timestamps: List[int] = [
        h["hop"] for h in hops if not h.get("timestamp")
    ]
    if (
        len(hops) >= MISSING_TS_MIN_HOPS
        and missing_timestamps
        and len(missing_timestamps) < len(hops)
    ):
        unique_signals.append("missing_timestamps")

    # --- Score ---
    if not unique_signals:
        # Clean, short path -> small positive bonus.
        score = 2
        verdict = "pass"
        recommendation = None
    else:
        score = 0
        if "tls_downgrade" in unique_signals:
            score += CR.get_iris_scoring_weight("received_path_anomaly.tls_downgrade", -4)  # recalibración de pesos
        if "long_chain" in unique_signals:
            score += CR.get_iris_scoring_weight("received_path_anomaly.long_chain", -3)  # recalibración de pesos
        if "missing_timestamps" in unique_signals:
            score += CR.get_iris_scoring_weight("received_path_anomaly.missing_timestamps", 0)  # recalibración de pesos

        # Soft-fail vs hard-fail: tls_downgrade is a stronger signal
        # than just missing timestamps.
        if "tls_downgrade" in unique_signals or "long_chain" in unique_signals:
            verdict = "fail"
        else:
            verdict = "suspicious"

        reasons = {
            "tls_downgrade": "al menos un salto perdió TLS al reenviar",
            "long_chain": "cadena Received inusualmente larga",
            "missing_timestamps": "algunos hops no exponen timestamp parseable",
        }
        msg = "; ".join(reasons[s] for s in unique_signals)
        recommendation = (
            "El recorrido Received presenta anomalías: " + msg + "."
        )

    details = {
        "hops": len(hops),
        "unique_signals": unique_signals,
        "transitions_evaluated": len(transitions),
    }
    if "tls_downgrade" in unique_signals:
        details["tls_downgrade_hops"] = tls_downgrade_pairs
    if "long_chain" in unique_signals:
        details["long_chain"] = True
    if "missing_timestamps" in unique_signals:
        details["missing_timestamps"] = missing_timestamps

    return RuleResult(
        score=score,
        verdict=verdict,
        details=details,
        recommendation=recommendation,
    )


# Hostname con forma de dominio dentro del texto libre de un token `from`
# de Received (que puede venir como "smtp.example.com (smtp.example.com
# [1.2.3.4])" o variantes).
_HOSTNAME_RE = re.compile(r"[a-zA-Z0-9][\w.-]*\.[a-zA-Z]{2,}")


@iris_rules.register(
    name="Origin HELO Coherence",
    category="header_analysis", family="received",
    description=(
        "Aproximación offline (Iris no resuelve DNS/PTR real) de coherencia "
        "HELO/EHLO: el hop de origen declara un hostname que no coincide "
        "con el From, el Message-ID ni ningún host `by` posterior de la "
        "cadena -- corrobora, no decide en solitario, y solo se combina "
        "con un fallo de autenticación."
    ),
    needs_context=True,
)
def check_origin_helo_coherence(context) -> RuleResult:
    received = context.received_headers or []
    if not received:
        return RuleResult(score=0, verdict="neutral", details={"reason": "no Received chain"})

    origin = parse_received_line(received[-1])
    helo = (origin.get("from") or "").strip()
    if not helo:
        return RuleResult(score=0, verdict="neutral", details={"reason": "no HELO declared at origin"})

    helo_match = _HOSTNAME_RE.search(helo)
    if not helo_match:
        return RuleResult(score=0, verdict="neutral", details={"reason": "HELO sin forma de hostname"})
    helo_domain = registrable_domain(helo_match.group(0).lower())
    if not helo_domain:
        return RuleResult(score=0, verdict="neutral", details={})

    from_domain = registrable_domain(extract_domain(context.headers.get("from", "")))

    message_id = context.headers.get("message-id", "")
    msgid_match = re.search(r"@([\w.-]+)", message_id)
    msgid_domain = registrable_domain(msgid_match.group(1).lower()) if msgid_match else None

    chain_domains: set[str] = set()
    for line in received:
        by_host = (parse_received_line(line).get("by") or "").strip().rstrip(".,;")
        if by_host:
            dom = registrable_domain(by_host)
            if dom:
                chain_domains.add(dom)

    known_domains = {d for d in (from_domain, msgid_domain) if d} | chain_domains
    if not known_domains or helo_domain in known_domains:
        return RuleResult(score=0, verdict="pass", details={"helo_domain": helo_domain})

    return RuleResult(
        score=CR.get_iris_scoring_weight("origin_helo_coherence.mismatch", -5), verdict="fail",
        details={"helo_domain": helo_domain, "known_domains": sorted(known_domains)},
        recommendation=(
            f"El servidor de origen se identifica como '{helo_domain}' (HELO/EHLO), un "
            "dominio que no coincide con el remitente, el Message-ID ni ningún salto "
            "posterior de la cadena Received. Iris no realiza resolución DNS/PTR real; "
            "esto es una aproximación offline, corroborante -- no decisiva en solitario."
        ),
    )
