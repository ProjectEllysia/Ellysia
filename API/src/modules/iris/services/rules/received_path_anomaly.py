"""
Received Path Anomaly rule.

Consumes the parsed Received chain (built by
``services.received_parser``) and emits a score reflecting how clean the
path looks. The rule deliberately **avoids double-counting** signals
that other rules already cover:

* Time inversions are already penalised by
  ``Received Chain Temporal Inconsistency``.
* A private/loopback origin IP is already penalised by
  ``Received Chain``.

This rule contributes only **new** signals:

* TLS downgrades between consecutive hops (encrypted hop followed by a
  clear hop).
* Excessively long chains (>= 5 hops with mostly unique IPs).
* Hops with unparseable timestamps when the rest of the chain has them.

A clean, short, fully-encrypted path earns a small positive bonus so
the rule can also *legitimise* a message.
"""

from __future__ import annotations

from typing import List

from ..parsers import build_path
from ..registry import iris_rules, RuleResult


LONG_CHAIN_THRESHOLD = 5
MISSING_TS_MIN_HOPS = 3


@iris_rules.register(
    name="Received Path Anomaly",
    category="header_analysis",
    description=(
        "Eval\u00faa el recorrido Received: del correo \u2014 n\u00famero de saltos, "
        "downgrades TLS entre hops, cadenas excesivamente largas y "
        "timestamps no parseables. Se\u00f1ales complementarias a las "
        "reglas de Received Chain existentes (no double-counting)."
    ),
    needs_context=True,
)
def check_received_path_anomaly(context) -> RuleResult:
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

    # --- TLS downgrade between consecutive hops ---
    tls_downgrade_pairs: List[dict] = [
        {"from": t["from"], "to": t["to"]}
        for t in transitions
        if "tls_downgrade" in t.get("reasons", [])
    ]
    if tls_downgrade_pairs:
        unique_signals.append("tls_downgrade")

    # --- Long chain (>= 5 hops with mostly unique IPs) ---
    long_chain = False
    if len(hops) >= LONG_CHAIN_THRESHOLD:
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
            score -= 6
        if "long_chain" in unique_signals:
            score -= 4
        if "missing_timestamps" in unique_signals:
            score -= 3

        # Soft-fail vs hard-fail: tls_downgrade is a stronger signal
        # than just missing timestamps.
        if "tls_downgrade" in unique_signals or "long_chain" in unique_signals:
            verdict = "fail"
        else:
            verdict = "suspicious"

        reasons = {
            "tls_downgrade": "al menos un salto perdi\u00f3 TLS al reenviar",
            "long_chain": "cadena Received inusualmente larga",
            "missing_timestamps": "algunos hops no exponen timestamp parseable",
        }
        msg = "; ".join(reasons[s] for s in unique_signals)
        recommendation = (
            "El recorrido Received presenta anomal\u00edas: " + msg + "."
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
