"""
Received-Chain Temporal Inconsistency rule — flags a ``Received:`` chain
whose timestamps are NOT strictly increasing from the originating hop
to the final delivery hop.

RFC 5321 §4.4 requires the originating MTA to stamp the *first* line,
and every subsequent MTA appends *its* Received line with a current
timestamp. The order in the message (top to bottom) is the *delivery*
order: the first Received is added by the final server. So the
chronological order from oldest to newest is *bottom to top* of the
list, i.e. ``received[-1]`` is the oldest.

If timestamps fail to be monotonically increasing when read in that
direction, at least one hop forged its line — a textbook sign of
header manipulation / spoofing. The existing ``received_chain`` rule
only compares the top Received against the ``Date:`` header; this one
inspects the *internal consistency* of the chain itself.
"""

from ..registry import iris_rules, RuleResult
from ..parsers import _hop_timestamp


@iris_rules.register(
    name="Received Chain Temporal Inconsistency",
    category="header_analysis",
    description=(
        "Detecta cadenas Received: con marcas de tiempo no monótonamente "
        "crecientes desde el origen hasta el destino, una firma de "
        "manipulación o fabricación de cabeceras."
    ),
    needs_context=True,
)
def check_received_chain_temporal_inconsistency(context) -> RuleResult:
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
    inversions: list[dict] = []
    for i in range(len(timestamps) - 1):
        a, b = timestamps[i], timestamps[i + 1]
        if a is None or b is None:
            continue
        if a < b:
            delta = (b - a).total_seconds()
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

    score = -10 if len(inversions) == 1 else -15

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
