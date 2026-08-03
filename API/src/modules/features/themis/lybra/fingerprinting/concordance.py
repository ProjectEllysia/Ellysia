"""Oracle / concordance: measuring agreement between our own fingerprints and Nmap.

The governing principle of the whole fingerprinting package is that **Nmap
stays the oracle**: when a service already carries a Nmap-sourced
product/version, a dissector's own reading never overrides it.
:func:`agrees_with_nmap` and :func:`concordance_rate` turn "does our
fingerprint match Nmap's?" into a measurable number — the roadmap's
Definition of Done requires agreement to reach 0.90 before Nmap could be
demoted to a *fallback*. Actually running that measurement against a lab of
real targets is an operational step for the user, much like the knowledge
base's initial full download.

This module is deliberately protocol-agnostic: it takes plain
``(product, version)`` pairs, not an ``HttpFingerprint`` or ``SshFingerprint``,
so every dissector shares one comparison and one metric instead of each
re-implementing its own.
"""

from __future__ import annotations

from typing import Iterable, Optional, Tuple

# Quality of Detection for a fingerprint finding: informational only. It exists
# to gather calibration evidence and never contributes to a vulnerability's
# confidence.
QOD_FINGERPRINT = 20


def _versions_agree(version: str, nmap_version: str) -> bool:
    """Return whether two version strings identify the same release.

    Nmap often appends extra info after the bare version number — SSH banners
    in particular come back as e.g. ``"6.6.1p1 Ubuntu 2ubuntu2.13"`` for our
    plain ``"6.6.1p1"`` — so an exact-string comparison would call that a
    disagreement when the version itself is identical. A prefix match on a
    word boundary still counts as agreement; anything else does not.
    """
    if version == nmap_version:
        return True
    return nmap_version.startswith(version + " ") or version.startswith(nmap_version + " ")


def agrees_with_nmap(
    product: Optional[str], version: Optional[str],
    nmap_product: Optional[str], nmap_version: Optional[str],
) -> bool:
    """Decide whether our fingerprint agrees with Nmap's for one service.

    Product names are compared by case-insensitive substring overlap, because the
    two tools name things differently ("Apache" versus "Apache httpd"). Versions
    are compared leniently (see :func:`_versions_agree`), but only when both
    sides actually report one. This is the per-service judgement that
    :func:`concordance_rate` aggregates.

    Args:
        product: Our identified product.
        version: Our identified version.
        nmap_product: Nmap's product for the same service.
        nmap_version: Nmap's version for the same service.

    Returns:
        ``True`` if the two identifications agree, ``False`` otherwise (including
        when either side has no product to compare).
    """
    if not product or not nmap_product:
        return False
    p, np = product.lower(), nmap_product.lower()
    if p not in np and np not in p:
        return False
    if version and nmap_version and not _versions_agree(version, nmap_version):
        return False
    return True


def concordance_rate(pairs: Iterable[Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]]) -> float:
    """Compute the fraction of fingerprints that agree with Nmap.

    This is the metric the roadmap's Definition of Done thresholds at 0.90 before
    Nmap could become a fallback for a service family. Collecting real
    ``(product, version, nmap_product, nmap_version)`` pairs from a lab of known
    targets is an operational step for the user; this function only does the
    arithmetic once the pairs exist.

    Args:
        pairs: An iterable of ``(product, version, nmap_product, nmap_version)``
            tuples, one per compared service.

    Returns:
        The fraction that agree, in ``[0.0, 1.0]``. Empty input returns 0.0 (no
        evidence yet, not perfect agreement).
    """
    pairs = list(pairs)
    if not pairs:
        return 0.0
    hits = sum(1 for p in pairs if agrees_with_nmap(*p))
    return hits / len(pairs)
