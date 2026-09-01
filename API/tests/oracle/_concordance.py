"""Concordancia con Nmap: la vara de medir, fuera del producto.

Estas tres funciones vivían dentro del paquete que se despliega
(``lybra/fingerprinting/concordance.py`` y ``lybra/transport.py``). Se mudaron
aquí en L52, cuando se retiró el acoplamiento de Lybra con escáneres de
terceros, y la razón de mudarlas en vez de borrarlas merece decirse entera.

Lo que se retiró del producto es la **subordinación**: que Nmap fuera la
autoridad en tiempo de ejecución, que un escaneo de Lybra pudiera lanzarse
desde uno de Nmap, y que pudiera lanzar otros escáneres para que le dieran la
razón. Un motor cuyo análisis propio no puede prevalecer sobre el de otra
herramienta no es independiente.

Lo que no se retiró es la **medición**. Comparar el motor contra una referencia
externa en los tests no es acoplamiento: es la única forma de demostrar que el
motor es bueno en vez de afirmarlo. La independencia se demuestra midiéndose
contra el mejor del mercado y empatando o ganando, no negándose a la
comparación — y el objetivo declarado del roadmap (concordancia ≥ 0,90 en
fingerprint, ≥ 0,95 en descubrimiento de puertos) es exactamente esa
demostración. Aquí, en ``tests/``, la vara de medir existe y el producto no
sabe que existe.

Este módulo es deliberadamente agnóstico del protocolo: recibe pares
``(producto, versión)`` planos, no un ``HttpFingerprint`` ni un
``SshFingerprint``, para que todo el banco comparta una sola comparación y una
sola métrica.
"""

from __future__ import annotations

from typing import Iterable, Optional, Tuple


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
    hits = sum(1 for pair in pairs if agrees_with_nmap(*pair))
    return hits / len(pairs)


def port_concordance(own_ports: Iterable[int], nmap_ports: Iterable[int]) -> float:
    """Measure how well our discovered ports agree with Nmap's.

    Computes the Jaccard index (size of the intersection over size of the union)
    between the two port sets. Two empty sets count as full agreement — there is
    nothing to disagree about.

    Args:
        own_ports: The ports Lybra's connect scan found.
        nmap_ports: The ports Nmap found (the reference being measured against).

    Returns:
        A value in ``[0.0, 1.0]``, where 1.0 is perfect agreement.
    """
    own, nmap = set(own_ports), set(nmap_ports)
    union = own | nmap
    if not union:
        return 1.0
    return len(own & nmap) / len(union)
