"""The dissector dispatch — replaces an if/elif chain with one entry per protocol.

``LybraEngineManager._fingerprint_services`` used to ask, for every discovered
service, "is this HTTP? SSH? FTP?" as a chain of ``if``/``elif`` branches, each
running that protocol's own multi-step probe inline. Every new protocol Fase N
adds meant a new branch in the manager. A :class:`Dissector` moves each
protocol's applicability test and probe logic into its own small object,
registered once in :func:`~.default_dissectors`; the manager just asks each one
in turn "does this apply, and if so, what did you find?" — adding protocol N+1
means adding one more entry to that list, never touching the manager again.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ..engine import Service


# Quality of Detection de un hallazgo de fingerprint: informativo y nada más.
# Constata qué identificó el motor; nunca contribuye a la confianza de una
# vulnerabilidad. Vivía en ``concordance.py`` hasta L52, cuando ese módulo se
# fue al arnés de pruebas por medir contra Nmap dentro del producto.
QOD_FINGERPRINT = 20


@dataclass(frozen=True)
class DissectorResult:
    """One protocol's identification of a service, ready for a fingerprint finding.

    Attributes:
        product: El producto identificado, o ``None``.
        version: La versión identificada, o ``None``.
        label: La etiqueta del dissector que lo leyó (``"HTTP"``, ``"FTP"``...).
        qod: Cuánto se fía el dissector de esta lectura concreta, si sabe
            distinguirlo. Por defecto :data:`QOD_FINGERPRINT`, que es lo que
            todos los dissectors usaban y lo que sigue valiendo para los que
            leen una sola fuente. El de HTTP sí distingue —su versión puede
            venir de seis sitios de calidad muy distinta— y lo aprovecha (L18).
    """
    product: Optional[str]
    version: Optional[str]
    label: str
    qod: int = QOD_FINGERPRINT


class Dissector:
    """One protocol's Fase F/N identification strategy: applicability + probe.

    :meth:`probe` returns ``None`` only for a raw transport failure (connection
    refused, timeout, connection closed before anything usable arrived) — a
    completed exchange always returns a :class:`DissectorResult`, even with
    empty ``product``/``version`` fields when nothing was recognisable. This
    mirrors how ``fingerprint_http``/``fingerprint_ssh``/``fingerprint_ftp``
    themselves never return ``None``, only an empty reading.
    """

    label: str = ""

    def applies(self, service: Service) -> bool:
        """Return whether this dissector should probe ``service`` at all."""
        raise NotImplementedError

    def probe(self, target: str, service: Service, rate_limiter) -> Optional[DissectorResult]:
        """Perform the (possibly multi-step) network exchange and identify the service."""
        raise NotImplementedError
