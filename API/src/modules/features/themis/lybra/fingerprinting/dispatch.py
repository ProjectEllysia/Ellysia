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
        extra_layers: Las capas de servidor **adicionales** observadas en el
            mismo puerto, como tuplas ``(producto, versión, rol)``. Vacía en el
            caso normal, un elemento cuando hay un proxy inverso por delante de
            un servidor distinto (L48-b). La primera capa no aparece aquí: ya
            viaja en ``product``/``version``.
    """
    product: Optional[str]
    version: Optional[str]
    label: str
    qod: int = QOD_FINGERPRINT
    extra_layers: tuple = ()


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

    tries_blind: bool = False
    """Si este protocolo se puede intentar **a ciegas**, con una sonda activa
    barata, contra un servicio que no ha ofrecido banner ninguno.

    Lo declaran Redis (``INFO``) y HTTP (``GET /``): dos protocolos que no
    saludan pero contestan a una pregunta corta y sin efectos. Es el último
    escalón de :func:`~.cascade.identify_unknown_service`, y va acotado por
    presupuesto — probarlos todos contra todo puerto desconocido sería un
    escaneo de servicios completo, no una cascada barata.
    """

    def applies(self, service: Service) -> bool:
        """Return whether this dissector should probe ``service`` at all."""
        raise NotImplementedError

    def identify_from_banner(self, banner: bytes) -> Optional[DissectorResult]:
        """Identifica el servicio a partir de un banner que ya se ha leído.

        La otra puerta de entrada al dissector, y la que existe para los
        servicios que **no** están en su puerto de siempre. ``applies`` decide
        por nombre o por número de puerto; esto decide por lo que el servicio
        realmente ha dicho, que es como identifican Nmap y OpenVAS.

        La implementación por defecto devuelve ``None``: un protocolo que
        necesita negociar —SMB, TLS, SNMP— no puede reconocerse en un banner
        ofrecido, porque no ofrece ninguno. Los ocho que sí leen un saludo
        voluntario lo sobrescriben.

        Cada implementación debe exigir un **marcador propio del protocolo**
        antes de reclamar el banner (``SSH-``, ``RFB ``, ``+OK``...): varios
        protocolos empiezan por ``220``, y sin marcador el primero de la lista
        se quedaría con todos.

        Args:
            banner: Los bytes crudos que el servicio envió sin que se le
                pidiera nada.

        Returns:
            La identificación, o ``None`` si el banner no es de este protocolo.
        """
        return None

    def probe(self, target: str, service: Service, rate_limiter) -> Optional[DissectorResult]:
        """Perform the (possibly multi-step) network exchange and identify the service."""
        raise NotImplementedError
