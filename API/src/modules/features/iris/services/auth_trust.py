"""
Frontera de confianza de la cadena ``Received`` de un mensaje.

El problema que resuelve este módulo es que **una parte de las cabeceras de un
correo las escribe el atacante**. Los MTA *anteponen* su ``Received``, así que
la cadena se lee de arriba abajo desde el último salto (el servidor del
destinatario) hasta el origen. Los saltos de abajo los aportó quien envió el
mensaje, y puede inventárselos: nada le impide fabricar tres ``Received``
falsos que describan un recorrido que nunca ocurrió.

Eso importa porque ``Authentication-Results`` —la cabecera donde un servidor
apunta el resultado de SPF, DKIM y DMARC— **también la puede escribir el
remitente**. Iris ya comprobaba que el ``authserv-id`` que la firma apareciera
como host ``by`` de algún salto de la cadena, pero aceptaba *cualquier* salto,
incluidos los de abajo. Un atacante que inyecte a la vez su propio ``Received``
(``by: mx.suservidor.example``) y su propio ``Authentication-Results``
(``mx.suservidor.example; spf=pass; dkim=pass; dmarc=pass``) pasaba la
comprobación: los dos elementos que se estaban contrastando eran suyos.

La frontera de confianza es el punto de la cadena por debajo del cual nada es
verificable. Este módulo la calcula y responde a la única pregunta que las
reglas necesitan: *¿escribió esta cabecera alguien en quien podemos confiar?*
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional, Sequence

import src.modules.system.config_reading as CR

from .parsers import parse_received_line
from .text import registrable_domain


#: Veredictos de :func:`assess_authserv_trust`.
TRUST_CONFIGURED = "configured"
"""El verificador está en la lista explícita de confianza del despliegue."""

TRUST_BOUNDARY = "boundary"
"""El verificador es la propia infraestructura receptora (por encima de la
frontera). Es el caso normal del correo legítimo."""

TRUST_BELOW_BOUNDARY = "below_boundary"
"""El ``authserv-id`` solo aparece en saltos que el remitente pudo fabricar.
Es el bypass que esta frontera cierra: la cabecera existe y "cuadra" con la cadena,
pero cuadra con la parte de la cadena que escribió el atacante."""

TRUST_ABSENT = "absent"
"""El ``authserv-id`` no aparece en ningún salto: la cabecera la estampó un
servidor que nunca tocó el mensaje."""

TRUST_UNKNOWN = "unknown"
"""No hay cadena ``Received`` que contrastar. No es una acusación: sin base
para juzgar, la regla se queda neutral."""


def trusted_authserv_ids() -> frozenset[str]:
    """Verificadores declarados de confianza en ``features.iris.data``.

    Sirve para el despliegue que sabe qué servidor autentica su correo —el
    gateway corporativo, el proveedor gestionado— y quiere que se acepte
    aunque no encabece la cadena. Vacío por defecto: sin configuración, la
    confianza se deduce de la propia cadena (ver :func:`trust_boundary`), que
    es lo que hace que el módulo funcione en cualquier despliegue sin tocar
    nada.
    """
    configured = CR.get_iris_data("trusted_authserv_ids") or []
    return frozenset(str(entry).strip().lower() for entry in configured if str(entry).strip())


@dataclass(frozen=True)
class ReceivedHop:
    """Un salto de la cadena, reducido a lo que la frontera necesita."""

    position: int
    """0 es el último salto (el servidor del destinatario), el más fiable."""

    by_host: Optional[str]
    by_domain: Optional[str]


def parse_hops(received_headers: Sequence[str]) -> List[ReceivedHop]:
    """Reduce la cadena a sus hosts ``by``, conservando el orden de entrega.

    ``received_headers[0]`` es el salto final y ``[-1]`` el origen — el mismo
    orden que produce ``MessageContext.received_headers`` y que consume
    ``build_path``.
    """
    hops: List[ReceivedHop] = []
    for position, line in enumerate(received_headers):
        by_host = (parse_received_line(line).get("by") or "").strip().rstrip(".,;").lower()
        hops.append(ReceivedHop(
            position=position,
            by_host=by_host or None,
            by_domain=registrable_domain(by_host) if by_host else None,
        ))
    return hops


def trust_boundary(hops: Sequence[ReceivedHop]) -> int:
    """Cuántos saltos, contando desde el final de entrega, son fiables.

    La regla es la contigüidad organizativa desde arriba: el salto 0 lo escribió
    el servidor que entregó el mensaje —el nuestro, o el de nuestro proveedor—
    y por tanto no lo pudo fabricar el remitente. Los saltos inmediatamente
    siguientes que pertenecen a **la misma organización** (mismo dominio
    registrable) son el recorrido interno de esa misma infraestructura, y
    tampoco. En cuanto la cadena cambia de organización se ha salido del
    perímetro receptor y ya no hay nada que garantice que lo de abajo ocurrió.

    Un salto declarado de confianza en la configuración extiende la frontera
    aunque cambie de dominio: es el caso del gateway corporativo que entrega a
    un buzón alojado en otro proveedor.

    Sin cadena, la frontera es 0 — no hay nada fiable, pero tampoco nada que
    acusar; de eso se encarga el llamante.
    """
    if not hops:
        return 0

    anchor_domain = hops[0].by_domain
    configured = trusted_authserv_ids()

    boundary = 0
    for hop in hops:
        is_same_organisation = anchor_domain is not None and hop.by_domain == anchor_domain
        is_configured = (hop.by_host in configured) or (hop.by_domain in configured)
        if is_same_organisation or is_configured:
            boundary = hop.position + 1
            continue
        break

    # Una cadena de un solo salto sin `by` legible no ancla nada, pero el salto
    # final sigue siendo el final: se cuenta como frontera para no tratar como
    # forjado un mensaje cuya cadena simplemente no se pudo parsear.
    return boundary or 1


@dataclass(frozen=True)
class AuthservTrust:
    """Resultado de contrastar un ``authserv-id`` con la cadena real."""

    verdict: str
    is_trusted: bool
    boundary: int
    matched_position: Optional[int] = None
    trusted_by_domains: tuple[str, ...] = ()
    untrusted_by_domains: tuple[str, ...] = ()


def assess_authserv_trust(authserv_id: str, received_headers: Sequence[str]) -> AuthservTrust:
    """¿Escribió esta cabecera alguien en quien podemos confiar?

    Distingue tres desenlaces que antes eran dos. Que el ``authserv-id``
    aparezca *en algún sitio* de la cadena ya no basta: importa **dónde**.
    Aparecer solo por debajo de la frontera (``below_boundary``) es la firma de
    la inyección que este módulo existe para detectar, y es un caso más grave
    que no aparecer en absoluto — quien fabrica los dos elementos a la vez para
    que se corroboren mutuamente sabe exactamente lo que hace.
    """
    normalised = (authserv_id or "").strip().lower()
    configured = trusted_authserv_ids()
    hops = parse_hops(received_headers)

    if normalised in configured or (registrable_domain(normalised) or "") in configured:
        return AuthservTrust(verdict=TRUST_CONFIGURED, is_trusted=True,
                             boundary=len(hops))

    if not hops or all(hop.by_domain is None for hop in hops):
        return AuthservTrust(verdict=TRUST_UNKNOWN, is_trusted=False, boundary=0)

    boundary = trust_boundary(hops)
    authserv_domain = registrable_domain(normalised)

    trusted_domains = tuple(sorted({
        hop.by_domain for hop in hops[:boundary] if hop.by_domain
    }))
    untrusted_domains = tuple(sorted({
        hop.by_domain for hop in hops[boundary:] if hop.by_domain
    }))

    for hop in hops[:boundary]:
        if hop.by_domain and hop.by_domain == authserv_domain:
            return AuthservTrust(verdict=TRUST_BOUNDARY, is_trusted=True, boundary=boundary,
                                 matched_position=hop.position,
                                 trusted_by_domains=trusted_domains,
                                 untrusted_by_domains=untrusted_domains)

    for hop in hops[boundary:]:
        if hop.by_domain and hop.by_domain == authserv_domain:
            return AuthservTrust(verdict=TRUST_BELOW_BOUNDARY, is_trusted=False, boundary=boundary,
                                 matched_position=hop.position,
                                 trusted_by_domains=trusted_domains,
                                 untrusted_by_domains=untrusted_domains)

    return AuthservTrust(verdict=TRUST_ABSENT, is_trusted=False, boundary=boundary,
                         trusted_by_domains=trusted_domains,
                         untrusted_by_domains=untrusted_domains)


# ``arc=pass`` dentro de un Authentication-Results: el resultado de que **el
# servidor receptor** validara criptográficamente la cadena ARC. Es distinto de
# ``ARC-Seal: cv=pass``, que es lo que la propia cadena dice de sí misma.
_ARC_RESULT_RE = re.compile(r"\barc\s*=\s*pass\b", re.IGNORECASE)


def is_arc_verified_by_trusted_hop(headers: dict, received_headers: Sequence[str]) -> bool:
    """¿Ha validado la cadena ARC alguien en quien confiamos?

    Iris no verifica firmas criptográficas —ni de DKIM, ni de ARC—, así que un
    ``ARC-Seal: cv=pass`` es solo una afirmación del propio mensaje sobre sí
    mismo. Cualquiera puede escribirla, incluido quien tenga interés en que su
    correo parezca un reenvío legítimo.

    Quien sí la verifica es el MTA receptor, que apunta el resultado como
    ``arc=pass`` dentro de **su** ``Authentication-Results`` (RFC 8617 §5.2).
    Esa afirmación sí vale, con la condición de siempre: que la cabecera la
    haya escrito un verificador por encima de la frontera de confianza. Si no,
    estaríamos otra vez creyéndonos algo que pudo escribir el remitente, solo
    que con un rodeo más.
    """
    auth_results = (headers.get("authentication-results") or "").strip()
    if not auth_results:
        return False
    if not _ARC_RESULT_RE.search(auth_results):
        return False

    authserv_id = auth_results.split(";", 1)[0].strip().lower()
    return assess_authserv_trust(authserv_id, received_headers).is_trusted
