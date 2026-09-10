"""Frontera de confianza de la cadena ``Received``.

El corpus de ataque que pide el criterio de cierre del issue: **ningún
``Authentication-Results`` aportado por el atacante convierte por sí solo un
mensaje en autenticado**.

La idea que se prueba aquí es sencilla de enunciar y fácil de perder de vista:
los MTA *anteponen* su ``Received``, así que la cadena va del último salto (el
servidor del destinatario) al origen, y **los saltos de abajo los escribió
quien envió el mensaje**. Contrastar una cabecera que aporta el remitente
contra otra cabecera que también aporta el remitente no verifica nada.
"""

from __future__ import annotations

import pytest

from src.modules.features.iris.services.auth_trust import (
    TRUST_ABSENT,
    TRUST_BELOW_BOUNDARY,
    TRUST_BOUNDARY,
    TRUST_CONFIGURED,
    TRUST_UNKNOWN,
    assess_authserv_trust,
    is_arc_verified_by_trusted_hop,
    parse_hops,
    trust_boundary,
)
from src.modules.features.iris.services.parsers import MessageContext
from src.modules.features.iris.services.rules.auth_rules import (
    check_auth_results_provenance,
)

pytestmark = pytest.mark.unit


def _hop(sender: str, receiver: str, when: str = "Wed, 25 Jun 2025 10:00:00 +0000") -> str:
    return f"from {sender} by {receiver}; {when}"


# La cadena legítima: dos saltos internos del proveedor del destinatario y,
# debajo, el servidor real del remitente.
_LEGITIMATE_CHAIN = [
    _hop("mx-in.destino.example", "mx2.destino.example"),
    _hop("smtp.remitente.example", "mx-in.destino.example"),
]


# ---------------------------------------------------------------------------
# La frontera en sí
# ---------------------------------------------------------------------------

def test_boundary_covers_the_receiving_infrastructure():
    """Los saltos contiguos de la misma organización que entregó el mensaje
    son recorrido interno suyo: nadie de fuera los pudo escribir."""
    hops = parse_hops(_LEGITIMATE_CHAIN)

    # Los dos saltos entregan a destino.example (mx2 y mx-in): son el recorrido
    # interno del proveedor del destinatario, así que ninguno de los dos lo
    # pudo escribir el remitente. El salto de origen ya queda fuera.
    assert [hop.by_domain for hop in hops] == ["destino.example", "destino.example"]
    assert trust_boundary(hops) == 2


def test_boundary_extends_across_contiguous_hops_of_the_same_organisation():
    chain = [
        _hop("mx1.destino.example", "mx2.destino.example"),
        _hop("gateway.destino.example", "mx1.destino.example"),
        _hop("smtp.remitente.example", "gateway.destino.example"),
    ]

    # Los tres primeros `by` son destino.example; el cuarto salto ya no existe.
    assert trust_boundary(parse_hops(chain)) == 3


def test_boundary_stops_at_the_first_foreign_organisation():
    chain = [
        _hop("relay.tercero.example", "mx.destino.example"),
        _hop("origen.example", "relay.tercero.example"),
        _hop("otro.example", "mx.destino.example"),  # vuelve a "los nuestros"
    ]

    # La frontera es contigua desde arriba: que un salto de más abajo vuelva a
    # nombrar nuestro dominio no lo hace fiable — eso es justamente lo que
    # escribiría quien quisiera colarse.
    assert trust_boundary(parse_hops(chain)) == 1


# ---------------------------------------------------------------------------
# El ataque que cierra la frontera de confianza
# ---------------------------------------------------------------------------

def test_injected_received_plus_auth_results_no_longer_passes():
    """El bypass, en su forma exacta.

    El atacante añade a su propio correo dos cabeceras que se respaldan
    mutuamente: un ``Received`` que dice ``by: mx.atacante.example`` y un
    ``Authentication-Results`` firmado por ``mx.atacante.example``. Antes, la
    regla comprobaba que el authserv-id apareciera en *algún* salto — y
    aparecía, porque el propio atacante lo había puesto ahí.
    """
    context = MessageContext(
        headers={
            "authentication-results": "mx.atacante.example; spf=pass; dkim=pass; dmarc=pass",
        },
        received_headers=[
            _hop("mx.atacante.example", "mx2.destino.example"),   # salto real
            _hop("origen.atacante.example", "mx.atacante.example"),  # inventado
        ],
    )

    result = check_auth_results_provenance(context)

    assert result.verdict == "fail"
    assert result.score < 0
    assert result.details["trust"] == TRUST_BELOW_BOUNDARY


def test_the_same_header_from_the_real_delivering_server_still_passes():
    """La otra mitad: el correo legítimo no puede empezar a fallar."""
    context = MessageContext(
        headers={
            "authentication-results": "mx2.destino.example; spf=pass; dkim=pass; dmarc=pass",
        },
        received_headers=_LEGITIMATE_CHAIN,
    )

    result = check_auth_results_provenance(context)

    assert result.verdict == "pass"
    assert result.details["trust"] == TRUST_BOUNDARY


def test_an_authserv_id_that_never_touched_the_message_still_fails():
    """El caso que ya se detectaba antes de la frontera de confianza sigue detectándose."""
    context = MessageContext(
        headers={
            "authentication-results": "inventado.example; spf=pass; dkim=pass; dmarc=pass",
        },
        received_headers=_LEGITIMATE_CHAIN,
    )

    result = check_auth_results_provenance(context)

    assert result.verdict == "fail"
    assert result.details["trust"] == TRUST_ABSENT


def test_duplicate_authentication_results_cannot_be_smuggled_below():
    """Cabeceras duplicadas.

    El dict de cabeceras conserva una sola aparición por nombre, así que el
    atacante no gana nada duplicando ``Authentication-Results``: la que se
    evalúa se contrasta igualmente contra la frontera, y su salto sigue
    estando por debajo.
    """
    context = MessageContext(
        headers={
            "authentication-results": "mx.atacante.example; spf=pass; dmarc=pass",
        },
        received_headers=[
            _hop("mx.atacante.example", "mx2.destino.example"),
            _hop("a.example", "mx.atacante.example"),
            _hop("b.example", "mx.atacante.example"),
        ],
    )

    assert check_auth_results_provenance(context).verdict == "fail"


def test_no_received_chain_stays_neutral():
    """Sin cadena que contrastar no hay base para acusar de forjado; neutral,
    no "sospechoso por defecto" — pegar solo unas cabeceras sueltas es un uso
    legítimo de Iris."""
    context = MessageContext(
        headers={"authentication-results": "cualquiera.example; spf=pass"},
        received_headers=[],
    )

    result = check_auth_results_provenance(context)

    assert result.verdict == "neutral"
    assert result.score == 0
    assert assess_authserv_trust("cualquiera.example", []).verdict == TRUST_UNKNOWN


# ---------------------------------------------------------------------------
# Lista explícita de verificadores de confianza
# ---------------------------------------------------------------------------

def test_a_configured_verifier_is_trusted_wherever_it_appears(monkeypatch):
    """Para el despliegue que sabe qué servidor autentica su correo — un
    gateway corporativo que entrega a un buzón alojado en otro proveedor y
    que, por tanto, no encabeza la cadena."""
    import src.modules.features.iris.services.auth_trust as auth_trust

    monkeypatch.setattr(auth_trust.CR, "get_iris_data",
                        lambda key: ["gateway.corporativo.example"] if key == "trusted_authserv_ids" else None)

    trust = assess_authserv_trust("gateway.corporativo.example", _LEGITIMATE_CHAIN)

    assert trust.verdict == TRUST_CONFIGURED
    assert trust.is_trusted is True


def test_without_configuration_trust_comes_from_the_chain_alone():
    """El dataset está vacío por defecto: el módulo tiene que funcionar en
    cualquier despliegue sin que nadie configure nada."""
    trust = assess_authserv_trust("mx2.destino.example", _LEGITIMATE_CHAIN)

    assert trust.is_trusted is True
    assert trust.verdict == TRUST_BOUNDARY


# ---------------------------------------------------------------------------
# ARC
# ---------------------------------------------------------------------------

def test_a_forged_arc_seal_is_not_verified():
    """``ARC-Seal: cv=pass`` es lo que el mensaje dice de sí mismo. Iris no
    verifica firmas, así que no puede valer como prueba."""
    headers = {"arc-seal": "i=1; a=rsa-sha256; cv=pass; d=atacante.example; s=s1; b=xyz"}

    assert is_arc_verified_by_trusted_hop(headers, _LEGITIMATE_CHAIN) is False


def test_arc_is_verified_when_the_delivering_server_says_so():
    """Quien sí valida la cadena es el MTA receptor, que lo apunta como
    ``arc=pass`` en su propio Authentication-Results (RFC 8617 §5.2)."""
    headers = {
        "arc-seal": "i=1; a=rsa-sha256; cv=pass; d=lista.example; s=s1; b=xyz",
        "authentication-results": "mx2.destino.example; arc=pass; spf=fail; dmarc=fail",
    }

    assert is_arc_verified_by_trusted_hop(headers, _LEGITIMATE_CHAIN) is True


def test_arc_confirmation_signed_below_the_boundary_does_not_count():
    """Y el rodeo obvio tampoco funciona: escribir uno mismo el ``arc=pass``
    en un Authentication-Results propio es el mismo ataque con un paso más."""
    headers = {
        "arc-seal": "i=1; a=rsa-sha256; cv=pass; d=atacante.example; s=s1; b=xyz",
        "authentication-results": "mx.atacante.example; arc=pass; spf=pass; dmarc=pass",
    }
    chain = [
        _hop("mx.atacante.example", "mx2.destino.example"),
        _hop("origen.example", "mx.atacante.example"),
    ]

    assert is_arc_verified_by_trusted_hop(headers, chain) is False


def test_arc_without_any_authentication_results_is_not_verified():
    headers = {"arc-seal": "i=1; cv=pass; d=lista.example"}

    assert is_arc_verified_by_trusted_hop(headers, _LEGITIMATE_CHAIN) is False
