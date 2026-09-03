"""La única verdad sobre si un objetivo está expuesto a internet (L38).

La clasificación acota la prioridad de todo hallazgo en red privada (tope HIGH
en ``score_finding``) y entra en el prompt del informe, que le dice al modelo
que en LAN el riesgo máximo es MEDIO. Estaba escrita dos veces; si divergían,
el scoring y el informe decían cosas distintas del mismo host y nada lo
detectaba.
"""

from __future__ import annotations

import pytest

from src.modules.shared import classify_exposure, is_private_target

pytestmark = pytest.mark.unit


@pytest.mark.parametrize("target", [
    "10.0.0.5", "192.168.1.1", "172.16.0.1",   # RFC 1918
    "127.0.0.1",                               # loopback
    "169.254.10.1",                            # link-local
    "::1", "fe80::1",                          # lo mismo en IPv6
])
def test_private_addresses_are_private(target):
    assert is_private_target(target)
    assert classify_exposure(target) == "private"


@pytest.mark.parametrize("target", ["8.8.8.8", "1.1.1.1", "2001:4860:4860::8888"])
def test_public_addresses_are_public(target):
    assert not is_private_target(target)
    assert classify_exposure(target) == "public"


@pytest.mark.parametrize("target", [
    "localhost",
    "impresora.local",        # mDNS, RFC 6762
    "router.home.arpa",       # RFC 8375
    "app.internal",           # reservado por ICANN para uso privado
    "srv.lan", "wiki.intranet", "dc1.corp", "nas.home",
])
def test_internal_hostnames_are_private(target):
    assert classify_exposure(target) == "private"


@pytest.mark.parametrize("target", ["example.com", "www.ellysia.es", "api.github.com"])
def test_an_unknown_hostname_is_treated_as_public(target):
    """Errar aquí es asimétrico: llamar pública a una red interna sólo infla la
    prioridad, mientras que lo contrario la rebaja y puede esconder algo que sí
    está expuesto. Ante la duda, público."""
    assert classify_exposure(target) == "public"


def test_surrounding_whitespace_does_not_change_the_verdict():
    assert classify_exposure("  10.0.0.5  ") == "private"
    assert classify_exposure(" IMPRESORA.LOCAL ") == "private"


def test_both_consumers_agree():
    """El motivo de existir del módulo: el scoring del motor y el prompt del
    informe leen la misma respuesta."""
    from src.modules.features.themis.lybra import classify_exposure as engine_view
    from src.modules.features.themis.services.analyzers import NmapAIWriter

    writer = NmapAIWriter.__new__(NmapAIWriter)
    for target in ("10.0.0.5", "8.8.8.8", "impresora.local", "example.com"):
        expected_private = engine_view(target) == "private"
        assert writer._classify_network_context(target)["is_private"] is expected_private
