"""Tests de la vara de medir: la aritmética de la concordancia con Nmap.

Vive en ``tests/oracle/`` porque mide junto al banco diferencial, pero **no**
lleva el marcador ``oracle``: son funciones puras sobre cadenas y conjuntos de
puertos, sin Docker, sin red y sin base de datos. Corren en el CI por defecto
como cualquier test unitario — que la vara de medir esté fuera del producto no
significa que nadie compruebe que mide bien.

Estos casos venían de ``test_lybra_fingerprint.py`` y ``test_lybra_transport.py``
y se mudaron con el código que ejercitan.
"""

import pytest

from ._concordance import agrees_with_nmap, concordance_rate, port_concordance

pytestmark = pytest.mark.unit


def test_agrees_with_nmap_token_overlap_and_version():
    assert agrees_with_nmap("Apache", "2.4.49", "Apache httpd", "2.4.49") is True
    assert agrees_with_nmap("OpenSSH", "7.4", "OpenSSH", "7.4") is True
    assert agrees_with_nmap("nginx", None, "nginx", "1.18") is True   # no version to contradict
    assert agrees_with_nmap("Apache", "2.4.49", "Apache httpd", "2.4.50") is False
    assert agrees_with_nmap("nginx", None, "Apache", None) is False
    assert agrees_with_nmap(None, None, "Apache", "2.4.49") is False


def test_agrees_with_nmap_tolerates_nmap_trailing_detail():
    """Nmap añade detalle del sistema tras la versión desnuda en los banners SSH;
    la versión es la misma y la comparación tiene que verlo así."""
    assert agrees_with_nmap("OpenSSH", "6.6.1p1", "OpenSSH", "6.6.1p1 Ubuntu 2ubuntu2.13") is True


def test_concordance_rate():
    pairs = [
        ("Apache", "2.4.49", "Apache httpd", "2.4.49"),   # agree
        ("nginx", "1.18", "nginx", "1.19"),                # disagree (version)
        ("OpenSSH", "7.4", "OpenSSH", "7.4"),               # agree
    ]
    assert concordance_rate(pairs) == pytest.approx(2 / 3)


def test_concordance_rate_empty_is_zero_not_perfect():
    assert concordance_rate([]) == 0.0


@pytest.mark.parametrize("own,nmap,expected", [
    ({80, 443}, {80, 443}, 1.0),
    ({80, 443}, {80, 443, 22}, 2 / 3),
    (set(), set(), 1.0),                        # nothing to disagree on
    ({80}, set(), 0.0),
])
def test_port_concordance(own, nmap, expected):
    assert port_concordance(own, nmap) == pytest.approx(expected)
