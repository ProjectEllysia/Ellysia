"""El catálogo de favicons y su hash.

El favicon se descargaba, se hasheaba y **nadie consultaba el resultado**: una
petición de red por servicio HTTP, con su turno de limitador, a cambio de un
dato muerto. Este fichero cubre las tres piezas que lo arreglan: el hash en la
convención pública, el catálogo que lo consulta, y la decisión de no pagar la
petición cuando no hay con qué comparar.
"""

import base64

import pytest

from src.modules.features.themis.lybra.checks import Response
from src.modules.features.themis.lybra.fingerprinting.favicon import (
    FaviconCatalog,
    FaviconEntry,
    favicon_hash,
    load_favicon_hashes,
    murmurhash3_x86_32,
    validate_favicon_hashes,
)
from src.modules.features.themis.lybra.fingerprinting.http import fingerprint_http

pytestmark = pytest.mark.unit


# ==================================================================== el hash


def test_murmurhash3_of_the_empty_input_is_zero():
    """El único vector de la especificación verificable a ojo, y el que delata
    de inmediato un error en el paso final de mezcla."""
    assert murmurhash3_x86_32(b"") == 0


@pytest.mark.parametrize("length", [1, 2, 3, 4, 5, 7, 8, 15, 16, 17, 64, 255])
def test_murmurhash3_handles_every_tail_length(length):
    """Los tres bytes de cola son la parte del algoritmo donde una
    transcripción se rompe sin que los casos redondos lo noten."""
    data = bytes(range(256))[:length]
    value = murmurhash3_x86_32(data)
    assert -(2 ** 31) <= value < 2 ** 31
    assert murmurhash3_x86_32(data) == value          # determinista


def test_murmurhash3_notices_a_single_changed_byte():
    original = b"favicon-bytes-aqui"
    altered = b"favicon-bytes-aquj"
    assert murmurhash3_x86_32(original) != murmurhash3_x86_32(altered)


def test_favicon_hash_follows_the_public_base64_convention():
    """El detalle que decide si el catálogo sirve o no.

    Shodan hashea el favicon **codificado en base64** (saltos cada 76
    caracteres, salto final), no los bytes crudos. Si se hashearan los bytes,
    el número no coincidiría con ningún catálogo público y toda la técnica
    perdería su razón de ser, que es comparativa.
    """
    data = bytes(range(256)) * 4
    assert favicon_hash(data) == murmurhash3_x86_32(base64.encodebytes(data))
    assert favicon_hash(data) != murmurhash3_x86_32(data)


# ================================================================= el catálogo


def test_an_unknown_favicon_produces_no_identification():
    """La garantía que impide inventar: un icono que no está catalogado no
    sugiere un producto parecido, no sugiere nada."""
    catalog = FaviconCatalog([FaviconEntry(favicon_hash(b"conocido"), "Jenkins",
                                           source="test")])
    assert catalog.identify(b"desconocido") is None
    assert catalog.identify(None) is None
    assert catalog.identify(b"") is None


def test_a_catalogued_favicon_resolves_the_product():
    icon = b"\x00\x00\x01\x00favicon de ejemplo"
    catalog = FaviconCatalog([FaviconEntry(favicon_hash(icon), "GitLab",
                                           vendor="GitLab Inc.", source="test")])
    entry = catalog.identify(icon)
    assert entry.product == "GitLab"
    assert entry.vendor == "GitLab Inc."


def test_the_bundled_catalog_is_well_formed():
    assert validate_favicon_hashes(load_favicon_hashes()) == []


def test_the_catalog_validator_finds_each_kind_of_breakage():
    """Sin este bloque, un validador que devolviera siempre `[]` dejaría el
    test de arriba en verde para siempre."""
    nameless = [FaviconEntry(1, "", source="test")]
    sourceless = [FaviconEntry(2, "Jenkins")]
    colliding = [FaviconEntry(3, "Jenkins", source="test"),
                 FaviconEntry(3, "GitLab", source="test")]
    assert len(validate_favicon_hashes(nameless)) == 1
    assert len(validate_favicon_hashes(sourceless)) == 1
    assert len(validate_favicon_hashes(colliding)) == 1


# ============================================ integración con fingerprint_http


def test_the_favicon_only_names_a_product_nobody_else_named(monkeypatch):
    """Un favicon identifica producto y casi nunca versión, así que nunca debe
    desplazar a una lectura que sí la trae."""
    from src.modules.features.themis.lybra.fingerprinting import http as http_module

    icon = b"icono-de-jenkins"
    monkeypatch.setattr(
        http_module, "_FAVICON_CATALOG",
        FaviconCatalog([FaviconEntry(favicon_hash(icon), "Jenkins", source="test")]),
    )

    # Sin ninguna otra señal: el icono nombra el producto.
    alone = fingerprint_http(Response(200, "<html></html>", {}), favicon=icon)
    assert alone.product == "Jenkins"
    assert alone.version is None

    # Con una cabecera Server que trae producto y versión: gana la cabecera.
    with_header = fingerprint_http(
        Response(200, "<html></html>", {"server": "Apache/2.4.49"}), favicon=icon)
    assert (with_header.product, with_header.version) == ("Apache", "2.4.49")


def test_the_fingerprint_keeps_both_hashes():
    """SHA-256 como identidad exacta del fichero, MurmurHash3 como clave de
    catálogo. Se guardan los dos porque responden a preguntas distintas."""
    icon = b"icono"
    fingerprint = fingerprint_http(Response(200, "<html></html>", {}), favicon=icon)
    assert fingerprint.favicon_catalog_hash == favicon_hash(icon)
    assert fingerprint.favicon_hash is not None
    assert len(fingerprint.favicon_hash) == 64          # hex de SHA-256


def test_no_favicon_still_fingerprints_normally():
    fingerprint = fingerprint_http(Response(200, "<html></html>",
                                            {"server": "nginx/1.24.0"}))
    assert (fingerprint.product, fingerprint.version) == ("nginx", "1.24.0")
    assert fingerprint.favicon_hash is None
    assert fingerprint.favicon_catalog_hash is None


# ================================ la petición sólo se paga cuando puede pagarse


class _RecordingProbe:
    """Sonda HTTP falsa que apunta cada ruta que se le pide."""

    def __init__(self):
        self.paths = []
        self.byte_paths = []

    def fetch(self, host, port, method, path):
        self.paths.append(path)
        return Response(200, "<html></html>", {"server": "nginx/1.24.0"})

    def fetch_bytes(self, host, port, path):
        self.byte_paths.append(path)
        return b"icono"


class _NullRateLimiter:
    def acquire(self, host):
        pass


def _probe_with_catalog(monkeypatch, catalog):
    from src.modules.features.themis.lybra.fingerprinting import http as http_module
    from src.modules.features.themis.lybra.engine import Service

    monkeypatch.setattr(http_module, "_FAVICON_CATALOG", catalog)
    recorder = _RecordingProbe()
    dissector = http_module.HttpDissector(probe=recorder)
    dissector.probe("10.0.0.5", Service(80, "tcp", "http"), _NullRateLimiter())
    return recorder


def test_an_empty_catalog_means_the_favicon_is_never_requested(monkeypatch):
    """El reproche que originó todo esto: pagar una sonda por un dato muerto no
    se justifica. Con el catálogo vacío la petición desaparece."""
    recorder = _probe_with_catalog(monkeypatch, FaviconCatalog([]))
    assert recorder.byte_paths == []


def test_a_populated_catalog_brings_the_request_back(monkeypatch):
    """Y vuelve sola en cuanto hay entradas: no hace falta tocar código para
    reactivarla, sólo poblar el feed."""
    catalog = FaviconCatalog([FaviconEntry(favicon_hash(b"icono"), "Jenkins",
                                           source="test")])
    recorder = _probe_with_catalog(monkeypatch, catalog)
    assert recorder.byte_paths == ["/favicon.ico"]
