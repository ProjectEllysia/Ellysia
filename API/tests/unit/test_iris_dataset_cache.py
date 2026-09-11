"""Un cambio de configuración llega al siguiente análisis.

Los datasets de detección de Iris —marcas, proveedores gratuitos, keywords,
TLDs sospechosos, tabla de homóglifos— se cachean, y con razón: se consultan
en cada regla de cada análisis. El problema era la clave de esa caché.

Era el nombre del dataset a secas, y las cachés eran permanentes. Recargar la
configuración (``PUT /system`` en la API, o el ``reload_if_changed()`` que el
worker hace antes de cada job) sustituía el árbol ``_configs`` pero dejaba en
pie los valores viejos. Un cambio guardado desde ConfigView no llegaba al
siguiente análisis, y no había forma de enterarse: nada fallaba, simplemente
se seguía analizando con los datos anteriores.
"""

from __future__ import annotations

import pytest

import src.modules.system.config_reading as CR
from src.modules.features.iris.services import wordlists

pytestmark = pytest.mark.unit


@pytest.fixture()
def config_tree(monkeypatch):
    """Devuelve una función que instala un árbol de configuración completo.

    Sustituye ``_configs`` entero, que es lo que hacen de verdad ``reload()``,
    ``reload_if_changed()`` y ``save_full_config()`` — no se parchea el getter,
    porque entonces el test no probaría el mecanismo que se está arreglando.
    """
    def _install(iris_data: dict):
        monkeypatch.setattr(
            CR, "_configs",
            {"features": {"iris": {"data": iris_data}}},
            raising=False,
        )
    return _install


def test_a_changed_dataset_reaches_the_next_analysis(config_tree):
    """El caso del issue: se añade una marca y el siguiente análisis la ve."""
    config_tree({"canonical_brands": ["paypal"]})
    assert "acmebank" not in wordlists.canonical_brands()

    config_tree({"canonical_brands": ["paypal", "acmebank"]})

    assert "acmebank" in wordlists.canonical_brands()


def test_a_removed_entry_also_disappears(config_tree):
    """Y en la otra dirección: quitar una marca tiene que quitarla de verdad.

    Importa tanto o más que añadir — una entrada que sobrevive a su borrado
    sigue generando hallazgos que el operador cree haber desactivado.
    """
    config_tree({"canonical_brands": ["paypal", "acmebank"]})
    assert "acmebank" in wordlists.canonical_brands()

    config_tree({"canonical_brands": ["paypal"]})

    assert "acmebank" not in wordlists.canonical_brands()


def test_tuple_datasets_follow_the_configuration_too(config_tree):
    """Los datasets ordenados usan otra caché (``_cached_tuple``): también."""
    config_tree({"free_provider_domains": ["gmail.com"]})
    assert wordlists.free_provider_domains() == ("gmail.com",)

    config_tree({"free_provider_domains": ["gmail.com", "correo.example"]})

    assert wordlists.free_provider_domains() == ("gmail.com", "correo.example")


def test_the_homoglyph_table_follows_the_configuration(config_tree):
    """La tabla de homóglifos se construye una vez y se cachea aparte."""
    config_tree({"homoglyph_map": {"0": "o"}})
    # Con solo el 0 mapeado, el 1 se queda como está.
    assert "paypa1".translate(wordlists.homoglyph_table()) == "paypa1"

    config_tree({"homoglyph_map": {"0": "o", "1": "l"}})

    assert "paypa1".translate(wordlists.homoglyph_table()) == "paypal"


def test_phrase_patterns_are_recompiled(config_tree):
    """Las frases se compilan a una expresión regular, que es la caché más
    cara de todas y por tanto la más tentadora de dejar permanente."""
    config_tree({"bec_phrases": ["cambio de cuenta"]})
    assert wordlists.phrase_matches("bec_phrases", "urge un pago inmediato") == []

    config_tree({"bec_phrases": ["cambio de cuenta", "pago inmediato"]})

    assert wordlists.phrase_matches("bec_phrases", "urge un pago inmediato") == ["pago inmediato"]


def test_brand_trusted_domains_follow_the_configuration(config_tree):
    config_tree({"brand_trusted_domains": [{"keywords": ["paypal"], "domains": ["paypal.com"]}]})
    assert wordlists.brand_trusted_domains() == ((("paypal",), ("paypal.com",)),)

    config_tree({"brand_trusted_domains": [{"keywords": ["acme"], "domains": ["acme.example"]}]})

    assert wordlists.brand_trusted_domains() == ((("acme",), ("acme.example",)),)


def test_reading_twice_without_changes_uses_the_cache(config_tree):
    """La invalidación no puede costar la caché: leer dos veces con la misma
    configuración tiene que devolver **el mismo objeto**, no reconstruirlo.

    Estos datasets se consultan en cada regla de cada análisis; recalcularlos
    cada vez es precisamente lo que la caché existe para evitar.
    """
    config_tree({"canonical_brands": ["paypal"]})

    first = wordlists.canonical_brands()
    second = wordlists.canonical_brands()

    assert first is second


def test_config_version_changes_when_the_tree_is_replaced(config_tree):
    """La pieza en la que se apoya todo lo anterior."""
    config_tree({"canonical_brands": ["paypal"]})
    before = CR.config_version()

    config_tree({"canonical_brands": ["acmebank"]})

    assert CR.config_version() != before
