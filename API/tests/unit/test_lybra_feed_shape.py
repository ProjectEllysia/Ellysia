"""El feed de checks está bien formado (L27).

El feed son **datos que se ejecutan**: diecisiete reglas en YAML que deciden si
un hallazgo de seguridad existe. Hasta ahora ningún test comprobaba que
estuvieran bien formadas, y su modo de fallo es el peor posible — el silencio.
Un ``tlsRule`` mal escrito, un ``script`` que no existe, un ``type`` con un
typo: en los tres casos el check no aplica nunca, el escaneo termina en verde,
y lo único que pasa es que una vulnerabilidad deja de detectarse.

Este fichero hace con el feed lo que ``test_config_shape.py`` hace con el enum
``ScanType`` y ``test_config_view_paths.py`` con las rutas de configuración:
convertir en fallo de CI algo que hasta ahora sólo se detectaba leyendo.

Dos bloques, y el segundo importa tanto como el primero:

1. El feed empaquetado pasa la validación entera.
2. La validación **encuentra** cada tipo de rotura cuando se la mete a
   propósito. Sin esto, un validador que devolviera siempre una lista vacía
   dejaría el primer bloque en verde para siempre.
"""

from dataclasses import replace

import pytest

from src.modules.features.themis.lybra.checks import (
    CHECKS_FEED_VERSION,
    Matcher,
    Request,
    load_checks,
    validate_checks,
)

pytestmark = pytest.mark.unit


@pytest.fixture(scope="module")
def feed():
    return load_checks()


# ============================================================ el feed de serie

def test_the_bundled_feed_is_completely_well_formed(feed):
    """La afirmación de fondo: ningún check del feed está muerto por
    construcción. No dice que los checks sean *buenos* —eso lo miden los bancos
    de precisión—, sino que todos pueden llegar a ejecutarse."""
    assert validate_checks(feed) == []


def test_the_feed_is_not_empty_and_declares_its_version(feed):
    """Un feed vacío pasaría todas las validaciones de forma vacua. Y sin
    ``CHECKS_FEED_VERSION`` un hallazgo guardado no puede decir con qué reglas
    se produjo."""
    assert feed
    assert CHECKS_FEED_VERSION.startswith("lybra-checks-")


def test_no_two_checks_share_an_identifier(feed):
    """``check_id`` es ``namespace:id@version`` y viaja hasta el hallazgo
    guardado. Dos checks con el mismo par serían indistinguibles en el informe,
    y el ciclo de vida (que correlaciona hallazgos entre escaneos por su
    identidad) los trataría como uno solo."""
    identifiers = [check.check_id for check in feed]
    assert len(identifiers) == len(set(identifiers))


# ===================================================== la validación sí detecta
#
# Cada caso rompe un campo de un check real y comprueba que el problema sale
# nombrado. Un validador que no distinguiera estos casos dejaría el bloque de
# arriba en verde diciendo nada.

def _first_of_type(feed, check_type):
    return next(check for check in feed if check.type == check_type)


@pytest.mark.parametrize("field,value,needle", [
    ("type",     "htpp",      "tipo"),
    ("mode",     "agresivo",  "modo"),
    ("severity", "GRAVE",     "severidad"),
    ("category", "exposicion", "categoría"),
    ("version",  0,           "entero positivo"),
])
def test_a_broken_field_is_reported(feed, field, value, needle):
    broken = replace(_first_of_type(feed, "http"), **{field: value})
    problems = validate_checks([broken])
    assert any(needle in problem for problem in problems), problems


def test_an_unimplemented_tls_rule_is_reported(feed):
    """Un ``tlsRule`` inválido cae por ``check.tls_rule not in _TLS_RULES`` en
    ``_applies_tls``, que es exactamente igual que "este check no aplicaba a
    este host": normal, esperable, invisible."""
    broken = replace(_first_of_type(feed, "tls"), tls_rule="caducado")
    assert any("regla TLS" in problem for problem in validate_checks([broken]))


def test_a_script_without_plugin_is_reported(feed):
    """Igual que el anterior pero por ``plugin is None`` en ``_applies_script``:
    el check se carga, se valida, y no corre jamás."""
    broken = replace(_first_of_type(feed, "script"), script="smb-signing")
    assert any("script" in problem for problem in validate_checks([broken]))


def test_a_network_service_without_predicate_is_reported(feed):
    """El caso de #272: un check ``network`` para un protocolo que ningún
    predicado reconoce. Aquel arreglo lo hizo fallar al cargar; esta validación
    lo encuentra además sobre un feed externo, que no pasa por ese camino."""
    broken = replace(_first_of_type(feed, "network"), service="postgres")
    assert any("predicado" in problem for problem in validate_checks([broken]))


def test_a_check_without_requests_is_reported(feed):
    broken = replace(_first_of_type(feed, "http"), requests=())
    assert any("sin ninguna petición" in problem for problem in validate_checks([broken]))


def test_a_request_without_matchers_is_reported(feed):
    """Una petición sin matchers no decide nada: se hace el viaje a la red y no
    se mira la respuesta."""
    broken = replace(_first_of_type(feed, "http"),
                     requests=(Request(method="GET", path="/", matchers=()),))
    assert any("sin ningún matcher" in problem for problem in validate_checks([broken]))


@pytest.mark.parametrize("matcher,needle", [
    (Matcher(type="palabra", part="body", values=("x",)), "tipo"),
    (Matcher(type="word", part="headers", values=("x",)), "parte"),
    (Matcher(type="word", part="body", values=()),        "sin valores"),
])
def test_a_broken_matcher_is_reported(feed, matcher, needle):
    """Los tres modos de romper un matcher, y el segundo es el más traicionero:
    ``part: "headers"`` en plural no es un error, es una búsqueda en el cuerpo
    —el defecto— que nunca encuentra la cabecera que el autor buscaba."""
    broken = replace(_first_of_type(feed, "http"),
                     requests=(Request(method="GET", path="/", matchers=(matcher,)),))
    assert any(needle in problem for problem in validate_checks([broken]))


def test_a_duplicated_identifier_is_reported(feed):
    check = _first_of_type(feed, "http")
    assert any("duplicado" in problem for problem in validate_checks([check, check]))


def test_an_unknown_read_mode_is_reported(feed):
    """El parseo ya rechaza un ``read`` desconocido al cargar el feed, así que
    aquí hay que construir la petición a mano. La validación lo cubre igual
    porque también se le pueden pasar checks que no vinieron de ``load_checks``
    — los traducidos de plantillas de Nuclei, por ejemplo."""
    broken = replace(
        _first_of_type(feed, "network"),
        requests=(Request(method="GET", path="/", read="parrafo",
                          matchers=(Matcher(type="word", values=("x",)),)),),
    )
    assert any("modo de lectura" in problem for problem in validate_checks([broken]))
