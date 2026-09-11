"""El DSL de checks: variables extraídas, encadenamiento y payloads.

El motor sabía hacer una petición y mirar la respuesta, y nada más. No podía
leer un dato de una respuesta y usarlo en la siguiente (login → recurso
protegido), ni probar la misma ruta con veinte nombres de fichero sin escribir
veinte checks. Esto añade las tres piezas que faltaban —**extractores**,
**cuerpo/cabeceras** y **payloads con tope**— y aquí se prueban las tres, más
las dos reglas que las hacen seguras: un extractor que no casa **aborta** la
cadena, y un payload **nunca** supera el tope de expansiones.
"""

import pytest

from src.modules.features.themis.lybra.checks import (
    Check,
    CheckRuntime,
    Extractor,
    Matcher,
    Request,
    Response,
    Service,
    _substitute,
    load_checks,
    validate_checks,
)

pytestmark = pytest.mark.unit

_SVC = Service(80, "tcp", "http", None, None, None)


def _run(check, fetch, **kwargs):
    return CheckRuntime([check], fetch, **kwargs).run("10.0.0.1", [_SVC])


# =============================================== sustitución de variables (unidad)


def test_substitute_replaces_a_bound_variable():
    assert _substitute("/user/{{id}}", {"id": "42"}) == "/user/42"


def test_substitute_leaves_an_unbound_marker_verbatim():
    """Un marcador sin valor se deja tal cual —no se borra— para que un typo
    falle a la vista (una ruta con ``{{fil}}`` literal da un 404 visible) en vez
    de sondear ``/`` en silencio y parecer que corrió."""
    assert _substitute("/{{fil}}", {"name": "x"}) == "/{{fil}}"


def test_substitute_does_not_re_expand_a_value():
    """Una sola pasada: un valor que a su vez trae ``{{...}}`` no se vuelve a
    expandir. El valor viene del objetivo, y re-expandirlo dejaría que una
    respuesta dirigiera las peticiones siguientes."""
    assert _substitute("{{a}}", {"a": "{{b}}", "b": "x"}) == "{{b}}"


# =============================================== extractores + encadenamiento


def test_an_extractor_binds_a_value_for_the_next_request():
    """La pieza que convierte dos peticiones sueltas en una cadena: la primera
    extrae un token, la segunda lo usa en la ruta."""
    first = Request(
        path="/token",
        matchers=(Matcher(type="status", values=(200,)),),
        extractors=(Extractor(name="tok", pattern=r"TOKEN=([A-Z0-9]+)"),),
    )
    second = Request(
        path="/resource/{{tok}}",
        matchers=(Matcher(type="status", values=(200,)),),
    )
    check = Check(id="chain", version=1, type="http", category="exposed_service",
                  severity="HIGH", service="http", mode="safe",
                  requests=(first, second), finding={"title": "x"})

    requested = []

    def fetch(host, port, method, path, *args):
        requested.append(path)
        if path == "/token":
            return Response(200, "TOKEN=ABC123", {})
        if path == "/resource/ABC123":
            return Response(200, "ok", {})
        return Response(404, "", {})

    assert [f["check_id"] for f in _run(check, fetch)] == ["lybra:chain@1"]
    assert requested == ["/token", "/resource/ABC123"]


def test_a_login_chain_uses_body_and_headers():
    """El criterio de cierre entero: login (POST con cuerpo) → recurso protegido
    (GET con el token de sesión en una cabecera), encadenados por una variable
    extraída de la respuesta del login."""
    login = Request(
        method="POST", path="/login", body="user=admin&pass={{pw}}",
        matchers=(Matcher(type="status", values=(200,)),),
        extractors=(Extractor(name="sid", pattern=r"sid: ([A-Za-z0-9]+)", part="header"),),
    )
    protected = Request(
        method="GET", path="/admin", headers=(("Cookie", "session={{sid}}"),),
        matchers=(Matcher(type="word", part="body", values=("bienvenido",)),),
    )
    # ``pw`` llega como payload de un solo valor: prueba de paso que payload y
    # extracción conviven en la misma cadena.
    check = Check(id="login", version=1, type="http", category="exposed_service",
                  severity="HIGH", service="http", mode="safe",
                  payloads=(("pw", ("s3cret",)),),
                  requests=(login, protected), finding={"title": "x"})

    def fetch(host, port, method, path, body=None, headers=None):
        if method == "POST" and path == "/login":
            assert body == "user=admin&pass=s3cret", body
            return Response(200, "", {"sid": "Tok9"})
        if method == "GET" and path == "/admin":
            assert headers == {"Cookie": "session=Tok9"}, headers
            return Response(200, "bienvenido", {})
        return Response(404, "", {})

    assert [f["check_id"] for f in _run(check, fetch)] == ["lybra:login@1"]


def test_an_extractor_that_does_not_match_aborts_the_check():
    """La regla que hace fiable el encadenamiento: si el extractor no encuentra
    su valor, la cadena no puede continuar honestamente, así que el check no
    dispara —ni siquiera lanza la petición siguiente."""
    first = Request(
        path="/token",
        matchers=(Matcher(type="status", values=(200,)),),
        extractors=(Extractor(name="tok", pattern=r"NO_APARECE=([0-9]+)"),),
    )
    second = Request(path="/resource/{{tok}}",
                     matchers=(Matcher(type="status", values=(200,)),))
    check = Check(id="chain", version=1, type="http", category="exposed_service",
                  severity="HIGH", service="http", mode="safe",
                  requests=(first, second), finding={"title": "x"})

    requested = []

    def fetch(host, port, method, path, *args):
        requested.append(path)
        return Response(200, "sin token aquí", {})

    assert _run(check, fetch) == []
    assert requested == ["/token"]        # la segunda petición nunca se lanza


def test_a_backward_compatible_fetch_still_works_for_plain_checks():
    """Un check sin cuerpo ni cabeceras llama al ``fetch`` con los cuatro
    argumentos posicionales de siempre, así que un ``fetch`` de test escrito
    ``(host, port, method, path)`` sigue valiendo —sólo los checks que de
    verdad mandan cuerpo o cabeceras necesitan un ``fetch`` que los acepte."""
    check = Check(id="plain", version=1, type="http", category="exposed_path",
                  severity="HIGH", service="http", mode="safe",
                  requests=(Request(path="/.git/config",
                                    matchers=(Matcher(type="status", values=(200,)),)),),
                  finding={"title": "x"})

    def four_arg_fetch(host, port, method, path):     # exactamente cuatro
        return Response(200, "", {})

    assert [f["check_id"] for f in _run(check, four_arg_fetch)] == ["lybra:plain@1"]


# =============================================== payloads + tope


def _sql_dump_check():
    return [c for c in load_checks() if c.id == "sql-dump-exposure"][0]


def test_a_payload_expands_one_request_over_many_values():
    """Un check con payloads prueba cada valor sin escribir un check por
    valor: aquí, siete nombres de volcado SQL con una sola entrada de feed."""
    check = _sql_dump_check()
    tried = []

    def fetch(host, port, method, path, *args):
        tried.append(path)
        if path == "/db.sql":
            return Response(200, "INSERT INTO users VALUES (1);", {})
        return Response(404, "", {})

    assert [f["check_id"] for f in _run(check, fetch)] == ["lybra:sql-dump-exposure@1"]
    assert "/backup.sql" in tried and "/db.sql" in tried


def test_a_payload_never_exceeds_the_expansion_cap():
    """El tope no es opcional: es lo que impide que un payload se convierta en
    un barrido. Con el tope en 2, sólo se prueban dos valores —aunque un valor
    posterior sí existiría, no se llega a él y el check no dispara."""
    check = _sql_dump_check()
    tried = []

    def fetch(host, port, method, path, *args):
        tried.append(path)
        # database.sql es el tercer payload: existiría, pero el tope lo deja fuera
        return Response(200, "CREATE TABLE x", {}) if path == "/database.sql" else Response(404, "", {})

    findings = _run(check, fetch, max_payload_expansions=2)
    assert findings == []
    assert len(tried) == 2


def test_the_first_matching_payload_wins_as_a_single_finding():
    """Veinte sondas colapsan en un hallazgo: en cuanto un valor pica, el check
    dispara una vez y no sigue probando el resto."""
    check = _sql_dump_check()
    tried = []

    def fetch(host, port, method, path, *args):
        tried.append(path)
        return Response(200, "CREATE TABLE x", {})       # todos "existen"

    findings = _run(check, fetch)
    assert len(findings) == 1
    assert len(tried) == 1                                # paró en el primero


# ===================================================== validación de forma (CI)


def test_the_shipped_feed_including_the_payload_check_is_well_formed():
    assert validate_checks(load_checks()) == []


def test_an_extractor_with_an_invalid_regex_is_reported():
    bad = Request(path="/", matchers=(Matcher(type="status", values=(200,)),),
                  extractors=(Extractor(name="x", pattern="(sin cerrar"),))
    check = Check(id="bad", version=1, type="http", category="exposed_path",
                  severity="HIGH", service="http", mode="safe",
                  requests=(bad,), finding={})
    assert any("patrón inválido" in problem for problem in validate_checks([check]))


def test_an_extractor_without_a_name_is_reported():
    bad = Request(path="/", matchers=(Matcher(type="status", values=(200,)),),
                  extractors=(Extractor(name="", pattern="x"),))
    check = Check(id="bad", version=1, type="http", category="exposed_path",
                  severity="HIGH", service="http", mode="safe",
                  requests=(bad,), finding={})
    assert any("'name'" in problem for problem in validate_checks([check]))


def test_a_payload_with_no_values_is_reported():
    check = Check(id="bad", version=1, type="http", category="exposed_path",
                  severity="HIGH", service="http", mode="safe",
                  payloads=(("name", ()),),
                  requests=(Request(path="/{{name}}",
                                    matchers=(Matcher(type="status", values=(200,)),)),),
                  finding={})
    assert any("no tiene ningún valor" in problem for problem in validate_checks([check]))
