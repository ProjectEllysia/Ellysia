"""La tabla de ``location`` de nginx tiene que seguir a los blueprints de Flask
y a las rutas de vue-router.

``web/api-locations.conf`` es el único sitio donde se decide, para cada URL, si
la petición va a Flask o si se sirve el ``index.html`` del SPA. Esa decisión
depende de dos ficheros que viven lejos y que nadie está obligado a mirar al
editarlos:

- ``API/run.py:_register_blueprints`` — los prefijos de la API. Si se registra
  un blueprint nuevo y no se añade aquí, nginx se lleva la URL al ``location /``
  de respaldo y devuelve el ``index.html`` del SPA donde el cliente esperaba
  JSON. El síntoma es ``Unexpected token '<'`` en el navegador, lejísimos de la
  causa. Ya pasó con ``/hygeia``, ``/plans`` y ``/organizations`` (A15).
- ``web/app/src/router/index.js`` — las rutas del SPA. Las que cuelgan de un
  prefijo de la API (``/hygeia/activos``, ``/themis/escaneos``...) las captura
  el ``proxy_pass`` de ese prefijo, así que necesitan su propio ``location =``
  con ``try_files``. Sin él, la navegación interna funciona —vue-router no pasa
  por nginx— pero recargar la página o pegar la URL a mano da el 404 de Flask.
  Ese es el modo de fallo que peor se detecta: solo se ve en producción y solo
  al recargar.

Este test convierte las dos divergencias en un fallo de CI. Sigue el patrón de
``test_config_view_paths.py``, que ata la otra pareja cruzada del monorepo
(``ConfigView.vue`` con ``SecOpsConfig.json``) leyendo el fuente y comparando,
sin arrancar la app.

Es también la razón principal por la que ``web/`` y ``API/`` siguen en el mismo
repositorio: separados, este contrato no se puede verificar en ningún CI.
"""

import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

_REPO_ROOT = Path(__file__).resolve().parents[3]
_RUN_PY = _REPO_ROOT / "API" / "run.py"
_API_LOCATIONS = _REPO_ROOT / "web" / "api-locations.conf"
_ROUTER = _REPO_ROOT / "web" / "app" / "src" / "router" / "index.js"

# register_blueprint(themis_blp, url_prefix="/themis") -> /themis
_BLUEPRINT_RE = re.compile(r"""register_blueprint\(\s*\w+\s*,\s*url_prefix\s*=\s*["']([^"']+)["']""")

# location /themis/  { proxy_pass ... }  -> /themis/
_PROXY_PREFIX_RE = re.compile(r"^location\s+(/\S*)\s*\{\s*proxy_pass", re.MULTILINE)
# location = /users  { proxy_pass ... }  -> /users
_PROXY_EXACT_RE = re.compile(r"^location\s+=\s+(/\S*)\s*\{\s*proxy_pass", re.MULTILINE)
# location = /hygeia/activos { try_files ... } -> /hygeia/activos
_SPA_EXACT_RE = re.compile(r"^location\s+=\s+(/\S*)\s*\{\s*try_files", re.MULTILINE)

# path: '/hygeia/activos' -> /hygeia/activos
_ROUTE_RE = re.compile(r"^\s*path:\s*'([^']+)'", re.MULTILINE)


@pytest.fixture(scope="module")
def blueprint_prefixes() -> set[str]:
    return set(_BLUEPRINT_RE.findall(_RUN_PY.read_text(encoding="utf-8")))


@pytest.fixture(scope="module")
def nginx() -> dict[str, set[str]]:
    source = _API_LOCATIONS.read_text(encoding="utf-8")
    return {
        # Los de prefijo son los que NO llevan `=`; el regex de arriba los pilla
        # a los dos, así que se restan los exactos.
        "proxy_prefix": set(_PROXY_PREFIX_RE.findall(source)),
        "proxy_exact": set(_PROXY_EXACT_RE.findall(source)),
        "spa_exact": set(_SPA_EXACT_RE.findall(source)),
    }


@pytest.fixture(scope="module")
def spa_routes() -> set[str]:
    routes = set(_ROUTE_RE.findall(_ROUTER.read_text(encoding="utf-8")))
    # El comodín `/:pathMatch(.*)*` no es una URL, es la regla de captura final.
    return {route for route in routes if ":" not in route}


def test_cada_blueprint_tiene_su_proxy_pass(blueprint_prefixes, nginx):
    """Todo prefijo registrado en Flask se reenvía desde nginx."""
    proxied = nginx["proxy_prefix"] - nginx["proxy_exact"]
    faltan = {prefix for prefix in blueprint_prefixes if f"{prefix}/" not in proxied}
    assert not faltan, (
        f"Blueprints registrados en run.py sin `location /<prefijo>/ {{ proxy_pass }}` "
        f"en web/api-locations.conf: {sorted(faltan)}. Sin esa línea nginx devuelve el "
        f"index.html del SPA donde el cliente espera JSON."
    )


def test_las_rutas_del_spa_bajo_un_prefijo_de_api_no_se_las_traga_flask(
    blueprint_prefixes, nginx, spa_routes
):
    """Ninguna ruta del SPA queda capturada por un `proxy_pass`.

    Una ruta está capturada si la pilla un ``location = <ruta>`` de proxy o un
    ``location /<prefijo>/`` de proxy. Solo la rescata su propio
    ``location = <ruta> { try_files ... }``.
    """
    proxy_prefixes = nginx["proxy_prefix"] - nginx["proxy_exact"]
    capturadas = {
        route
        for route in spa_routes
        if route in nginx["proxy_exact"]
        or any(route.startswith(prefix) for prefix in proxy_prefixes)
    }
    sin_rescatar = capturadas - nginx["spa_exact"]
    assert not sin_rescatar, (
        f"Rutas de vue-router que nginx manda a Flask: {sorted(sin_rescatar)}. "
        f"Añade `location = <ruta> {{ try_files $uri /index.html; }}` en "
        f"web/api-locations.conf. Si la ruta choca con un endpoint real de la API "
        f"(un `location =` no puede servir a los dos), renómbrala en el router."
    )


def test_no_quedan_locations_del_spa_para_rutas_que_ya_no_existen(nginx, spa_routes):
    """El contrato también se rompe al revés: borrar una ruta del router y
    dejarse su `location` aquí. No da error, pero engaña al siguiente que lea
    el fichero creyendo que esa URL existe."""
    # Los hubs se declaran con barra final a propósito (los usuarios la escriben
    # a mano), pero en el router son `/themis`, `/aegis`... sin ella.
    huerfanas = {
        location
        for location in nginx["spa_exact"]
        if location not in spa_routes and location.rstrip("/") not in spa_routes
    }
    assert not huerfanas, (
        f"`location = ... {{ try_files }}` en web/api-locations.conf sin ruta "
        f"correspondiente en web/app/src/router/index.js: {sorted(huerfanas)}"
    )
