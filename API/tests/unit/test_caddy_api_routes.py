"""La tabla de rutas del ``Caddyfile`` tiene que seguir a los blueprints de
Flask y a las rutas de vue-router.

``web/Caddyfile`` es el único sitio donde se decide, para cada URL, si la
petición va a Flask o si se sirve el ``index.html`` del SPA. Esa decisión
depende de dos ficheros que viven lejos y que nadie está obligado a mirar al
editarlos:

- ``API/run.py:_register_blueprints`` — los prefijos de la API. Si se registra
  un blueprint nuevo y no se añade al matcher ``@api``, Caddy se lleva la URL
  al ``handle`` final de respaldo y devuelve el ``index.html`` del SPA donde el
  cliente esperaba JSON. El síntoma es ``Unexpected token '<'`` en el
  navegador, lejísimos de la causa. Ya pasó con ``/hygeia``, ``/plans`` y
  ``/organizations`` (A15).
- ``web/app/src/router/index.js`` — las rutas del SPA. Las que cuelgan de un
  prefijo de la API (``/hygeia/activos``, ``/themis/escaneos``...) las captura
  el ``@api``, así que necesitan estar en ``@spa_bajo_prefijo_api``. Sin eso,
  la navegación interna funciona —vue-router no pasa por el proxy— pero
  recargar la página o pegar la URL a mano da el 404 de Flask. Ese es el modo
  de fallo que peor se detecta: solo se ve en producción y solo al recargar.

Y una tercera cosa, propia de Caddy: los dos ``handle`` son mutuamente
excluyentes y se evalúan en el ORDEN ESCRITO. Nginx tenía precedencia
implícita (un ``location =`` ganaba siempre, sin importar el orden en el
fichero); aquí no hay red. Invertir los dos bloques no da ningún error, manda
``/hygeia/activos`` a Flask. Por eso hay un test solo para el orden.

Este test convierte las tres divergencias en un fallo de CI. Sigue el patrón de
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
_CADDYFILE = _REPO_ROOT / "web" / "Caddyfile"
_ROUTER = _REPO_ROOT / "web" / "app" / "src" / "router" / "index.js"

# register_blueprint(themis_blp, url_prefix="/themis") -> /themis
_BLUEPRINT_RE = re.compile(r"""register_blueprint\(\s*\w+\s*,\s*url_prefix\s*=\s*["']([^"']+)["']""")

# path: '/hygeia/activos' -> /hygeia/activos
_ROUTE_RE = re.compile(r"^\s*path:\s*'([^']+)'", re.MULTILINE)

_SPA_MATCHER = "spa_bajo_prefijo_api"
_API_MATCHER = "api"


def _caddyfile_source() -> str:
    """El Caddyfile con los finales de línea normalizados.

    El repositorio se edita en Windows y git puede dejar el fichero con CRLF en
    el checkout. Cada matcher va en UNA línea (`caddy fmt` reescribe las
    continuaciones con `\\`), así que no hay nada más que unir.
    """
    return _CADDYFILE.read_text(encoding="utf-8").replace("\r\n", "\n")


def _matcher_paths(source: str, name: str) -> set[str]:
    """Los `path` de un matcher con nombre: `@api path /users /users/* ...`.

    El `assert` no es decorativo: si un cambio de formato deja de casar, sin él
    el conjunto quedaría vacío y las comprobaciones de abajo pasarían en vacío
    —exactamente el fallo mudo que este test existe para evitar—. Le pasó a la
    versión de nginx de este test, cuyos regex anclaban `location` en la
    columna 0.
    """
    match = re.search(rf"^\s*@{name}\s+path\s+(.*)$", source, re.MULTILINE)
    assert match, (
        f"No se encuentra el matcher `@{name} path ...` en web/Caddyfile. "
        f"Si se ha renombrado, hay que actualizar este test: sin él, la tabla "
        f"de rutas deja de estar verificada."
    )
    return set(match.group(1).split())


@pytest.fixture(scope="module")
def caddyfile() -> str:
    return _caddyfile_source()


@pytest.fixture(scope="module")
def blueprint_prefixes() -> set[str]:
    return set(_BLUEPRINT_RE.findall(_RUN_PY.read_text(encoding="utf-8")))


@pytest.fixture(scope="module")
def api_paths(caddyfile) -> set[str]:
    return _matcher_paths(caddyfile, _API_MATCHER)


@pytest.fixture(scope="module")
def spa_paths(caddyfile) -> set[str]:
    return _matcher_paths(caddyfile, _SPA_MATCHER)


@pytest.fixture(scope="module")
def spa_routes() -> set[str]:
    routes = set(_ROUTE_RE.findall(_ROUTER.read_text(encoding="utf-8")))
    # El comodín `/:pathMatch(.*)*` no es una URL, es la regla de captura final.
    return {route for route in routes if ":" not in route}


def _captura(patron: str, ruta: str) -> bool:
    """¿El `path` de un matcher de Caddy se lleva esta URL?

    `/users` es coincidencia exacta; `/users/*` es de prefijo, y el `*` casa
    también con la cadena vacía (`/users/*` se lleva `/users/`).
    """
    if patron.endswith("*"):
        return ruta.startswith(patron[:-1])
    return ruta == patron


def test_cada_blueprint_tiene_su_proxy(blueprint_prefixes, api_paths):
    """Todo prefijo registrado en Flask lo reenvía Caddy a la API."""
    faltan = {prefix for prefix in blueprint_prefixes if f"{prefix}/*" not in api_paths}
    assert not faltan, (
        f"Blueprints registrados en run.py que no aparecen en el matcher `@api` "
        f"de web/Caddyfile: {sorted(faltan)}. Hace falta la forma `<prefijo>/*`. "
        f"Sin ella Caddy devuelve el index.html del SPA donde el cliente espera "
        f"JSON."
    )


def test_no_se_reenvian_prefijos_que_ya_no_registra_nadie(blueprint_prefixes, api_paths):
    """Y al revés: un `path` en `@api` que ya no corresponde a ningún blueprint
    se come una ruta del SPA y la convierte en un 404 de la API.

    Venía de `test_nginx_api_prefixes.py`, que se retiró con nginx. Sus otras
    dos comprobaciones no sobrevivieron por motivos distintos: una la cubre
    `test_cada_blueprint_tiene_su_proxy`, y la que exigía que los dos bloques
    `server` compartieran el mismo `include` es imposible de violar ahora — el
    Caddyfile tiene UNA sola lista de direcciones, así que la tabla de rutas ya
    no se puede escribir dos veces.
    """
    registrados = {prefix.strip("/") for prefix in blueprint_prefixes}
    reenviados = {path.strip("/*").strip("/").split("/")[0] for path in api_paths}
    desconocidos = reenviados - registrados
    assert not desconocidos, (
        f"El matcher `@api` de web/Caddyfile reenvía prefijos que run.py no "
        f"registra: {sorted(desconocidos)}. Si el módulo se retiró, quita también "
        f"su entrada; mientras siga ahí se traga cualquier ruta del SPA que "
        f"cuelgue de ese prefijo."
    )


def test_las_rutas_del_spa_bajo_un_prefijo_de_api_no_se_las_traga_flask(api_paths, spa_paths, spa_routes):
    """Ninguna ruta del SPA queda capturada por el matcher `@api`.

    Solo la rescata su propia entrada en `@spa_bajo_prefijo_api`, que se evalúa
    antes.
    """
    capturadas = {
        route for route in spa_routes if any(_captura(patron, route) for patron in api_paths)
    }
    sin_rescatar = capturadas - spa_paths
    assert not sin_rescatar, (
        f"Rutas de vue-router que Caddy manda a Flask: {sorted(sin_rescatar)}. "
        f"Añádelas al matcher `@spa_bajo_prefijo_api` de web/Caddyfile. Si la "
        f"ruta choca de frente con un endpoint real de la API (misma URL exacta "
        f"sirviendo dos cosas), ningún proxy puede desambiguarla: hay que "
        f"renombrarla en el router, como se hizo con /users -> /usuarios."
    )


def test_no_quedan_matchers_del_spa_para_rutas_que_ya_no_existen(spa_paths, spa_routes):
    """El contrato también se rompe al revés: borrar una ruta del router y
    dejarse su entrada aquí. No da error, pero engaña al siguiente que lea el
    fichero creyendo que esa URL existe."""
    # Los hubs se declaran con barra final a propósito (los usuarios la escriben
    # a mano), pero en el router son `/themis`, `/aegis`... sin ella.
    huerfanas = {
        path for path in spa_paths if path not in spa_routes and path.rstrip("/") not in spa_routes
    }
    assert not huerfanas, (
        f"Entradas de `@spa_bajo_prefijo_api` en web/Caddyfile sin ruta "
        f"correspondiente en web/app/src/router/index.js: {sorted(huerfanas)}"
    )


def test_el_handle_del_spa_va_antes_que_el_de_la_api(caddyfile):
    """El orden escrito de los dos `handle` ES la regla de precedencia.

    `handle` es mutuamente excluyente y gana el primero que casa. Como
    `path /themis/*` casa también con `/themis/`, invertir los dos bloques se
    lleva a Flask todos los hubs y subrutas del SPA. No da error de sintaxis ni
    aviso al arrancar: solo un 404 al recargar la página en producción.
    """
    spa = caddyfile.index(f"handle @{_SPA_MATCHER}")
    api = caddyfile.index(f"handle @{_API_MATCHER}")
    assert spa < api, (
        "En web/Caddyfile el `handle @api` está escrito ANTES que el "
        "`handle @spa_bajo_prefijo_api`. Los `handle` se evalúan en orden y "
        "`@api` incluye `/themis/*`, `/hygeia/*`..., así que se lleva a Flask "
        "las rutas del SPA que el otro bloque debía rescatar."
    )
