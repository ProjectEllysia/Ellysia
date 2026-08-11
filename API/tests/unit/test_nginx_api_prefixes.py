"""Los prefijos que nginx reenvía a Flask tienen que ser los que registra
``run.py`` (A15 en ``plans/deuda-tecnica-y-calidad.md``).

La lista vivía escrita dos veces dentro de ``web/nginx.conf`` —un bloque
``server`` por cada origen que sirve el SPA— y divergió dos veces sin que nadie
se enterara:

- ``/hygeia`` nunca se añadió, así que Hygeia funcionaba en desarrollo (donde
  proxya Vite) y estaba roto en el despliegue con contenedores.
- Al estrenar la capa comercial se añadieron ``/plans`` y ``/organizations`` a
  ``vite.config.js`` y no a nginx, con el mismo resultado.

El fallo es silencioso y caro de diagnosticar: nginx no da error, cae en
``location /`` y devuelve el ``index.html`` del SPA donde se esperaba JSON. El
cliente revienta con ``Unexpected token '<'``, que no señala a ninguna parte.

La duplicación ya está resuelta (ambos bloques incluyen
``web/api-locations.conf``). Lo que cierra este test es la otra mitad: que ese
fichero siga a ``run.py``, que es la verdad. Mismo criterio que
``test_config_view_paths.py``.
"""

import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

_REPO_ROOT = Path(__file__).resolve().parents[3]
_RUN_PY = _REPO_ROOT / "API" / "run.py"
_API_LOCATIONS = _REPO_ROOT / "web" / "api-locations.conf"
_NGINX_CONF = _REPO_ROOT / "web" / "nginx.conf"

# register_blueprint(plans_blp, url_prefix="/plans") -> plans
_URL_PREFIX_RE = re.compile(r'url_prefix\s*=\s*"/([^/"]+)"')

# location /plans/  |  location = /plans   -> plans
_LOCATION_RE = re.compile(r"^\s*location\s+(?:=\s+)?/([^/\s{]+)/?\s*\{", re.MULTILINE)


def _registered_prefixes() -> set[str]:
    return set(_URL_PREFIX_RE.findall(_RUN_PY.read_text(encoding="utf-8")))


def _proxied_prefixes() -> set[str]:
    return set(_LOCATION_RE.findall(_API_LOCATIONS.read_text(encoding="utf-8")))


def test_nginx_proxies_every_registered_blueprint():
    """Ningún módulo puede quedarse sin su `location`.

    Es el fallo que ya ocurrió con Hygeia, con planes y con organizaciones.
    """
    missing = _registered_prefixes() - _proxied_prefixes()
    assert not missing, (
        f"Estos prefijos se registran en run.py pero nginx no los reenvía: "
        f"{sorted(missing)}. En el despliegue con contenedores devolverán el "
        f"index.html del SPA en vez de JSON. Añádelos a web/api-locations.conf."
    )


def test_nginx_does_not_proxy_unknown_prefixes():
    """Y al revés: un `location` que ya no corresponde a ningún blueprint se
    come una ruta del SPA y la convierte en un 404 de la API."""
    unknown = _proxied_prefixes() - _registered_prefixes()
    assert not unknown, (
        f"web/api-locations.conf reenvía prefijos que run.py no registra: "
        f"{sorted(unknown)}. Si el módulo se retiró, quita también su location."
    )


def test_both_spa_server_blocks_use_the_shared_include():
    """La lista tiene que seguir en UN solo sitio.

    Los dos bloques `server` que sirven el SPA (localhost sin TLS y los
    dominios reales con TLS) deben incluir el mismo fichero. Si alguien vuelve
    a pegar las `location` a mano en uno de ellos, esto lo caza antes de que
    los dos vuelvan a contar cosas distintas.
    """
    nginx_conf = _NGINX_CONF.read_text(encoding="utf-8")
    includes = nginx_conf.count("include /etc/nginx/api-locations.conf;")
    assert includes == 2, (
        f"Se esperaban 2 inclusiones de api-locations.conf (un bloque server "
        f"por origen que sirve el SPA) y hay {includes}."
    )
    # Y que no haya vuelto a aparecer la lista a mano fuera del include.
    inline = re.findall(r"location\s+(?:=\s+)?/\w+/?\s*\{[^}]*Ellysia-API", nginx_conf)
    assert not inline, (
        f"Hay {len(inline)} location(s) hacia Ellysia-API escritas directamente "
        f"en nginx.conf: van en web/api-locations.conf."
    )
