"""Las rutas de configuración que codifica el SPA tienen que existir de verdad
(A11 en ``plans/deuda-tecnica-y-calidad.md``).

``web/app/src/views/ConfigView.vue`` enlaza cada control del formulario con
``store.configFlat['ruta.con.puntos']``. Ese ``configFlat`` es el aplanado de
lo que devuelve ``GET /system``, es decir de ``SecOpsConfig.json`` entero, así
que cada una de esas rutas literales es una ruta real dentro del JSON.

Los controles pintados con ``v-for`` no escriben la ruta entera, la componen
—``configFlat[`features.hygeia.limits.${limit.key}`]``—, así que el recorrido
de rutas literales no los ve. De esos se verifica el tramo fijo: que apunte a
una rama que existe de verdad, que es lo que se rompe al mover una clave.

El modo de fallo que esto cierra es silencioso en las dos direcciones:

- Un typo en la ruta del ``v-model`` no da error en ninguna parte. Vue crea
  la clave nueva en el objeto reactivo, el control se pinta perfectamente,
  el usuario edita... y al guardar se manda una clave que el backend no lee.
  El control simplemente no está enlazado a nada.
- Mover una clave en ``SecOpsConfig.json`` sin actualizar el ``.vue`` produce
  exactamente lo mismo, y además ``_cfg()`` devuelve el *default* cuando una
  ruta no resuelve, así que tampoco salta por el lado del backend.

Este test no unifica las tres fuentes (eso sería servir el esquema desde la
API), pero convierte esa divergencia en un fallo de CI, que es donde duele
barato. Complementa a ``test_config_shape.py``, que ata la otra pareja:
los getters de ``config_reading.py`` con el JSON.
"""

import json
import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

_REPO_ROOT = Path(__file__).resolve().parents[3]
_CONFIG_VIEW = _REPO_ROOT / "web" / "app" / "src" / "views" / "ConfigView.vue"
_SECOPS_CONFIG = _REPO_ROOT / "API" / "SecOpsConfig.json"

# store.configFlat['features.themis.enabled'] -> features.themis.enabled
_CONFIG_FLAT_PATH_RE = re.compile(r"configFlat\[\s*'([^']+)'\s*\]")

# Los controles que se pintan con v-for no escriben la ruta entera, la
# componen: configFlat[`features.hygeia.limits.${limit.key}`]. La parte
# variable no se puede resolver sin ejecutar el .vue, pero el tramo literal
# de delante sí, y es el que se rompe cuando alguien mueve una rama del JSON.
_CONFIG_FLAT_TEMPLATE_RE = re.compile(r"configFlat\[\s*`([^`]*?)\$\{")


def _config_view_paths() -> list[str]:
    source = _CONFIG_VIEW.read_text(encoding="utf-8")
    return sorted(set(_CONFIG_FLAT_PATH_RE.findall(source)))


def _config_view_branch_prefixes() -> list[str]:
    """Los tramos literales de las rutas compuestas, sin el punto final."""
    source = _CONFIG_VIEW.read_text(encoding="utf-8")
    return sorted({
        prefix.rstrip(".")
        for prefix in _CONFIG_FLAT_TEMPLATE_RE.findall(source)
        if prefix.strip(".")
    })


def _resolve(config: dict, dotted_path: str):
    """Resuelve una ruta con puntos, o lanza KeyError indicando dónde se rompe."""
    node = config
    walked: list[str] = []
    for key in dotted_path.split("."):
        if not isinstance(node, dict) or key not in node:
            reached = ".".join(walked) or "(raíz)"
            raise KeyError(f"se rompe en '{reached}' -> no existe '{key}'")
        node = node[key]
        walked.append(key)
    return node


@pytest.fixture(scope="module")
def secops_config() -> dict:
    return json.loads(_SECOPS_CONFIG.read_text(encoding="utf-8"))


def test_config_view_exists():
    """Si el .vue se renombra, este test debe caer en vez de pasar en vacío."""
    assert _CONFIG_VIEW.is_file(), f"no se encontró {_CONFIG_VIEW}"


def test_config_view_binds_some_paths():
    """Red de seguridad del propio test: si el regex deja de casar (porque el
    .vue pasa a otra forma de enlazar), esto cae en vez de dar por buenas cero
    rutas y pasar en verde sin comprobar nada."""
    paths = _config_view_paths()
    assert len(paths) > 30, f"solo se extrajeron {len(paths)} rutas de ConfigView.vue"


def test_every_config_view_path_exists_in_secops_config(secops_config):
    """Cada ruta enlazada en el formulario existe en SecOpsConfig.json."""
    broken = []
    for path in _config_view_paths():
        try:
            _resolve(secops_config, path)
        except KeyError as exc:
            broken.append(f"  {path}: {exc.args[0]}")

    assert not broken, (
        "ConfigView.vue enlaza rutas que no existen en SecOpsConfig.json.\n"
        "Un control con una ruta rota se pinta igual pero no guarda nada:\n"
        + "\n".join(broken)
    )


def test_every_config_view_path_points_at_a_leaf(secops_config):
    """Además de existir, la ruta tiene que apuntar a un valor, no a una rama.

    ``configFlat`` es el aplanado del JSON y solo contiene hojas (ver
    ``flatten`` en ``useUtils.js``: recursa en los objetos y solo asigna
    escalares y arrays). Una ruta que apunte a una rama no aparecería en
    ``configFlat``, así que el control quedaría igual de desconectado que con
    un typo — y esto no lo detecta el test anterior.
    """
    branches = []
    for path in _config_view_paths():
        value = _resolve(secops_config, path)
        if isinstance(value, dict):
            branches.append(f"  {path}: apunta a una rama ({sorted(value)[:4]}...), no a un valor")

    assert not branches, (
        "ConfigView.vue enlaza rutas que apuntan a una rama del JSON.\n"
        "`flatten` solo produce claves para hojas, así que ese control no se "
        "enlaza con nada:\n" + "\n".join(branches)
    )


def test_config_view_binds_some_composed_paths():
    """Red de seguridad del test de abajo, igual que la del de rutas literales:
    si el .vue dejara de componer rutas con plantillas, esto caería en vez de
    dar por buenos cero prefijos."""
    prefixes = _config_view_branch_prefixes()
    assert len(prefixes) > 5, f"solo se extrajeron {len(prefixes)} prefijos de ConfigView.vue"


def test_every_composed_path_prefix_is_a_real_branch(secops_config):
    """El tramo fijo de una ruta compuesta apunta a una rama que existe.

    Los controles que se pintan con ``v-for`` —los umbrales y los límites de
    Hygeia, los diales del motor de Lybra, el modelo de cada proveedor de IA—
    no llevan la ruta escrita entera, así que el test de rutas literales no
    los ve: son decenas de campos sin ninguna red debajo.

    Resolver la parte variable exigiría ejecutar el ``.vue``, pero no hace
    falta para cubrir el fallo que de verdad ocurre: mover o renombrar una
    rama del JSON. Si ``features.hygeia.limits`` pasara a llamarse de otra
    forma, el prefijo dejaría de resolver aquí — y en el panel, esos diez
    controles se pintarían igual sin estar enlazados a nada.
    """
    broken = []
    for prefix in _config_view_branch_prefixes():
        try:
            node = _resolve(secops_config, prefix)
        except KeyError as exc:
            broken.append(f"  {prefix}: {exc.args[0]}")
            continue
        if not isinstance(node, dict):
            broken.append(f"  {prefix}: existe pero es un valor, no una rama")

    assert not broken, (
        "ConfigView.vue compone rutas sobre prefijos que no son ramas del JSON.\n"
        "Los controles pintados con v-for se dibujan igual pero no guardan nada:\n"
        + "\n".join(broken)
    )
