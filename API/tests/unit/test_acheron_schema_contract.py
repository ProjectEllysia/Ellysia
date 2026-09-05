"""El registro de storables de la API tiene que seguir a ``AcheronSchema``.

El catálogo de tipos de la bóveda de Acheron —qué es una «cuenta», qué campos
tiene una «tarjeta»— está escrito en cuatro sitios y en cuatro lenguajes: aquí
(``storable_specs.py``), en la SPA (``storableSchema.js``), en la app Android
(``StorableTypes.kt``) y en ``AcheronCore``. Los cuatro tienen que coincidir en
los nombres EXACTOS de los campos, porque esos nombres son las claves del JSON
de la bóveda que los clientes cifran y se intercambian.

El modo de fallo no es un error limpio. Si la API espera ``cardHolderName`` y
un cliente escribe ``cardholderName``, el campo simplemente no llega: se pierde
en silencio en un ``dict`` que nadie mira, y el usuario descubre que su tarjeta
no tiene titular mucho después, sin ninguna traza que apunte al renombrado.

``AcheronSchema`` es la fuente de verdad común, y este test convierte la
divergencia en un fallo de CI. Sigue el patrón de ``test_caddy_api_routes.py``
y ``test_config_view_paths.py``, que atan las otras parejas cruzadas del
monorepo leyendo un fichero que vive lejos y comparando.

El ORDEN de los campos no se comprueba, y merece decirse por qué: el JSON del
vault es un objeto con los campos por nombre, no una tupla, así que ningún
cliente depende de él para leer un storable. Hoy hay una divergencia real en
``creditcard``, y el reparto es dos y dos:

- ``… postalCode, cvv`` — esta API y el motor Java de ``AcheronCore``.
- ``… cvv, postalCode`` — la SPA y la app Android.

No rompe nada, y por eso se comparan conjuntos y no listas en los cuatro
clientes. Si algún día el orden pasa a importar, el sitio donde decidirlo es
``AcheronSchema``, no este test.

Deliberadamente NO se genera ``storable_specs.py`` desde el esquema. Ese
registro ata además cada tipo a su modelo SQLAlchemy y a los nombres de
atributo en ``snake_case``, que son información propia de la API y no
pertenecen a un contrato compartido. Verificar basta, y es mucho menos invasivo.
"""

import json
from pathlib import Path

import pytest

from src.modules.features.acheron.storable_specs import STORABLE_SPECS

pytestmark = pytest.mark.unit

_REPO_ROOT = Path(__file__).resolve().parents[3]

# La copia versionada del contrato vive con la suite del SPA, que es su otro
# consumidor; su procedencia está anotada en web/app/test/README.md. Se lee de
# ahí en vez de duplicarla: una segunda copia sería un quinto sitio donde el
# catálogo puede divergir, que es justo lo que este test existe para evitar.
_SCHEMA = _REPO_ROOT / "web" / "app" / "test" / "acheron-schema.json"


def _shared_schema() -> dict:
    assert _SCHEMA.is_file(), (
        f"No está la copia de AcheronSchema en {_SCHEMA}. "
        "Se copia del repositorio AcheronSchema a un tag concreto; "
        "ver web/app/test/README.md."
    )
    return json.loads(_SCHEMA.read_text(encoding="utf-8"))


def test_the_api_knows_exactly_the_kinds_the_shared_schema_declares():
    """Ni un tipo de más ni uno de menos."""
    schema_kinds = {t["kind"] for t in _shared_schema()["types"]}
    api_kinds = set(STORABLE_SPECS)

    assert api_kinds == schema_kinds, (
        f"faltan en la API: {sorted(schema_kinds - api_kinds)}; "
        f"sobran en la API: {sorted(api_kinds - schema_kinds)}"
    )


def test_every_kind_maps_to_the_json_list_key_the_schema_declares():
    """``json_list_key`` es la clave de lista dentro del JSON del vault.

    Si la API la llama ``creditcards`` y el cliente escribe bajo ``cards``, la
    API no ve ni un solo storable de ese tipo y no falla: lee una lista vacía.
    """
    for type_ in _shared_schema()["types"]:
        spec = STORABLE_SPECS[type_["kind"]]
        assert spec.json_list_key == type_["category"], (
            f"{type_['kind']}: la API usa la clave de lista '{spec.json_list_key}' "
            f"y el esquema declara '{type_['category']}'"
        )


def test_every_kind_declares_exactly_the_field_keys_of_the_shared_schema():
    """Las claves JSON, comparadas en ambos sentidos.

    Comprobar sólo que no falta ninguna dejaría pasar el campo de más, que es
    el que aparece al borrar un campo del esquema sin tocar la API.
    """
    for type_ in _shared_schema()["types"]:
        spec = STORABLE_SPECS[type_["kind"]]
        schema_keys = {field["key"] for field in type_["fields"]}
        api_keys = {json_key for _attribute, json_key in spec.fields}

        assert api_keys == schema_keys, (
            f"{type_['kind']}: faltan en la API {sorted(schema_keys - api_keys)}; "
            f"sobran en la API {sorted(api_keys - schema_keys)}"
        )
