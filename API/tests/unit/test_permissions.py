"""Tests unitarios del modelo de permisos (RBAC + ABAC)."""

import pytest

from src.modules.users.services.permissions import (
    AttributeType,
    DEFAULT_USER_ATTRIBUTES,
    Role,
    ROLE_PERMISSIONS,
)

pytestmark = pytest.mark.unit


def test_role_hierarchy_order():
    assert Role.USER.rank() < Role.ADMIN.rank() < Role.ROOT.rank()


def test_role_enum_has_exactly_three_members():
    """Regresión: un miembro _HIERARCHY (pensado como constante interna, no
    excluido por el mecanismo de Enum al no ser un nombre "sunder") se colaba
    como un cuarto Role real con .value siendo una lista en vez de un string."""
    assert len(list(Role)) == 3
    assert {r.name for r in Role} == {"ROOT", "ADMIN", "USER"}
    assert all(isinstance(r.value, str) for r in Role)


def test_role_db_name_matches_value():
    assert Role.ADMIN.db_name == "role_admin"
    assert Role.ROOT.db_name == "role_root"


def test_attribute_db_name():
    assert AttributeType.THEMIS_READ.db_name == "themis_read"
    assert AttributeType.IRIS_DELETE.db_name == "iris_delete"


def test_attribute_db_description_returns_non_empty_string():
    """db_description devuelve una descripción legible para cada miembro del Enum."""
    assert AttributeType.THEMIS_READ.db_description == "Read access for Themis security scans"
    assert AttributeType.ACHERON_READ.db_description == "Read access for Acheron vault secrets"
    assert AttributeType.IRIS_DELETE.db_description == "Delete access for Iris email header analysis"


def test_user_role_baseline_is_empty():
    """El baseline de Role.USER tiene que seguir vacío, y no es un descuido.

    Lo que concede el baseline es irrevocable: require_attributes calcula
    `baseline | filas_explícitas` y remove_user_attributes solo borra filas.
    En cuanto se meta aquí un solo atributo, el administrador —y el dueño de
    una organización— pierde la capacidad de retirárselo a nadie.
    """
    assert ROLE_PERMISSIONS[Role.USER] == set()


def test_default_user_attributes_covers_the_whole_enum():
    """Freemium y Gold tienen el mismo llavero: lo que los separa son los topes
    del plan, no los atributos. Un atributo nuevo entra solo en el conjunto por
    defecto; si algún día alguno debe quedarse fuera, hay que decirlo aquí."""
    assert DEFAULT_USER_ATTRIBUTES == frozenset(AttributeType)


def test_user_without_explicit_rows_has_no_permissions():
    """Fallo cerrado: sin filas en UserAttribute, un role_user no puede nada.

    Es la contrapartida del baseline vacío — el permiso ahora viene siempre de
    un dato, nunca de un rol, y por eso se puede quitar.
    """
    effective = ROLE_PERMISSIONS.get(Role.USER, set()) | set()
    assert effective == set()


def test_admin_baseline_survives_and_covers_themis():
    """Role.ADMIN sí conserva baseline: es estructural y lo gestiona root."""
    admin_perms = ROLE_PERMISSIONS[Role.ADMIN]
    assert AttributeType.THEMIS_CREATE in admin_perms
    assert AttributeType.THEMIS_DELETE in admin_perms


def test_root_is_not_in_role_permissions_matrix():
    # Root cortocircuita las comprobaciones ABAC; no debe tener fila explícita.
    assert Role.ROOT not in ROLE_PERMISSIONS


def test_all_attribute_values_are_unique_strings():
    values = [a.value for a in AttributeType if isinstance(a.value, str)]
    assert len(values) == len(set(values))
