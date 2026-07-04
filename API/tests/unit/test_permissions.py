"""Tests unitarios del modelo de permisos (RBAC + ABAC)."""

import pytest

from src.modules.users.services.permissions import (
    AttributeType,
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
    assert AttributeType.SENTINEL_READ.db_name == "sentinel_read"
    assert AttributeType.IRIS_DELETE.db_name == "iris_delete"


def test_attribute_db_description_returns_non_empty_string():
    """db_description devuelve una descripción legible para cada miembro del Enum."""
    assert AttributeType.SENTINEL_READ.db_description == "Read access for Sentinel security scans"
    assert AttributeType.ACHERON_READ.db_description == "Read access for Acheron vault secrets"
    assert AttributeType.IRIS_DELETE.db_description == "Delete access for Iris email header analysis"


def test_user_role_includes_read_baseline():
    user_perms = ROLE_PERMISSIONS[Role.USER]
    assert AttributeType.SENTINEL_READ in user_perms
    assert AttributeType.IRIS_READ in user_perms


def test_user_role_excludes_create_capabilities():
    user_perms = ROLE_PERMISSIONS[Role.USER]
    assert AttributeType.SENTINEL_CREATE not in user_perms
    assert AttributeType.IRIS_CREATE not in user_perms


def test_admin_is_superset_of_user_for_sentinel():
    admin_perms = ROLE_PERMISSIONS[Role.ADMIN]
    assert AttributeType.SENTINEL_CREATE in admin_perms
    assert AttributeType.SENTINEL_DELETE in admin_perms


def test_root_is_not_in_role_permissions_matrix():
    # Root cortocircuita las comprobaciones ABAC; no debe tener fila explícita.
    assert Role.ROOT not in ROLE_PERMISSIONS


def test_all_attribute_values_are_unique_strings():
    values = [a.value for a in AttributeType if isinstance(a.value, str)]
    assert len(values) == len(set(values))
