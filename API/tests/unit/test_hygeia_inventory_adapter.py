"""Tests unitarios del adaptador inventario -> servicios de Lybra (Fase I-b).

Pura lógica: sin DB, sin red. El caso motivador es real, no hipotético — visto
en el primer análisis de un inventario Windows de verdad (ver el docstring de
``services_from_inventory``).
"""

import pytest

from src.modules.features.hygeia.services.inventory_adapter import services_from_inventory

pytestmark = pytest.mark.unit


def _pkg(name, version=None, **overrides):
    entry = {"name": name, "version": version, "vendor": "ACME"}
    entry.update(overrides)
    return entry


def test_uses_the_version_field_when_the_name_has_no_embedded_version():
    services = services_from_inventory([_pkg("Docker Desktop", "4.80.0")])
    assert len(services) == 1
    assert services[0].product == "Docker Desktop"
    assert services[0].version == "4.80.0"


def test_prefers_the_name_embedded_version_when_it_disagrees_with_the_version_field():
    """El caso real que motivó esto: JetBrains registra el build interno como
    `version` de Windows, mientras la versión de marketing (contra la que NVD
    expresa sus rangos) solo aparece en el propio nombre."""
    services = services_from_inventory([
        _pkg("IntelliJ IDEA 2025.2.2", "252.26199.169"),
    ])
    assert len(services) == 1
    assert services[0].version == "2025.2.2"


def test_name_and_field_agreeing_is_unaffected():
    # El caso normal, observado en la mayoría del inventario real: ambas
    # fuentes coinciden, así que preferir la del nombre no cambia nada.
    services = services_from_inventory([_pkg("7-Zip 25.01 (x64)", "25.01")])
    assert services[0].version == "25.01"


def test_falls_back_to_version_field_when_name_has_no_dotted_number():
    # "Half-Life 2" NO es una versión (Fase I-b, normalize_product_name ya
    # protege este caso) — la extracción debe dejarlo intacto y usar `version`.
    services = services_from_inventory([_pkg("Half-Life 2", "1.0")])
    assert services[0].product == "Half-Life 2"
    assert services[0].version == "1.0"


def test_package_without_any_version_is_discarded():
    services = services_from_inventory([_pkg("AI Limit", version=None)])
    assert services == []


def test_package_without_a_name_is_discarded():
    services = services_from_inventory([_pkg("", "1.0")])
    assert services == []


def test_every_service_carries_inventory_origin_no_port():
    services = services_from_inventory([_pkg("Docker Desktop", "4.80.0")])
    assert services[0].origin == "inventory"
    assert services[0].port is None
    assert services[0].protocol == ""


def test_empty_inventory_returns_empty():
    assert services_from_inventory([]) == []
    assert services_from_inventory(None) == []
