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


# =============================================================================
# VERSIÓN DE ORIGEN EN LOS PAQUETES DE LINUX
# =============================================================================

def _deb(name, version):
    return {"name": name, "version": version, "vendor": "Debian", "source": "dpkg"}


def test_the_packaging_suffix_is_stripped_from_debian_versions():
    """La gramática es ``[época:]versión_de_origen[-revisión]``."""
    cases = {
        "1:9.6p1-3ubuntu13.5": "9.6p1",           # época y revisión
        "2.39-0ubuntu8.3": "2.39",                # solo revisión
        "1:1.3.dfsg-3.1ubuntu2.1": "1.3.dfsg",    # la época no es la versión
        "128.0+build1-0ubuntu0.24.04.1": "128.0+build1",
    }
    for packaged, upstream in cases.items():
        services = services_from_inventory([_deb("openssh-server", packaged)])
        assert services[0].version == upstream, f"{packaged} -> {services[0].version}"


def test_a_native_debian_package_keeps_its_whole_version():
    # Sin guion no hay revisión: el paquete es propio de Debian y toda la
    # cadena es la versión de origen. Recortar aquí inventaría un recorte.
    services = services_from_inventory([_deb("base-files", "13ubuntu10.2")])
    assert services[0].version == "13ubuntu10.2"


def test_a_debian_prerelease_tag_survives():
    # Debian marca las preliminares con "~", no con "-", así que recortar por
    # el último guion no puede llevárselas por delante.
    services = services_from_inventory([_deb("nginx", "1.27.0~rc1-1ubuntu2")])
    assert services[0].version == "1.27.0~rc1"


def test_other_sources_are_left_alone():
    """Solo dpkg. RPM ya manda %{VERSION}; snap no sigue ninguna gramática."""
    untouched = [
        ({"name": "bash", "version": "5.3.9", "source": "rpm"}, "5.3.9"),
        ({"name": "firefox", "version": "122.0-2", "source": "snap"}, "122.0-2"),
        ({"name": "7-Zip", "version": "24.09", "source": "registry"}, "24.09"),
        ({"name": "Algo", "version": "1.0-2"}, "1.0-2"),  # sin `source`
    ]
    for item, expected in untouched:
        services = services_from_inventory([item])
        assert services[0].version == expected, f"{item} -> {services[0].version}"


def test_the_stripped_version_matches_an_nvd_range_that_the_raw_one_missed():
    """El motivo de todo esto, comprobado contra el comparador de verdad.

    Un rango ``version_start_including="2.39"`` debe casar con la libc de un
    Ubuntu que reporta "2.39-0ubuntu8.3". Con la versión sin recortar no casa:
    ``version_compare`` parte la cadena en tramos de dígitos y letras, las
    letras ordenan por debajo de los números, y el sufijo de empaquetado deja
    la versión instalada por debajo del inicio del rango.
    """
    from src.modules.features.themis.lybra import version_compare

    raw = "2.39-0ubuntu8.3"
    # El fallo que se está corrigiendo: sin recortar, la instalada parece
    # anterior al inicio del rango y la CVE no se reportaría.
    assert version_compare(raw, "2.39") < 0

    services = services_from_inventory([_deb("libc6", raw)])
    assert version_compare(services[0].version, "2.39") == 0


def test_stripping_never_leaves_the_version_empty():
    # Una versión mal formada no debe convertirse en "sin versión", que
    # descartaría el paquete entero del análisis.
    services = services_from_inventory([_deb("roto", "-3")])
    assert len(services) == 1
    assert services[0].version
