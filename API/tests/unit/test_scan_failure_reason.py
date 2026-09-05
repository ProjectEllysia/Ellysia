"""Un escaneo fallido dice por qué falló.

Hasta ahora los cinco caminos que acaban en ``FAILED`` —host inalcanzable,
barrido de puertos fallido, escáner externo sin resultados, escaneo huérfano
tras un reinicio, y excepción del motor— escribían exactamente lo mismo en la
fila: ``status = 'failed'``. La interfaz sólo podía decir «falló», que es la
misma frase para una máquina apagada y para un error del producto.

Estos tests fijan que cada camino deja su código, y que el código no sobrevive
a salir de FAILED (un escaneo relanzado no debe arrastrar el motivo del intento
anterior: la única pregunta que responde el campo es «por qué falló *éste*»).
"""

from __future__ import annotations

import pytest

from src.modules.features.themis.exceptions import ScanFailedError
from src.modules.features.themis.managers.lybra.sources import (
    DiscoveryProbes,
    SelfDiscovery,
)
from src.modules.features.themis.model import ScanFailureReason, ScanStatus
from src.modules.features.themis.repositories import ScanRepository

pytestmark = pytest.mark.unit


class _FakeScan:
    """Lo justo que ``update_status`` toca de una fila de escaneo."""

    def __init__(self):
        self.status = ScanStatus.RUNNING.value
        self.failure_reason = None
        self.finished_at = None


class _RepoWithoutSession(ScanRepository):
    """``update_status`` sólo escribe atributos y delega el guardado en
    ``update``; sustituirlo evita necesitar una sesión y una base de datos para
    comprobar qué escribe."""

    def __init__(self):  # pylint: disable=super-init-not-called
        pass

    def update(self, entity):
        return entity


# =============================================================================
# El repositorio: qué se guarda y qué no
# =============================================================================

def test_a_failed_scan_records_its_reason():
    scan = _FakeScan()

    _RepoWithoutSession().update_status(
        scan, ScanStatus.FAILED, ScanFailureReason.HOST_UNREACHABLE)

    assert scan.status == "failed"
    assert scan.failure_reason == "host_unreachable"


def test_a_scan_that_did_not_fail_records_no_reason():
    """Un motivo junto a un estado que no es FAILED sería un dato que
    contradice al estado, así que no se escribe aunque lo pasen."""
    scan = _FakeScan()

    _RepoWithoutSession().update_status(
        scan, ScanStatus.FINISHED, ScanFailureReason.HOST_UNREACHABLE)

    assert scan.failure_reason is None


def test_leaving_the_failed_state_clears_the_reason():
    """Un escaneo relanzado no arrastra el motivo del intento anterior: si lo
    hiciera, la interfaz respondería «por qué falló» con un residuo."""
    scan = _FakeScan()
    repo = _RepoWithoutSession()

    repo.update_status(scan, ScanStatus.FAILED, ScanFailureReason.INTERNAL_ERROR)
    repo.update_status(scan, ScanStatus.RUNNING)

    assert scan.failure_reason is None


# =============================================================================
# El descubrimiento de Lybra: sus dos fallos dejan de ser el mismo
# =============================================================================

def _probes(is_reachable=True, sweep=None) -> DiscoveryProbes:
    return DiscoveryProbes(
        is_host_reachable=lambda target, **kwargs: is_reachable,
        discover_ports=lambda target, ports: sweep,
        discover_udp_ports=lambda target: [],
    )


def test_an_unreachable_host_is_told_apart_from_a_broken_sweep(monkeypatch):
    """Los dos casos devolvían el mismo ``None``; ahora cada uno trae su
    código, que es lo que permite dar un consejo distinto a cada uno."""
    import src.modules.system.config_reading as CR

    monkeypatch.setattr(
        CR, "host_reachability_check",
        lambda: type("Check", (), {"enabled": True, "port": 80, "timeout": 1})())

    source = SelfDiscovery(ports_to_discover=None)

    with pytest.raises(ScanFailedError) as unreachable:
        source.resolve_services(None, _probes(is_reachable=False), "10.0.0.5")
    assert unreachable.value.reason is ScanFailureReason.HOST_UNREACHABLE

    with pytest.raises(ScanFailedError) as no_sweep:
        source.resolve_services(None, _probes(sweep=None), "10.0.0.5")
    assert no_sweep.value.reason is ScanFailureReason.PORT_DISCOVERY_FAILED


# =============================================================================
# El catálogo entero llega hasta la interfaz
# =============================================================================

def test_every_reason_has_its_prose_in_the_spa():
    """El SPA traduce cada código a una frase y un consejo, y esa redacción es
    lo único que el usuario llega a leer.

    Añadir un motivo en Python sin añadirlo allí no rompe nada visible: la
    tarjeta cae en el texto de reserva —«no se registró el motivo»— que existe
    para los escaneos anteriores a la columna, y el usuario recibe una
    explicación falsa en lugar de la suya. El fallo es silencioso por diseño,
    así que hace falta atarlo aquí.
    """
    from pathlib import Path
    import re

    repo_root = Path(__file__).resolve().parents[3]
    source = (repo_root / "web" / "app" / "src" / "components" / "themis" / "lybra"
              / "LybraResults.vue").read_text(encoding="utf-8")
    catalogue = source[source.index("const FAILURE = {"):source.index("const FAILURE_UNKNOWN")]
    documented = set(re.findall(r"^  ([a-z_]+): \{", catalogue, re.MULTILINE))

    assert {reason.value for reason in ScanFailureReason} == documented


def test_every_reason_is_a_plain_string_code():
    """El SPA traduce estos códigos a prosa: si alguno dejara de ser una cadena
    estable, la tarjeta del escaneo se quedaría sin texto que enseñar."""
    for reason in ScanFailureReason:
        assert isinstance(reason.value, str)
        assert reason.value == reason.value.lower()
        assert len(reason.value) <= 40  # el ancho de la columna
