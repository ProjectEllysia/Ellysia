"""Un escaneo que agota su plazo cierra su fila en vez de quedarse «escaneando».

La cola mata un trabajo que se pasa de tiempo lanzándole ``JobDeadlineExceeded``
desde fuera. Esa excepción hereda de ``BaseException`` a propósito, para
que ningún ``except Exception`` del código de negocio la confunda con un fallo
de red y se la trague.

El precio de aquel arreglo fue que tampoco la veía el único sitio que sabe qué
fila de la base de datos hay que cerrar. El 2026-09-05 tres escaneos de Lybra
murieron de plazo dentro del fingerprinting: RQ los marcó como fallidos en
Redis, la fila se quedó tal cual la dejó el ``RUNNING`` del principio, y un día
después el panel seguía diciendo «escaneando». La única red que había era la
reconciliación de arranque de la API, que además los habría cerrado como
``orphaned`` —«el servicio se reinició»—, que es falso.

Estos tests fijan las dos mitades del arreglo: la fila queda ``failed`` con
motivo ``timeout``, y la excepción **sigue subiendo** hasta RQ. Cerrar el
escaneo es legítimo; tragarse la sentencia de muerte no.
"""

from __future__ import annotations

import pytest

from src.modules.features.themis.managers import scan as scan_module
from src.modules.features.themis.managers.lybra import engine as engine_module
from src.modules.features.themis.managers.lybra.engine import LybraEngineManager
from src.modules.features.themis.managers.nmap import NmapScanManager
from src.modules.features.themis.model import ScanFailureReason, ScanStatus
from src.modules.system.taskqueue import JobDeadlineExceeded

pytestmark = pytest.mark.unit


def _record_status_writes(monkeypatch, manager_class) -> list:
    """Sustituye la escritura de estado por un registro de lo que se escribiría."""
    written: list = []
    monkeypatch.setattr(
        manager_class, "update_scan_status",
        lambda self, scan_id, status, failure_reason=None: written.append((status, failure_reason)),
    )
    return written


class _DeadlineOnEntry:
    """Un ``UnitOfWork`` que muere de plazo al abrirse.

    Vale cualquier punto del escaneo: lo que se comprueba es el manejador, no
    dónde estaba el hilo cuando le llegó la sentencia. En producción fue dentro
    del pool de fingerprinting.
    """

    def __init__(self, *args, **kwargs):
        raise JobDeadlineExceeded()


def test_a_lybra_scan_out_of_time_is_failed_with_its_reason(monkeypatch):
    written = _record_status_writes(monkeypatch, LybraEngineManager)
    monkeypatch.setattr(engine_module, "UnitOfWork", _DeadlineOnEntry)

    with pytest.raises(JobDeadlineExceeded):
        LybraEngineManager()._run_lybra(292, discover_ports=[80])  # pylint: disable=protected-access

    assert (ScanStatus.FAILED, ScanFailureReason.TIMEOUT) in written


def test_an_external_scanner_out_of_time_is_failed_with_its_reason(monkeypatch):
    """El mismo agujero lo tenían nmap, nikto y nuclei: comparten
    ``ScanManager._execute_scan``, que tenía el mismo manejador genérico."""
    written = _record_status_writes(monkeypatch, NmapScanManager)
    monkeypatch.setattr(scan_module, "UnitOfWork", _DeadlineOnEntry)

    with pytest.raises(JobDeadlineExceeded):
        NmapScanManager()._execute_scan(293, task=None)  # pylint: disable=protected-access

    assert (ScanStatus.FAILED, ScanFailureReason.TIMEOUT) in written


def test_the_deadline_keeps_climbing_after_the_row_is_closed(monkeypatch):
    """Si se capturara sin volver a lanzarla, la fila diría «falló» y la cola
    diría «terminado con éxito» — la misma contradicción, del revés.

    Además el temporizador dispara una sola vez: un plazo tragado deja al
    trabajo corriendo sin ningún límite a partir de ese momento.
    """
    _record_status_writes(monkeypatch, LybraEngineManager)
    monkeypatch.setattr(engine_module, "UnitOfWork", _DeadlineOnEntry)

    with pytest.raises(JobDeadlineExceeded):
        LybraEngineManager()._run_lybra(294)  # pylint: disable=protected-access
