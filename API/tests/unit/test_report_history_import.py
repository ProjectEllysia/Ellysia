"""Regresión: el import perezoso de ``ScanHistoryManager`` en
``PrintingStrategy._append_history_stats``.

Se escribió como ``from ..managers import ScanHistoryManager``, que desde
``themis/services/reports/base.py`` resuelve a ``themis.services.managers``
— un paquete que no existe. El fallo solo aparecía al generar el PDF en el
worker (``ModuleNotFoundError``), no al importar el módulo: el import es
perezoso y vive dentro del método.
"""

import pytest

from src.modules.features.themis.model import Scan
from src.modules.features.themis.services.reports.base import PrintingStrategy

pytestmark = pytest.mark.unit


class _StubPrintingStrategy(PrintingStrategy):
    """Estrategia mínima: solo hace falta heredar para poder instanciar."""

    def append_body(self, theme, elements, ai_report=False):
        pass

    def get_filename_suffix(self):
        return "_Stub.pdf"

    def get_picture_name(self, dark=True):
        return "logo"

    def get_report_title(self):
        return "Stub"


def test_append_history_stats_resolves_scan_history_manager_import():
    """El import perezoso de ``ScanHistoryManager`` debe resolver.

    Un ``Scan`` base (no Nmap/Nikto) sale por la vía rápida del ``tool_map``
    justo después del import, así que no toca la BD. El test cae con
    ``ModuleNotFoundError`` si alguien vuelve a apuntar el import a un
    paquete inexistente.
    """
    strategy = _StubPrintingStrategy(Scan(target="10.0.0.1", user_id=1))

    strategy._append_history_stats(elements=[], theme=None)  # pylint: disable=protected-access