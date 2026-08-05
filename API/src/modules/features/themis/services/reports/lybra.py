"""Estrategia de impresión de los informes del motor Lybra (D5)."""

from ...model import ScanType
from ..analyzers import LybraAIWriter
from .base import PrintingStrategy
from .findings import FindingsPrintingStrategy


@PrintingStrategy.register(ScanType.LYBRA)
class LybraPrintingStrategy(FindingsPrintingStrategy):
    """Printing strategy for Lybra engine scan reports.

    Color palette: Green theme, matching Lybra's own UI identity. All the
    rendering logic lives in `FindingsPrintingStrategy`; this class only fixes
    Lybra's identity — behaviour is unchanged from before the Fase U1 extract.
    """

    _TOOL = ScanType.LYBRA
    _WRITER_CLASS = LybraAIWriter
    _WRITER_PROMPT_KEY = "lybra"
    _OWN_SOURCE = "lybra"
    _HEADER_TITLE = "Informe del Motor Lybra"
    _REPORT_TITLE = "Veredicto del Motor Lybra"
    _FILENAME_SUFFIX = "_Lybra.pdf"
    _PICTURE_BASE = "Themis-Green-Bg"
    _DEFAULT_PALETTE = {
        "black": "#1A2410", "dark": "#4A6132", "main": "#7CA163",
        "secondary": "#A8C98F", "light": "#D4E8C4", "white": "#F3F8EE",
    }

