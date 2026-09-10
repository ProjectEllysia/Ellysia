"""Estrategia de impresión de los informes de Nuclei."""

from ...model import ScanType
from ..analyzers import LybraAIWriter
from .base import PrintingStrategy
from .findings import FindingsPrintingStrategy


@PrintingStrategy.register(ScanType.NUCLEI)
class NucleiPrintingStrategy(FindingsPrintingStrategy):
    """Printing strategy for Nuclei scan reports.

    Nuclei's JSONL output maps onto `Finding` almost as completely as Lybra's
    own engine (`cve_ids`, `cvss_score`, `check_id` all populated by
    `nuclei_result_to_finding`), so this reuses `FindingsPrintingStrategy`
    wholesale — a not-minor side benefit: the PDF is the hardest part of
    adding a scanner, and here it costs a dozen class attributes.

    Color palette: Blue theme, distinct from Lybra's green so the two
    coexist without visual confusion in the tool picker.
    """

    _TOOL = ScanType.NUCLEI
    _WRITER_CLASS = LybraAIWriter
    _WRITER_PROMPT_KEY = "nuclei"
    _OWN_SOURCE = "nuclei"
    _HEADER_TITLE = "Informe de Nuclei"
    _REPORT_TITLE = "Veredicto de Nuclei"
    _FILENAME_SUFFIX = "_Nuclei.pdf"
    _PICTURE_BASE = "Themis-Blue-Bg"
    _DEFAULT_PALETTE = {
        "black": "#0d1b2a", "dark": "#1b4965", "main": "#2b7fb8",
        "secondary": "#5fa8d3", "light": "#bee9e8", "white": "#f0f8ff",
    }