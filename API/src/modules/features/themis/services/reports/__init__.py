"""
Generación de informes PDF de Themis.

    theme.py     ColorType + ReportTheme (paleta y estilos)
    base.py      PrintingStrategy: contrato + registro
    creator.py   PDFCreator: arma el documento
    nmap.py      NmapPrintingStrategy
    nikto.py     NiktoPrintingStrategy
    findings.py  FindingsPrintingStrategy (base de los tipos que viven
                 enteramente en ``Finding``)
    lybra.py     LybraPrintingStrategy
    nuclei.py    NucleiPrintingStrategy

D5 en ``plans/deuda-tecnica-y-calidad.md``: este paquete sustituye al
``reports.py`` de 85 KB, el fichero más grande del repositorio. Su
estructura interna ya era buena —el registro ``@PrintingStrategy.register``
estaba bien hecho— y el problema era puramente de tamaño: tocar la paleta
de un escáner obligaba a abrir un fichero de 2.000 líneas, y dos cambios en
escáneres distintos colisionaban siempre en el mismo sitio. Es la misma
Fase 3 que ya se aplicó a ``themis/managers.py``.

Las cuatro estrategias se importan aquí por su **efecto secundario**: cada
una se da de alta en ``PrintingStrategy._registry`` con su decorador al
importarse. Sin estos imports el registro quedaría vacío y
``resolve_printing_strategy`` no encontraría ninguna — mismo patrón que
``iris/services/mailbox/__init__.py`` (B5).
"""

from src.modules.shared.report_theme import ColorType, ReportTheme
from .base import PrintingStrategy
from .creator import PDFCreator
from .nmap import NmapPrintingStrategy
from .nikto import NiktoPrintingStrategy
from .findings import FindingsPrintingStrategy
from .lybra import LybraPrintingStrategy
from .nuclei import NucleiPrintingStrategy

__all__ = [
    "ColorType",
    "ReportTheme",
    "PrintingStrategy",
    "PDFCreator",
    "NmapPrintingStrategy",
    "NiktoPrintingStrategy",
    "FindingsPrintingStrategy",
    "LybraPrintingStrategy",
    "NucleiPrintingStrategy",
]
