"""Piezas de Lybra que sí necesitan el ORM (D1 en plans/deuda-tecnica-y-calidad.md).

``LybraEngineManager`` (``engine.py``) y ``ServiceSource``/``DiscoveryProbes``
(``sources.py``) vivían sueltos en ``managers/`` con nombres con prefijo
``lybra_*``. Se agrupan aquí en vez de en ``themis/lybra/`` porque ese paquete
mantiene una invariante real — libre de ORM y de efectos de red (ver su
``__init__.py``) — que ``ScanRepository``/``UnitOfWork``/``AuthorizedTargetManager``
rompería.

Este ``__init__.py`` reexporta los nombres públicos para que
``from ..managers.lybra import LybraEngineManager`` (y el registro de
``@ScanManager.register``, que referencia estos símbolos por atributo de
módulo) sigan funcionando sin cambios.
"""

from .engine import LybraEngineManager
from .sources import ServiceSource, DiscoveryProbes, ResolvedServices

__all__ = [
    "LybraEngineManager",
    "ServiceSource",
    "DiscoveryProbes",
    "ResolvedServices",
]
