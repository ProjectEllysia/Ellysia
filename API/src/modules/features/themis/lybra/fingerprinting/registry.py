"""The dissector registry — where each protocol subscribes itself via ``@register_dissector``.

Mirrors the pattern the manager layer already uses for scan types
(``ScanManager.register(ScanType.LYBRA)``): a class decorator appends to a
module-level list at import time, instead of a hand-maintained list of every
protocol in one place. Adding protocol N+1 means writing ``@register_dissector``
on its class, in its own module — nothing here, or in ``__init__.py``, changes.

Registration is a side effect of importing a protocol module, so it only
"sees" dissectors whose module has actually been imported. This package's own
``__init__.py`` imports every protocol module unconditionally, which is what
makes ``default_dissectors()`` complete in practice.
"""

from __future__ import annotations

from typing import List, Type, TypeVar

from .dispatch import Dissector

_DissectorT = TypeVar("_DissectorT", bound=Type[Dissector])

# Registration order follows import order (see __init__.py), ranked by
# cost/value — cheapest and most common protocols first.
#
# El orden **importa de verdad** para un caso concreto, no sólo para la
# legibilidad. Los predicados no son disjuntos: los
# puertos de las APIs de administración (2375, 9200, 6443...) entraron en la
# familia HTTP para que los checks de exposición y de higiene TLS los
# alcanzaran: ahora los reclaman dos dissectors, y
# ``LybraEngineManager._fingerprint_services`` se queda con el primero que
# aplique. ``http_apis`` va antes que ``http`` justamente por eso — si no, la
# sonda genérica se llevaría el 2375 y leería una cabecera ``Server`` en vez de
# la versión que el JSON publica.
_REGISTERED_DISSECTORS: List[Type[Dissector]] = []


def register_dissector(cls: _DissectorT) -> _DissectorT:
    """Class decorator: adds a :class:`Dissector` subclass to the registry.

    The class must be constructible with no arguments — see each dissector's
    own ``__init__``, which defaults its ``probe`` to a fresh instance of its
    protocol's ``Probe`` class when the caller does not inject one (tests
    still can, for a fake socket).
    """
    _REGISTERED_DISSECTORS.append(cls)
    return cls


def default_dissectors() -> List[Dissector]:
    """Instantiate every registered dissector, in registration order."""
    return [cls() for cls in _REGISTERED_DISSECTORS]
