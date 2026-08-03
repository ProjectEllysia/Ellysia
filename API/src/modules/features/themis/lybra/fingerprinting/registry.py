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

# Registration order follows import order (see __init__.py), which follows
# the roadmap's own cost/value ranking — cheapest and most common protocols
# first. Order only matters for readability: each dissector's ``applies``
# predicate is protocol-specific and none overlap.
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
