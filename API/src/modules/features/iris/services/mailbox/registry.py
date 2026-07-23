"""
Registro proveedor -> conector para el mailbox connector de Iris.

A diferencia de ``tools/herald``/``tools/scribe`` (una estrategia por
*módulo*, elegida en ``SecOpsConfig.json``), aquí la selección es por dato:
cada ``IrisMailboxConnection`` lleva su propio ``provider``, así que un
diccionario simple basta -- ver ``base.py`` para la justificación completa.
"""

from __future__ import annotations

from typing import Optional

from .base import MailboxConnector
from .gmail import GmailConnector
from .microsoft import GraphConnector

MAILBOX_CONNECTORS: dict[str, type[MailboxConnector]] = {
    "gmail": GmailConnector,
    "microsoft": GraphConnector,
}


def get_connector(provider: str, redirect_uri: str, folder: Optional[str] = None) -> MailboxConnector:
    """Instancia el conector del ``provider`` dado.

    Raises:
        ValueError: Si ``provider`` no es uno de los soportados.
    """
    connector_cls = MAILBOX_CONNECTORS.get(provider)
    if connector_cls is None:
        raise ValueError(
            f"Proveedor de buzón desconocido: '{provider}'. "
            f"Soportados: {', '.join(sorted(MAILBOX_CONNECTORS))}."
        )
    return connector_cls(redirect_uri, folder=folder)
