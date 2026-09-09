from .base import MailboxConnector, MailboxFolder, MessageRef, TokenSet
from .registry import MAILBOX_CONNECTORS, get_connector

# Importados por su efecto secundario: cada uno se da de alta en
# MAILBOX_CONNECTORS vía @register_connector al importarse (B5). El
# paquete es el único punto que debe dispararlo — ver el docstring de
# registry.py sobre por qué éste no los importa directamente.
from . import gmail as _gmail  # noqa: F401
from . import microsoft as _microsoft  # noqa: F401

__all__ = [
    "MailboxConnector", "MailboxFolder", "MessageRef", "TokenSet",
    "MAILBOX_CONNECTORS", "get_connector",
]
