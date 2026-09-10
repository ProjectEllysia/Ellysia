"""
MailboxConnector — interfaz común para los conectores de buzón externo
(Gmail, Microsoft Graph).

Mismo espíritu que ``tools/herald``/``tools/scribe`` (interfaz +
implementaciones intercambiables), con una diferencia deliberada en cómo se
elige la implementación: herald/scribe seleccionan una estrategia por
*módulo* desde ``SecOpsConfig.json``; aquí cada fila ``IrisMailboxConnection``
lleva su propio ``provider``, así que la selección es por dato (ver
``registry.get_connector``), no por config global — una instalación puede
tener conexiones Gmail y Graph activas simultáneamente.

Todos los métodos son deliberadamente síncronos y devuelven tipos simples
(dataclasses, str, list) — el manager que los llama corre siempre dentro de
un worker de TaskQueue, nunca en el hilo de una petición HTTP ni en el del
scheduler.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class TokenSet:
    """Resultado de un intercambio/refresco OAuth."""
    refresh_token: str
    access_token: str
    access_token_expires_at: datetime
    scopes: str
    account_email: str


@dataclass
class MessageRef:
    """Referencia opaca a un mensaje nuevo devuelta por ``list_new``."""
    provider_message_id: str
    # Datos crudos ya disponibles en el listado (si el proveedor los da sin
    # una llamada extra) — evita un round-trip cuando no hace falta.
    raw: dict = field(default_factory=dict)


@dataclass
class MailboxFolder:
    """Una carpeta/etiqueta real del proveedor que Iris puede vigilar.

    ``provider_id`` es el valor opaco que ``IrisMailboxConnection.folder``
    guarda y que los conectores usan para filtrar ``list_new`` -- nunca se
    interpreta ni se recorta, igual que ``sync_cursor``. ``folder_type``
    distingue una carpeta propia del proveedor ("system": Inbox, Sent,
    Trash...) de una creada por el usuario ("user": una etiqueta de Gmail,
    una subcarpeta de Outlook), información que no se puede derivar del
    nombre por sí solo.
    """
    provider_id: str
    display_name: str
    folder_type: str  # "system" | "user"


class MailboxConnector(ABC):
    """Conector OAuth + API de correo para un proveedor concreto."""

    provider: str

    @abstractmethod
    def authorize_url(self, state: str, full_message_mode: bool) -> str:
        """URL de consentimiento OAuth a la que redirigir al usuario.

        ``full_message_mode`` puede influir en el scope pedido (ver
        ``GmailConnector`` — Graph no tiene un scope solo-metadata, ver
        ``GraphConnector``).
        """

    @abstractmethod
    def exchange_code(self, code: str) -> TokenSet:
        """Canjea el ``code`` del callback OAuth por un TokenSet inicial."""

    @abstractmethod
    def refresh(self, refresh_token: str) -> TokenSet:
        """Obtiene un access_token nuevo a partir del refresh_token guardado."""

    @abstractmethod
    def list_new(self, access_token: str, cursor: Optional[str]) -> tuple[list[MessageRef], str]:
        """Mensajes nuevos desde ``cursor`` (o bootstrap si ``cursor`` es None).

        Cuando ``cursor`` es None, NO hace backfill de correo histórico —
        solo captura el cursor de partida y devuelve una lista vacía (ver
        docstring de cada implementación para el mecanismo concreto).

        Returns:
            (mensajes_nuevos, cursor_nuevo).
        """

    @abstractmethod
    def fetch_headers(self, access_token: str, message_ref: MessageRef) -> str:
        """Bloque de cabeceras RFC 5322 reconstruido (``"Header: value\\r\\n"``)."""

    @abstractmethod
    def fetch_raw(self, access_token: str, message_ref: MessageRef) -> str:
        """Mensaje MIME crudo completo (solo si full_message_mode)."""

    @abstractmethod
    def list_folders(self, access_token: str) -> list[MailboxFolder]:
        """Carpetas/etiquetas reales de la cuenta conectada.

        Única fuente de verdad para validar ``IrisMailboxConnection.folder``:
        un valor que no aparece aquí no es una carpeta que este proveedor y
        esta cuenta puedan vigilar, sea porque no existe, porque se escribió
        a mano, o porque pertenece a otro proveedor.
        """

    @abstractmethod
    def revoke(self, refresh_token: str) -> None:
        """Revoca el refresh token en el proveedor (al desconectar)."""
