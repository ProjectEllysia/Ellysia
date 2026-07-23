"""
IrisMailboxManager — OAuth connect/callback, connection CRUD, and background
mailbox sync for the Iris mailbox connector (Fase 4 del plan
plans/feature/iris/iris-mailbox-connector.md).

Fichero separado de ``managers.py`` (que ya tiene 1080+ líneas con
IrisManager + IrisReportManager) siguiendo el precedente de módulos grandes
divididos en varios ficheros de manager (``themis/managers/`` es un paquete
con scan.py/reports.py/traceroute.py, etc.).

La ingesta NO reimplementa nada del motor de reglas: cada mensaje nuevo se
entrega a ``IrisManager.analyze()``, que ya existe. Este manager solo se
ocupa de OAuth, credenciales cifradas, y el ciclo de sondeo.
"""

from __future__ import annotations

import logging
from datetime import date
from typing import Any, Optional

import requests
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

import src.modules.system.config_reading as CR
from src.modules.infrastructure import UnitOfWork
from src.modules.infrastructure.session import build_repository
from src.modules.shared import assert_owned, decrypt_at_rest, encrypt_at_rest, utcnow_naive
from src.modules.system.taskqueue import ITaskQueue, TaskQueue, job_context

from .exceptions import (
    IrisMailboxConnectionNotFoundError,
    IrisMailboxInvalidProviderError,
    IrisMailboxOAuthStateError,
    IrisMailboxQuotaExceededError,
)
from .managers import IrisManager
from .model import IrisMailboxConnection
from .repositories import IrisMailboxConnectionRepository
from .services.mailbox import MAILBOX_CONNECTORS, MailboxConnector, get_connector

logger = logging.getLogger(__name__)

_STATE_SALT = "iris-mailbox-oauth-state"
_STATE_MAX_AGE_SECONDS = 600  # 10 minutos — ver Decisión 5 del plan de sesión.

_VALID_UPDATE_STATUSES = ("active", "paused")


class _ReauthRequiredError(Exception):
    """Señal interna: el proveedor rechazó el refresh_token (revocado/expirado).

    No es una IrisError pública — se maneja íntegramente dentro de
    ``_sync_connection``, nunca cruza el límite de un endpoint.
    """


class IrisMailboxManager:
    """Orquesta el ciclo de vida de una conexión de buzón externo.

    Typical usage::

        manager = IrisMailboxManager()
        url = manager.start_connect(user_id, "microsoft", full_message_mode=False)
        # ... el usuario consiente en el proveedor, que redirige a /callback ...
        connection_id = manager.handle_callback(state, code)
        manager.trigger_sync(connection_id, user_id)   # sondeo manual
    """

    TASK_CATEGORY = "iris.ingest"
    EXTERNAL_ID_PREFIX = "iris-mailbox-sync:"

    def __init__(self, task_queue: ITaskQueue | None = None) -> None:
        self._tq: ITaskQueue = task_queue or TaskQueue.get_instance()

    # =========================================================================
    # OAuth: connect / callback
    # =========================================================================

    @staticmethod
    def list_providers() -> list[str]:
        return sorted(MAILBOX_CONNECTORS)

    @staticmethod
    def _redirect_uri() -> str:
        """Construido desde PUBLIC_WEB_URL, nunca desde un parámetro del
        request (evita un open-redirect en el flujo OAuth). El origen del
        frontend ya proxya las rutas de la API (ver ``npm run dev`` en
        ``web/app``), así que esta URL llega al backend igual en dev y prod.
        """
        return f"{CR.get_public_web_url()}/iris/mailbox/callback"

    @staticmethod
    def _state_serializer() -> URLSafeTimedSerializer:
        # Reutiliza JWT_SECRET_KEY (ya es un secreto fuerte existente) en vez
        # de introducir uno nuevo solo para firmar el state -- distinto
        # "salt" evita que una firma de state sea válida como JWT y viceversa.
        _, _, secret, _ = CR.get_oauth_config()
        return URLSafeTimedSerializer(secret, salt=_STATE_SALT)

    @classmethod
    def _sign_state(cls, *, user_id: int, provider: str,
                     full_message_mode: bool, folder: Optional[str]) -> str:
        return cls._state_serializer().dumps({
            "user_id": user_id, "provider": provider,
            "full_message_mode": full_message_mode, "folder": folder,
        })

    @classmethod
    def _verify_state(cls, state: str) -> dict[str, Any]:
        try:
            return cls._state_serializer().loads(state, max_age=_STATE_MAX_AGE_SECONDS)
        except (BadSignature, SignatureExpired) as e:
            raise IrisMailboxOAuthStateError(
                "El enlace de conexión es inválido o ha caducado. Vuelve a iniciar el proceso."
            ) from e

    def start_connect(self, user_id: int, provider: str,
                       full_message_mode: bool = False,
                       folder: Optional[str] = None) -> str:
        """Devuelve la URL de autorización a la que redirigir al usuario.

        Raises:
            IrisMailboxInvalidProviderError: proveedor no soportado.
            IrisMailboxQuotaExceededError: el usuario ya tiene
                ``iris.maxConnectionsPerUser`` conexiones.
        """
        if provider not in MAILBOX_CONNECTORS:
            raise IrisMailboxInvalidProviderError(provider)

        existing = build_repository(IrisMailboxConnectionRepository).count_for_user(user_id)
        max_connections = CR.get_iris_max_connections_per_user()
        if existing >= max_connections:
            raise IrisMailboxQuotaExceededError(
                f"Ya tienes {existing} conexiones activas (máximo {max_connections})."
            )

        state = self._sign_state(user_id=user_id, provider=provider,
                                  full_message_mode=full_message_mode, folder=folder)
        connector = get_connector(provider, self._redirect_uri(), folder=folder)
        return connector.authorize_url(state, full_message_mode)

    def handle_callback(self, state: str, code: str) -> int:
        """Canjea el code OAuth y crea (o reactiva) la conexión.

        Reconectar una cuenta ya conocida (mismo user/provider/email)
        actualiza sus credenciales en vez de fallar por la UNIQUE
        constraint -- es el camino natural para "reautorizar" tras
        ``reauth_required``.

        Returns:
            El id de la IrisMailboxConnection creada o actualizada.
        """
        claims = self._verify_state(state)
        user_id = claims["user_id"]
        provider = claims["provider"]
        full_message_mode = claims["full_message_mode"]
        folder = claims.get("folder")

        connector = get_connector(provider, self._redirect_uri(), folder=folder)
        token_set = connector.exchange_code(code)

        refresh_enc = encrypt_at_rest(token_set.refresh_token, purpose="iris_mailbox")
        access_enc = encrypt_at_rest(token_set.access_token, purpose="iris_mailbox")
        expires_at = token_set.access_token_expires_at.replace(tzinfo=None)

        with UnitOfWork() as uow:
            repo = IrisMailboxConnectionRepository(uow)
            existing = repo.get_by_user_provider_email(user_id, provider, token_set.account_email)
            if existing is not None:
                existing.refresh_token_enc = refresh_enc
                existing.access_token_enc = access_enc
                existing.access_token_expires_at = expires_at
                existing.scopes = token_set.scopes
                existing.full_message_mode = full_message_mode
                existing.folder = folder
                existing.status = "active"
                existing.last_error = None
                repo.update(existing)
                return existing.id

            connection = IrisMailboxConnection(
                user_id=user_id, provider=provider, account_email=token_set.account_email,
                scopes=token_set.scopes, refresh_token_enc=refresh_enc,
                access_token_enc=access_enc, access_token_expires_at=expires_at,
                folder=folder, full_message_mode=full_message_mode,
            )
            repo.save(connection)
            return connection.id

    # =========================================================================
    # CRUD
    # =========================================================================

    @staticmethod
    def list_connections(user_id: int) -> list[IrisMailboxConnection]:
        return build_repository(IrisMailboxConnectionRepository).get_by_user(user_id)

    @classmethod
    def assert_connection_ownership(cls, connection_id: int, user_id: int) -> IrisMailboxConnection:
        """Same-error-for-both-cases pattern as IrisManager.assert_analysis_ownership."""
        return assert_owned(IrisMailboxConnectionRepository, connection_id, user_id,
                             IrisMailboxConnectionNotFoundError)

    def update_connection(self, connection_id: int, user_id: int, *,
                           folder: Optional[str] = None,
                           status: Optional[str] = None) -> IrisMailboxConnection:
        self.assert_connection_ownership(connection_id, user_id)
        if status is not None and status not in _VALID_UPDATE_STATUSES:
            raise ValueError(f"status debe ser uno de {_VALID_UPDATE_STATUSES}")

        with UnitOfWork() as uow:
            repo = IrisMailboxConnectionRepository(uow)
            fresh = repo.get_by_id(connection_id)
            if folder is not None:
                fresh.folder = folder
            if status is not None:
                fresh.status = status
            repo.update(fresh)
            return fresh

    def delete_connection(self, connection_id: int, user_id: int) -> None:
        """Revoca el token en el proveedor (best-effort) y borra la fila.

        Un fallo al revocar no bloquea el borrado local -- dejar un refresh
        token vivo en el proveedor tras "desconectar" es un fallo de
        expectativa, pero no debe impedir que el usuario limpie su lista de
        conexiones si el proveedor está caído.
        """
        connection = self.assert_connection_ownership(connection_id, user_id)

        try:
            refresh_token = decrypt_at_rest(connection.refresh_token_enc, purpose="iris_mailbox")
            connector = get_connector(connection.provider, self._redirect_uri(), folder=connection.folder)
            connector.revoke(refresh_token)
        except Exception as e:
            logger.warning(f"No se pudo revocar el token de la conexión {connection_id} en el proveedor: {e}")

        with UnitOfWork() as uow:
            repo = IrisMailboxConnectionRepository(uow)
            fresh = repo.get_by_id(connection_id)
            if fresh is not None:
                repo.delete(fresh)

    # =========================================================================
    # Sondeo / sync
    # =========================================================================

    def trigger_sync(self, connection_id: int, user_id: int) -> None:
        """Sondeo manual: encola el mismo job que el scheduler periódico."""
        self.assert_connection_ownership(connection_id, user_id)
        self.submit_sync(connection_id)

    def submit_sync(self, connection_id: int) -> None:
        """Encola un job de sync para ``connection_id`` sin comprobar ownership
        (uso interno: llamado también por ``IrisMailboxScheduler``, que no
        actúa en nombre de un usuario concreto)."""
        self._tq.submit(
            func=IrisMailboxManager.execute_sync_connection,
            args=(connection_id,),
            name=f"IrisMailboxSync-{connection_id}",
            category=self.TASK_CATEGORY,
            external_id=f"{self.EXTERNAL_ID_PREFIX}{connection_id}",
        )

    @staticmethod
    def execute_sync_connection(connection_id: int) -> None:
        """Entry point submitted to the TaskQueue for a background sync."""
        with job_context():
            IrisMailboxManager()._sync_connection(connection_id)

    def _sync_connection(self, connection_id: int) -> None:
        connection = build_repository(IrisMailboxConnectionRepository).get_by_id(connection_id)
        if connection is None or connection.status != "active":
            return

        try:
            access_token, connector = self._ensure_access_token(connection)
        except _ReauthRequiredError as e:
            self._mark_reauth_required(connection_id, str(e))
            return
        except Exception as e:
            logger.error(f"Fallo refrescando token de la conexión {connection_id}: {e}", exc_info=True)
            self._record_sync_error(connection_id, str(e))
            return

        try:
            refs, new_cursor = connector.list_new(access_token, connection.sync_cursor)
        except Exception as e:
            logger.error(f"Fallo listando mensajes nuevos de la conexión {connection_id}: {e}", exc_info=True)
            self._record_sync_error(connection_id, str(e))
            return

        max_per_day = CR.get_iris_max_ingested_per_day()
        ingested_today, reset_date = self._current_daily_counter(connection)

        for ref in refs:
            if ingested_today >= max_per_day:
                logger.warning(
                    f"Conexión {connection_id} alcanzó la cuota diaria ({max_per_day}); "
                    "el resto de mensajes nuevos se procesará en el próximo sondeo."
                )
                break
            try:
                self._ingest_message(connection, connector, access_token, ref)
                ingested_today += 1
            except Exception as e:
                # Un mensaje roto (parseo, red, o un reintento duplicado que
                # choca con la UNIQUE constraint de idempotencia) no debe
                # tumbar el resto del lote.
                logger.error(
                    f"Fallo analizando el mensaje {ref.provider_message_id} "
                    f"de la conexión {connection_id}: {e}", exc_info=True,
                )

        self._finish_sync(connection_id, new_cursor, ingested_today, reset_date)

    def _ingest_message(self, connection: IrisMailboxConnection, connector: MailboxConnector,
                         access_token: str, ref) -> None:
        title = f"Auto ({connection.account_email})"
        if connection.full_message_mode:
            raw_message = connector.fetch_raw(access_token, ref)
            IrisManager().analyze(
                raw_headers=None, raw_message=raw_message, user_id=connection.user_id,
                title=title, connection_id=connection.id, source_message_uid=ref.provider_message_id,
            )
        else:
            raw_headers = connector.fetch_headers(access_token, ref)
            IrisManager().analyze(
                raw_headers=raw_headers, user_id=connection.user_id,
                title=title, connection_id=connection.id, source_message_uid=ref.provider_message_id,
            )

    def _ensure_access_token(self, connection: IrisMailboxConnection) -> tuple[str, MailboxConnector]:
        """Devuelve un access_token válido, refrescándolo si hace falta.

        Raises:
            _ReauthRequiredError: el proveedor rechazó el refresh (token
                revocado por el usuario, o expirado por inactividad).
        """
        connector = get_connector(connection.provider, self._redirect_uri(), folder=connection.folder)

        now = utcnow_naive()
        if (connection.access_token_enc and connection.access_token_expires_at
                and connection.access_token_expires_at > now):
            return decrypt_at_rest(connection.access_token_enc, purpose="iris_mailbox"), connector

        refresh_token = decrypt_at_rest(connection.refresh_token_enc, purpose="iris_mailbox")
        try:
            token_set = connector.refresh(refresh_token)
        except requests.HTTPError as e:
            status = e.response.status_code if e.response is not None else None
            if status in (400, 401):
                raise _ReauthRequiredError(
                    "El proveedor rechazó el token (revocado o caducado); es necesario reconectar."
                ) from e
            raise

        with UnitOfWork() as uow:
            repo = IrisMailboxConnectionRepository(uow)
            fresh = repo.get_by_id(connection.id)
            if fresh is not None:
                fresh.access_token_enc = encrypt_at_rest(token_set.access_token, purpose="iris_mailbox")
                fresh.refresh_token_enc = encrypt_at_rest(token_set.refresh_token, purpose="iris_mailbox")
                fresh.access_token_expires_at = token_set.access_token_expires_at.replace(tzinfo=None)
                repo.update(fresh)

        return token_set.access_token, connector

    @staticmethod
    def _current_daily_counter(connection: IrisMailboxConnection) -> tuple[int, date]:
        today = utcnow_naive().date()
        if connection.ingested_reset_date == today:
            return connection.ingested_today, today
        return 0, today

    @staticmethod
    def _finish_sync(connection_id: int, new_cursor: str, ingested_today: int, reset_date: date) -> None:
        with UnitOfWork() as uow:
            repo = IrisMailboxConnectionRepository(uow)
            fresh = repo.get_by_id(connection_id)
            if fresh is None:
                return
            fresh.sync_cursor = new_cursor
            fresh.ingested_today = ingested_today
            fresh.ingested_reset_date = reset_date
            fresh.last_sync_at = utcnow_naive()
            fresh.last_error = None
            repo.update(fresh)

    @staticmethod
    def _record_sync_error(connection_id: int, error: str) -> None:
        with UnitOfWork() as uow:
            repo = IrisMailboxConnectionRepository(uow)
            fresh = repo.get_by_id(connection_id)
            if fresh is not None:
                fresh.last_sync_at = utcnow_naive()
                fresh.last_error = error[:2000]
                repo.update(fresh)

    @staticmethod
    def _mark_reauth_required(connection_id: int, error: str) -> None:
        """El proveedor revocó/expiró el token -- para de sondear en vez de
        reintentar en bucle contra su API (mismo patrón degradado que
        ``execute_ai_summary_generation``)."""
        with UnitOfWork() as uow:
            repo = IrisMailboxConnectionRepository(uow)
            fresh = repo.get_by_id(connection_id)
            if fresh is not None:
                fresh.status = "reauth_required"
                fresh.last_sync_at = utcnow_naive()
                fresh.last_error = error[:2000]
                repo.update(fresh)
