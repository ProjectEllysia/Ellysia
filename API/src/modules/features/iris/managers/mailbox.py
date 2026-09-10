"""
IrisMailboxManager — OAuth connect/callback, connection CRUD, and background
mailbox sync for the Iris mailbox connector.

Fichero separado de ``managers.py`` (que ya tiene 1080+ líneas con
IrisManager + IrisReportManager) siguiendo el precedente de módulos grandes
divididos en varios ficheros de manager (``themis/managers/`` es un paquete
con scan.py/reports.py/traceroute.py, etc.).

La ingesta NO reimplementa nada del motor de reglas: cada mensaje nuevo se
entrega a ``IrisManager.analyze()``, que ya existe. Este manager solo se
ocupa de OAuth, credenciales cifradas, y el ciclo de sondeo.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import date, datetime
from typing import Any, Optional

import requests
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlalchemy import update

import src.modules.system.config_reading as CR
from src.modules.accounts import LimitKey, QuotaManager
from src.modules.infrastructure import UnitOfWork
from src.modules.infrastructure.session import build_repository
from src.modules.shared import assert_owned, utcnow_naive
from src.modules.system.taskqueue import TaskTrackingMixin, job_context
from src.modules.system.taskqueue.connection import RedisConnectionFactory
from src.modules.system.taskqueue.dispatcher import OutboxDispatcher
from src.modules.system.taskqueue.outbox_repository import TaskDispatchRepository

from ..exceptions import (
    IrisMailboxConnectionNotFoundError,
    IrisMailboxInvalidFolderError,
    IrisMailboxInvalidProviderError,
    IrisMailboxOAuthStateError,
    IrisMailboxQuotaExceededError,
)
from .analysis import IrisManager
from .notifications import IrisReauthNotifyManager
from ..model import IrisMailboxConnection, IrisMailboxInbox
from ..repositories import (
    IrisAnalysisRepository, IrisMailboxConnectionRepository, IrisMailboxInboxRepository,
)
from ..services.mailbox import (
    MAILBOX_CONNECTORS, MailboxConnector, MailboxFolder, MessageRef, get_connector,
)
from ..services.mailbox.locks import MailboxSyncLock
from ..services.parsers import build_subject_title

logger = logging.getLogger(__name__)

_STATE_SALT = "iris-mailbox-oauth-state"
_STATE_MAX_AGE_SECONDS = 600  # 10 minutos — ver Decisión 5 del plan de sesión.
_STATE_USED_KEY_PREFIX = "iris:mailbox:oauth-state-used:"

_VALID_UPDATE_STATUSES = ("active", "paused")


def _duration_ms(started_at: Optional[datetime]) -> Optional[int]:
    """Milisegundos transcurridos desde ``started_at`` hasta ahora.

    Args:
        started_at: Cuándo empezó el intento de sync que se está cerrando
            (``IrisMailboxConnection.sync_started_at`` leído justo antes de
            sobreescribirlo). ``None`` cuando no se sabe cuándo empezó -- no
            debería pasar en un sync real, pero una fila tocada a mano en un
            test o una migración a medio aplicar no debe reventar esto.

    Returns:
        Optional[int]: Milisegundos transcurridos, o ``None`` si
            ``started_at`` es ``None`` (sin esto, un sync sin duración
            conocida se vería como "0 ms", que parece salud perfecta en vez
            de un dato ausente).
    """
    if started_at is None:
        return None
    return int((utcnow_naive() - started_at).total_seconds() * 1000)


class _ReauthRequiredError(Exception):
    """Señal interna: el proveedor rechazó el refresh_token (revocado/expirado).

    No es una IrisError pública — se maneja íntegramente dentro de
    ``_sync_connection``, nunca cruza el límite de un endpoint.
    """


class IrisMailboxManager(TaskTrackingMixin):
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

    #: Orden de presentación en /iris/mailbox/providers — no es alfabético a
    #: propósito: Microsoft no exige verificación de Google para salir de
    #: modo "testing", así que es el conector que de verdad funciona de cara
    #: al lanzamiento y debe encabezar la lista. Cualquier provider nuevo que
    #: no esté aquí se añade al final, alfabéticamente.
    _PROVIDER_DISPLAY_ORDER = ("microsoft", "gmail")

    # __init__ (task_queue inyectable) lo aporta TaskTrackingMixin. Ya
    # declaraba TASK_CATEGORY/EXTERNAL_ID_PREFIX sin heredar del mixin —
    # ahora hereda también external_id_for/find_task/task_status_of.

    # =========================================================================
    # OAuth: connect / callback
    # =========================================================================

    @staticmethod
    def list_providers() -> list[str]:
        ordered = [provider for provider in IrisMailboxManager._PROVIDER_DISPLAY_ORDER if provider in MAILBOX_CONNECTORS]
        remaining = sorted(MAILBOX_CONNECTORS.keys() - set(ordered))
        return ordered + remaining

    @staticmethod
    def _redirect_uri() -> str:
        """Construido desde PUBLIC_WEB_URL, nunca desde un parámetro del
        request (evita un open-redirect en el flujo OAuth). El origen del
        frontend ya proxya las rutas de la API (ver ``npm run dev`` en
        ``web/app``), así que esta URL llega al backend igual en dev y prod.
        """
        return f"{CR.general_config().public_url}/iris/mailbox/callback"

    @staticmethod
    def _state_serializer() -> URLSafeTimedSerializer:
        # Reutiliza JWT_SECRET_KEY (ya es un secreto fuerte existente) en vez
        # de introducir uno nuevo solo para firmar el state -- distinto
        # "salt" evita que una firma de state sea válida como JWT y viceversa.
        secret = CR.jwt_config().secret
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

    @classmethod
    def _consume_state(cls, state: str) -> None:
        """Marca ``state`` como usado para que el callback no sea repetible.

        La firma + TTL de ``_verify_state`` bastan contra falsificación, pero
        no contra repetición: un ``state`` capturado (log, proxy, enlace
        reenviado) seguiría siendo válido durante toda su ventana de 10
        minutos. ``SET NX`` en Redis da un consumo atómico de un solo uso sin
        estado nuevo en Postgres -- la clave expira sola con el mismo TTL que
        ya limita la validez de la firma.
        """
        key = _STATE_USED_KEY_PREFIX + hashlib.sha256(state.encode()).hexdigest()
        already_used = not RedisConnectionFactory.decoded().set(
            key, "1", nx=True, ex=_STATE_MAX_AGE_SECONDS,
        )
        if already_used:
            raise IrisMailboxOAuthStateError(
                "Este enlace de conexión ya se usó. Vuelve a iniciar el proceso."
            )

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

        # Se comprueba aquí y no en handle_callback, donde nace la fila: es
        # mejor decir que no antes de mandar al usuario a Google que después de
        # que haya dado su consentimiento, y el callback responde con una
        # redirección al frontend, donde un 402 no se vería.
        #
        # Al ser existencias no se apunta nada: se cuenta la tabla real, así que
        # reintentar el flujo no cobra dos veces. Dos conexiones iniciadas a la
        # vez podrían colarse por encima del tope; se vería como "excedido" en
        # el uso, que es la misma situación que deja una bajada de plan.
        QuotaManager().consume(user_id, LimitKey.IRIS_MAILBOX_CONNECTIONS)

        existing = build_repository(IrisMailboxConnectionRepository).count_for_user(user_id)
        max_connections = CR.iris_config().max_connections_per_user
        if existing >= max_connections:
            raise IrisMailboxQuotaExceededError(
                f"Ya tienes {existing} conexiones activas (máximo {max_connections})."
            )

        state = self._sign_state(user_id=user_id, provider=provider,
                                  full_message_mode=full_message_mode, folder=folder)
        connector = get_connector(provider, self._redirect_uri(), folder=folder)
        return connector.authorize_url(state, full_message_mode)

    def handle_callback(self, state: str, code: str) -> int:  # pylint: disable=too-many-locals
        """Canjea el code OAuth y crea (o reactiva) la conexión.

        Reconectar una cuenta ya conocida (mismo user/provider/email)
        actualiza sus credenciales en vez de fallar por la UNIQUE
        constraint -- es el camino natural para "reautorizar" tras
        ``reauth_required``.

        Returns:
            El id de la IrisMailboxConnection creada o actualizada.
        """
        claims = self._verify_state(state)
        self._consume_state(state)
        user_id = claims["user_id"]
        provider = claims["provider"]
        full_message_mode = claims["full_message_mode"]
        folder = claims.get("folder")

        connector = get_connector(provider, self._redirect_uri(), folder=folder)
        token_set = connector.exchange_code(code)

        # Recién canjeado el code tenemos un access_token fresco -- es
        # el único momento del flujo de conexión en que se puede comprobar
        # la carpeta contra la cuenta real antes de guardarla.
        folder_metadata = (
            self._validate_folder(connector, token_set.access_token, folder)
            if folder is not None else None
        )

        expires_at = token_set.access_token_expires_at.replace(tzinfo=None)

        with UnitOfWork() as uow:
            repo = IrisMailboxConnectionRepository(uow)
            existing = repo.get_by_user_provider_email(user_id, provider, token_set.account_email)
            if existing is not None:
                existing.refresh_token = token_set.refresh_token
                existing.access_token = token_set.access_token
                existing.access_token_expires_at = expires_at
                existing.scopes = token_set.scopes
                existing.full_message_mode = full_message_mode
                existing.folder = folder
                existing.folder_display_name = (
                    folder_metadata.display_name if folder_metadata else None
                )
                existing.folder_type = folder_metadata.folder_type if folder_metadata else None
                existing.status = "active"
                existing.last_error = None
                repo.update(existing)
                return existing.id

            connection = IrisMailboxConnection(
                user_id=user_id, provider=provider, account_email=token_set.account_email,
                scopes=token_set.scopes, refresh_token=token_set.refresh_token,
                access_token=token_set.access_token, access_token_expires_at=expires_at,
                folder=folder, full_message_mode=full_message_mode,
                folder_display_name=folder_metadata.display_name if folder_metadata else None,
                folder_type=folder_metadata.folder_type if folder_metadata else None,
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
        connection = self.assert_connection_ownership(connection_id, user_id)
        if status is not None and status not in _VALID_UPDATE_STATUSES:
            raise ValueError(f"status debe ser uno de {_VALID_UPDATE_STATUSES}")

        # Cambiar de carpeta exige un access_token vivo para comprobarla
        # contra la cuenta real -- lo mismo que list_folders().
        folder_display_name = None
        folder_type = None
        if folder is not None:
            try:
                access_token, connector = self._ensure_access_token(connection)
            except _ReauthRequiredError as e:
                self._mark_reauth_required(connection_id, str(e))
                raise ValueError(
                    "La conexión necesita reautorización antes de poder cambiar de carpeta."
                ) from e
            matched = self._validate_folder(connector, access_token, folder)
            folder_display_name = matched.display_name
            folder_type = matched.folder_type

        with UnitOfWork() as uow:
            repo = IrisMailboxConnectionRepository(uow)
            fresh = repo.get_by_id(connection_id)
            if folder is not None:
                fresh.folder = folder
                fresh.folder_display_name = folder_display_name
                fresh.folder_type = folder_type
            if status is not None:
                fresh.status = status
            repo.update(fresh)
            return fresh

    def list_folders(self, connection_id: int, user_id: int) -> list[MailboxFolder]:
        """Carpetas/etiquetas reales de la cuenta -- únicos valores válidos
        para ``folder`` en ``update_connection()``."""
        connection = self.assert_connection_ownership(connection_id, user_id)
        try:
            access_token, connector = self._ensure_access_token(connection)
        except _ReauthRequiredError as e:
            self._mark_reauth_required(connection_id, str(e))
            raise
        return connector.list_folders(access_token)

    def get_connection_health(self, connection_id: int, user_id: int) -> dict:
        """Estado observable de una conexión, sin tener que leer los logs
        del servidor.

        Reúne columnas de la propia conexión con recuentos en vivo de
        ``IrisMailboxInbox`` (pendientes/reintentando/``dead``) y de
        ``IrisAnalysis`` (aceptados) -- salvo ``messages_discovered_total``,
        ningún dato aquí es un contador aparte que pudiera desincronizarse
        de la tabla real (mismo criterio que ``QuotaManager`` aplica a las
        claves de tipo "stock": lo que se puede contar, se cuenta, no se
        acumula por separado).

        Args:
            connection_id: Primary key de la ``IrisMailboxConnection`` a
                consultar.
            user_id: Id del propietario (debe coincidir con el dueño de la
                conexión).

        Returns:
            dict: Con las claves ``status``, ``last_sync_at``,
                ``last_success_at``, ``last_error``, ``sync_started_at``,
                ``last_sync_duration_ms``, ``cursor_established`` (bool),
                ``ingested_today``, ``max_ingested_per_day``,
                ``messages_discovered_total``, ``messages_accepted_total``,
                ``messages_pending``, ``messages_retrying``,
                ``messages_dead`` y ``oldest_pending_message_age_seconds``
                (``None`` si no hay ningún mensaje pendiente). El endpoint
                que lo expone lo traduce a camelCase.

        Raises:
            IrisMailboxConnectionNotFoundError: La conexión no existe o no
                pertenece a este usuario.
        """
        connection = self.assert_connection_ownership(connection_id, user_id)

        inbox_repo = build_repository(IrisMailboxInboxRepository)
        oldest_pending_at = inbox_repo.oldest_pending_created_at(connection_id)
        oldest_pending_age_seconds = (
            int((utcnow_naive() - oldest_pending_at).total_seconds())
            if oldest_pending_at is not None else None
        )

        return {
            "status": connection.status,
            "last_sync_at": connection.last_sync_at,
            "last_success_at": connection.last_success_at,
            "last_error": connection.last_error,
            "sync_started_at": connection.sync_started_at,
            "last_sync_duration_ms": connection.last_sync_duration_ms,
            "cursor_established": connection.sync_cursor is not None,
            "ingested_today": connection.ingested_today,
            "max_ingested_per_day": CR.iris_config().max_ingested_per_day,
            "messages_discovered_total": connection.messages_discovered_total,
            "messages_accepted_total": build_repository(IrisAnalysisRepository).count_by_connection(
                connection_id,
            ),
            "messages_pending": inbox_repo.count_pending(connection_id),
            "messages_retrying": inbox_repo.count_retrying(connection_id),
            "messages_dead": inbox_repo.count_dead(connection_id),
            "oldest_pending_message_age_seconds": oldest_pending_age_seconds,
        }

    @staticmethod
    def _validate_folder(
        connector: MailboxConnector, access_token: str, folder: str,
    ) -> MailboxFolder:
        """Comprueba ``folder`` contra las carpetas reales de la cuenta.

        Raises:
            IrisMailboxInvalidFolderError: ``folder`` no existe para esta
                cuenta y proveedor -- id equivocado, error tipográfico, o un
                valor que pertenece a otro proveedor.
        """
        folders = connector.list_folders(access_token)
        match = next((candidate for candidate in folders if candidate.provider_id == folder), None)
        if match is None:
            raise IrisMailboxInvalidFolderError(folder)
        return match

    def delete_connection(self, connection_id: int, user_id: int) -> None:
        """Revoca el token en el proveedor (best-effort) y borra la fila.

        Un fallo al revocar no bloquea el borrado local -- dejar un refresh
        token vivo en el proveedor tras "desconectar" es un fallo de
        expectativa, pero no debe impedir que el usuario limpie su lista de
        conexiones si el proveedor está caído.
        """
        connection = self.assert_connection_ownership(connection_id, user_id)

        try:
            connector = get_connector(connection.provider, self._redirect_uri(), folder=connection.folder)
            connector.revoke(connection.refresh_token)
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
        actúa en nombre de un usuario concreto).

        Encola directo, sin la outbox transaccional: no persiste ninguna fila
        antes del ``submit()``, así que no hay huérfano que prevenir, y un
        encolado perdido se repara solo en la siguiente pasada del
        ``IrisMailboxScheduler``, que sondea periódicamente todas las
        conexiones.
        """
        self._task_queue.submit(
            func=IrisMailboxManager.execute_sync_connection,
            args=(connection_id,),
            name=f"IrisMailboxSync-{connection_id}",
            category=self.TASK_CATEGORY,
            external_id=self.external_id_for(connection_id),
        )

    @staticmethod
    def execute_sync_connection(connection_id: int) -> None:
        """Entry point submitted to the TaskQueue for a background sync."""
        with job_context() as job:
            IrisMailboxManager()._sync_connection(connection_id, job_id=job.id)

    def _sync_connection(self, connection_id: int, job_id: Optional[str] = None) -> None:
        connection = build_repository(IrisMailboxConnectionRepository).get_by_id(connection_id)
        if connection is None or connection.status != "active":
            return

        # Serializa los syncs de una misma conexión. El job_id
        # determinista de TaskQueue ya evita reencolar mientras el anterior
        # sigue "started", pero ese estado no se autorrecupera si el worker
        # muere a mitad de sync -- este lock sí, por TTL.
        lock = MailboxSyncLock(connection_id, CR.iris_config().mailbox_sync_lock_ttl_seconds)
        if not lock.acquire():
            logger.info(f"Sync de la conexión {connection_id} ya en curso; se omite este sondeo.")
            return

        try:
            self._mark_sync_started(connection_id, job_id)

            try:
                access_token, connector = self._ensure_access_token(connection)
            except _ReauthRequiredError as e:
                self._mark_reauth_required(connection_id, str(e))
                return
            except Exception as e:
                logger.error(
                    f"Fallo refrescando token de la conexión {connection_id}: {e}", exc_info=True,
                )
                self._record_sync_error(connection_id, str(e))
                return

            try:
                refs, new_cursor = connector.list_new(access_token, connection.sync_cursor)
            except Exception as e:
                logger.error(
                    f"Fallo listando mensajes nuevos de la conexión {connection_id}: {e}", exc_info=True,
                )
                self._record_sync_error(connection_id, str(e))
                return

            # El mensaje entra en la cola de checkpoint antes de intentar
            # ingerirlo -- así una cuota agotada o un fallo a mitad de lote no
            # lo pierden, sino que lo dejan pendiente para el próximo sondeo.
            self._enqueue_pending(connection_id, refs)

            max_per_day = CR.iris_config().max_ingested_per_day
            ingested_today, reset_date = self._current_daily_counter(connection)
            ingested_today = self._drain_pending(
                connection, connector, access_token, ingested_today, max_per_day, lock,
            )

            # El cursor del proveedor solo se confirma cuando la cola queda
            # vacía: confirmarlo con referencias pendientes las perdería para
            # siempre, porque ni Gmail ni Graph vuelven a listar un mensaje
            # una vez el cursor avanza más allá de él.
            advance_cursor = not build_repository(IrisMailboxInboxRepository).has_pending(connection_id)
            self._finish_sync(connection_id, new_cursor, ingested_today, reset_date, advance_cursor)
        finally:
            self._clear_sync_started(connection_id)
            lock.release()

    @staticmethod
    def _mark_sync_started(connection_id: int, job_id: Optional[str]) -> None:
        with UnitOfWork() as uow:
            repo = IrisMailboxConnectionRepository(uow)
            fresh = repo.get_by_id(connection_id)
            if fresh is not None:
                fresh.sync_started_at = utcnow_naive()
                fresh.sync_job_id = job_id
                repo.update(fresh)

    @staticmethod
    def _clear_sync_started(connection_id: int) -> None:
        with UnitOfWork() as uow:
            repo = IrisMailboxConnectionRepository(uow)
            fresh = repo.get_by_id(connection_id)
            if fresh is not None:
                fresh.sync_started_at = None
                fresh.sync_job_id = None
                repo.update(fresh)

    @staticmethod
    def _enqueue_pending(connection_id: int, refs: list[MessageRef]) -> None:
        """Encola cada mensaje nuevo en ``IrisMailboxInbox``, saltando los que
        ya estaban en cola de un sondeo anterior (pendientes o ``dead``)."""
        if not refs:
            return
        with UnitOfWork() as uow:
            repo = IrisMailboxInboxRepository(uow)
            existing_ids = repo.get_existing_provider_ids(
                connection_id, [ref.provider_message_id for ref in refs],
            )
            new_refs = [ref for ref in refs if ref.provider_message_id not in existing_ids]
            for ref in new_refs:
                repo.save(IrisMailboxInbox(
                    connection_id=connection_id,
                    provider_message_id=ref.provider_message_id,
                    raw_ref=ref.raw or None,
                ))

            if new_refs:
                # Contador acumulado -- la fila de checkpoint de un
                # mensaje aceptado se borra al resolverse, así que sin esto
                # "cuántos ha descubierto esta conexión en total" se perdería
                # con ella. Incremento atómico dentro del propio UPDATE, no
                # leer-sumar-escribir.
                uow.session.execute(
                    update(IrisMailboxConnection)
                    .where(IrisMailboxConnection.id == connection_id)
                    .values(
                        messages_discovered_total=(
                            IrisMailboxConnection.messages_discovered_total + len(new_refs)
                        ),
                    )
                )

    def _drain_pending(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        self, connection: IrisMailboxConnection, connector: MailboxConnector,
        access_token: str, ingested_today: int, max_per_day: int, lock: MailboxSyncLock,
    ) -> int:
        """Procesa la cola de checkpoint (mensajes recién encolados y los que
        quedaron pendientes de sondeos anteriores) hasta agotar la cuota
        diaria. Devuelve el contador de ingeridos actualizado."""
        connection_id = connection.id
        inbox_repo = build_repository(IrisMailboxInboxRepository)
        analysis_repo = build_repository(IrisAnalysisRepository)

        for entry in inbox_repo.get_pending(connection_id):
            # Un lote grande puede tardar más que el TTL inicial del
            # lock -- renovarlo en cada mensaje evita que otro sync lo dé
            # por huérfano mientras éste sigue trabajando de verdad.
            lock.renew()

            if ingested_today >= max_per_day:
                logger.warning(
                    f"Conexión {connection_id} alcanzó la cuota diaria ({max_per_day}); "
                    "el resto de mensajes pendientes se procesará en el próximo sondeo."
                )
                break

            if analysis_repo.exists_by_source(connection_id, entry.provider_message_id):
                # Ya se aceptó en un intento anterior (p.ej. un fallo entre
                # el commit del análisis y el borrado de esta entrada) --
                # resolver sin reintentar ni contarlo de nuevo.
                self._resolve_inbox_entry(entry.id)
                continue

            ref = MessageRef(provider_message_id=entry.provider_message_id, raw=entry.raw_ref or {})
            try:
                self._ingest_message(connection, connector, access_token, ref)
                ingested_today += 1
                self._resolve_inbox_entry(entry.id)
            except Exception as e:
                # Un mensaje roto (parseo, red) no debe tumbar el resto del
                # lote -- queda pendiente (o dead-letter tras demasiados
                # intentos) para no bloquear el resto de la cola para siempre.
                logger.error(
                    f"Fallo analizando el mensaje {entry.provider_message_id} "
                    f"de la conexión {connection_id}: {e}", exc_info=True,
                )
                self._retry_or_deadletter(entry.id, str(e))

        return ingested_today

    @staticmethod
    def _resolve_inbox_entry(entry_id: int) -> None:
        with UnitOfWork() as uow:
            repo = IrisMailboxInboxRepository(uow)
            entry = repo.get_by_id(entry_id)
            if entry is not None:
                repo.delete(entry)

    @staticmethod
    def _retry_or_deadletter(entry_id: int, error: str) -> None:
        max_attempts = CR.iris_config().max_inbox_attempts
        with UnitOfWork() as uow:
            repo = IrisMailboxInboxRepository(uow)
            entry = repo.get_by_id(entry_id)
            if entry is None:
                return
            entry.attempts += 1
            entry.last_error = error[:2000]
            if entry.attempts >= max_attempts:
                entry.status = "dead"
            repo.update(entry)

    def _ingest_message(self, connection: IrisMailboxConnection, connector: MailboxConnector,
                         access_token: str, ref) -> None:
        if connection.full_message_mode:
            raw_message = connector.fetch_raw(access_token, ref)
            IrisManager().analyze(
                raw_headers=None, raw_message=raw_message, user_id=connection.user_id,
                title=build_subject_title(raw_message), connection_id=connection.id,
                source_message_uid=ref.provider_message_id,
            )
        else:
            raw_headers = connector.fetch_headers(access_token, ref)
            IrisManager().analyze(
                raw_headers=raw_headers, user_id=connection.user_id,
                title=build_subject_title(raw_headers), connection_id=connection.id,
                source_message_uid=ref.provider_message_id,
            )

    def _ensure_access_token(self, connection: IrisMailboxConnection) -> tuple[str, MailboxConnector]:
        """Devuelve un access_token válido, refrescándolo si hace falta.

        Raises:
            _ReauthRequiredError: el proveedor rechazó el refresh (token
                revocado por el usuario, o expirado por inactividad).
        """
        connector = get_connector(connection.provider, self._redirect_uri(), folder=connection.folder)

        now = utcnow_naive()
        if (connection.access_token and connection.access_token_expires_at
                and connection.access_token_expires_at > now):
            return connection.access_token, connector

        try:
            token_set = connector.refresh(connection.refresh_token)
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
                fresh.access_token = token_set.access_token
                fresh.refresh_token = token_set.refresh_token
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
    def _finish_sync(
        connection_id: int, new_cursor: str, ingested_today: int, reset_date: date,
        advance_cursor: bool = True,
    ) -> None:
        with UnitOfWork() as uow:
            repo = IrisMailboxConnectionRepository(uow)
            fresh = repo.get_by_id(connection_id)
            if fresh is None:
                return
            if advance_cursor:
                fresh.sync_cursor = new_cursor
                # Solo cuando la cola de checkpoint queda vacía se puede
                # decir de verdad "todo al día" -- last_sync_at por sí solo no
                # distingue eso de un sync que dejó mensajes atascados.
                fresh.last_success_at = utcnow_naive()
                # Un sync limpio resuelve cualquier atasco anterior --
                # se limpia aquí, no solo cuando se envía el aviso, para que
                # una recaída futura genere un aviso nuevo en vez de quedar
                # silenciada para siempre por la primera.
                fresh.stuck_alert_sent_at = None
            fresh.ingested_today = ingested_today
            fresh.ingested_reset_date = reset_date
            fresh.last_sync_at = utcnow_naive()
            fresh.last_sync_duration_ms = _duration_ms(fresh.sync_started_at)
            fresh.last_error = None
            repo.update(fresh)

    @staticmethod
    def _record_sync_error(connection_id: int, error: str) -> None:
        with UnitOfWork() as uow:
            repo = IrisMailboxConnectionRepository(uow)
            fresh = repo.get_by_id(connection_id)
            if fresh is not None:
                fresh.last_sync_at = utcnow_naive()
                fresh.last_sync_duration_ms = _duration_ms(fresh.sync_started_at)
                fresh.last_error = error[:2000]
                repo.update(fresh)

    @staticmethod
    def _mark_reauth_required(connection_id: int, error: str) -> None:
        """El proveedor revocó/expiró el token -- para de sondear en vez de
        reintentar en bucle contra su API (mismo patrón degradado que
        ``execute_ai_summary_generation``).

        Avisa al dueño de la conexión, pero solo en la transición
        hacia este estado: los tres puntos que llaman a este método pueden
        volver a invocarlo mientras la conexión sigue sin reautorizar (un
        segundo intento de cambiar de carpeta, por ejemplo), y sin esta
        comprobación cada uno de esos reintentos mandaría un correo nuevo.

        El cambio de estado y la intención de avisar se confirman juntos, y
        en el momento, por dos motivos:

        - El estado es el guardia. Cuando se confirmaba solo y el encolado
          fallaba después, las llamadas siguientes lo veían ya puesto y el
          aviso no llegaba nunca.
        - Dos de los tres llamantes (``update_connection`` y ``list_folders``)
          corren dentro de una request y lanzan una excepción justo después,
          así que ``teardown_request`` hace rollback. Sin un commit explícito
          aquí, el estado se perdía con él, y el job ya encolado veía la
          conexión todavía ``active`` y descartaba el aviso.

        Args:
            connection_id: Primary key de la ``IrisMailboxConnection`` cuyo
                token rechazó el proveedor. Si ya no existe, no se hace nada.
            error: Motivo que devolvió el proveedor; se guarda en
                ``last_error`` recortado a 2000 caracteres.
        """
        dispatch_id = None
        with UnitOfWork() as uow:
            repo = IrisMailboxConnectionRepository(uow)
            fresh = repo.get_by_id(connection_id)
            if fresh is None:
                return
            was_already_reauth_required = fresh.status == "reauth_required"
            fresh.status = "reauth_required"
            fresh.last_sync_at = utcnow_naive()
            fresh.last_sync_duration_ms = _duration_ms(fresh.sync_started_at)
            fresh.last_error = error[:2000]
            repo.update(fresh)
            if not was_already_reauth_required:
                dispatch_id = TaskDispatchRepository(uow).save(
                    IrisReauthNotifyManager.build_dispatch_for(connection_id),
                ).id
            uow.commit_for_handoff()
        if dispatch_id is not None:
            # Camino feliz: publicar ya. Si Redis falla, la fila queda
            # `pending` y la recogen el barrido periódico o la reconciliación
            # de arranque.
            OutboxDispatcher.dispatch(dispatch_id)
