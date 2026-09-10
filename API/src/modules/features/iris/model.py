"""
Database models for Iris email header analysis.

IrisAnalysis stores each submitted email header analysis request, its
lifecycle status, and the final score/verdict.  IrisRuleResult stores
the output of every individual rule that was executed during the analysis.
"""

from __future__ import annotations

from typing import Optional

from sqlalchemy import (
    Boolean, Column, Date, DateTime, Float, ForeignKey, Index, Integer,
    SmallInteger, String, Text, UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import deferred, relationship

from src.modules.shared import Base, Document, EncryptedText, utcnow_naive


class IrisAnalysis(Base):
    """Email header analysis request and its final result.

    Each row represents one analysis: the raw headers submitted by the
    user, the lifecycle status, and (once finished) the aggregated score
    and textual verdict.

    Attributes:
        id: Primary key, auto-incrementing integer.
        title: Optional user-defined label for quick identification.
        raw_headers: Cabeceras originales (o el ``.eml`` completo) como
                 texto plano. Property, no columna: el contenido de verdad
                 vive cifrado en la fila ``IrisRawMessage`` asociada
                 (``raw_message``, 1:1) para poder purgarlo de forma
                 independiente sin borrar el resultado analítico ya
                 calculado. Se lee y se escribe exactamente igual
                 que antes de esa separación -- ``analysis.raw_headers`` y
                 ``IrisAnalysis(raw_headers=...)`` siguen funcionando sin
                 cambios en el resto del código. ``None`` cuando la política
                 de retención ya ha purgado el raw de este análisis; a partir
                 de ahí, cualquier vista derivada del raw (cadena Received,
                 IOCs) deja de estar disponible -- ver
                 ``IrisManager.get_analysis_path``/``get_analysis_iocs``.
        status: Lifecycle state — "pending", "running", "finished",
                "failed", or "cancelled".
        total_score: Sum of all rule scores once the analysis completes.
        verdict: Overall classification — "Legitimate", "Suspicious",
                 or "Phishing".
        gate_reasons: List of human-readable reasons for the
                 high-confidence gates that fired (empty when the verdict
                 comes purely from the numeric score).
        analysis_quality: "complete" cuando todas las reglas se ejecutaron,
                 "degraded" cuando alguna no llegó a hacerlo. Un análisis
                 degradado no puede presentarse como limpio sin contexto —
                 ver ``services/quality.py``.
        failed_rules: Reglas que no se pudieron **ejecutar** (una excepción,
                 no un hallazgo), con su nombre, familia y categoría. NULL
                 cuando el análisis fue completo.
        detector_version: Marca del catálogo de reglas que produjo el
                 resultado (``iris-rules:<n>:<hash>``). Sin ella, un informe
                 guardado deja de ser interpretable cuando el catálogo cambia.
        failure_code: Why a ``failed`` analysis failed — "invalid_input"
                 (the submitted text is not an analysable message) or
                 "internal_error" (the pipeline broke). NULL for every
                 non-failed analysis. See ``services/failures.py``.
        failure_reason: Human-readable, **non-sensitive** companion to
                 ``failure_code``. Never contains the raw email: an
                 internal error collapses to a generic message and only
                 the server log keeps the traceback.
        ai_summary: AI-generated executive narrative (IA1) — dict with
                 executive_summary/attacker_intent/recommendations/
                 confidence, or None until generated (or if generation
                 failed/was never requested).
        ai_summary_status: "running" | "done" | "failed", o NULL si nunca se
                 pidió. Es lo que hace idempotente la generación: el manager
                 reclama la fila con una transición condicional sobre esta
                 columna, y quien pierde la carrera no cobra cuota ni encola.
        ai_summary_job_id: Id del trabajo en la cola que lo está generando.
        ai_summary_model / ai_summary_prompt_version: Con qué se generó. Un
                 resumen de hace tres meses lo escribió otro modelo con otro
                 prompt, y sin esto no hay forma de saber cuál (mismo papel
                 que ``detector_version`` para las reglas).
        started_at: Timestamp when the analysis was created.
        finished_at: Timestamp when the analysis reached a terminal state.
        cancel_requested_at: Cuándo el usuario pidió cancelar, si alguna vez
                 lo hizo; NULL si nunca se pidió. Se registra siempre que se
                 llama a ``cancel_analysis()``, gane o no la carrera contra
                 el worker -- es la traza de la intención del usuario, no del
                 resultado, así que no se borra ni se sobreescribe aunque el
                 worker termine primero y el análisis acabe ``finished`` en
                 vez de ``cancelled``.
        user_id: Foreign key to the owning User.
        user: SQLAlchemy relationship to User.
        rule_results: Ordered list of IrisRuleResult (per-rule outcomes).
        connection_id: FK to the IrisMailboxConnection that ingested this
                 message automatically; NULL for manual submissions (the
                 original, still-default flow).
        source_message_uid: Provider-specific message id, set only when
                 connection_id is set. Together with connection_id, a
                 UNIQUE constraint gives idempotency for free — a mailbox
                 sync retry that resubmits the same message is a no-op at
                 the DB level rather than a duplicate analysis. Two manual
                 submissions (connection_id NULL) never collide: standard
                 SQL UNIQUE treats NULL as distinct from every other NULL.
    """
    __tablename__ = "IrisAnalysis"

    id = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(String(120), nullable=True, default=None)
    status = Column(String(20), nullable=False, default="pending")
    total_score = Column(Float, nullable=True)
    verdict = Column(String(20), nullable=True)
    gate_reasons = Column(JSONB, nullable=True)
    analysis_quality = Column(String(16), nullable=True)
    failed_rules = Column(JSONB, nullable=True)
    detector_version = Column(String(64), nullable=True)
    failure_code = Column(String(32), nullable=True)
    failure_reason = Column(Text, nullable=True)
    ai_summary = Column(JSONB, nullable=True)
    ai_summary_status = Column(String(16), nullable=True)
    ai_summary_job_id = Column(String(64), nullable=True)
    ai_summary_model = Column(String(64), nullable=True)
    ai_summary_prompt_version = Column(String(32), nullable=True)
    started_at = Column(DateTime, nullable=False, default=utcnow_naive)
    finished_at = Column(DateTime, nullable=True)
    cancel_requested_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, default=utcnow_naive)

    user_id = Column(Integer, ForeignKey("User.id"), nullable=False)
    connection_id = Column(Integer, ForeignKey("IrisMailboxConnection.id", ondelete="SET NULL"), nullable=True)
    source_message_uid = Column(String(255), nullable=True)

    user = relationship("User", back_populates="analyses")
    connection = relationship("IrisMailboxConnection", back_populates="analyses")
    rule_results = relationship(
        "IrisRuleResult", back_populates="analysis",
        order_by="IrisRuleResult.position",
        cascade="all, delete-orphan",
    )
    documents = relationship(
        "IrisDocument", back_populates="analysis",
        cascade="all, delete-orphan",
    )
    raw_message = relationship(
        "IrisRawMessage", back_populates="analysis", uselist=False,
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        UniqueConstraint("connection_id", "source_message_uid",
                          name="uq_iris_analysis_connection_source_message"),
        Index("ix_iris_analysis_user_id", "user_id"),
        Index("ix_iris_analysis_created_at", "created_at"),
        Index("ix_iris_analysis_status", "status"),
        Index("ix_iris_analysis_verdict", "verdict"),
        Index("ix_iris_analysis_connection_id", "connection_id"),
    )

    @property
    def raw_headers(self) -> Optional[str]:
        """Contenido raw (cabeceras o ``.eml`` completo) de este análisis.

        Delega en ``raw_message.content`` -- ver el docstring de esta clase
        sobre por qué el raw vive en su propia fila en vez de en
        una columna de ``IrisAnalysis``. ``None`` si la retención ya lo
        purgó.
        """
        return self.raw_message.content if self.raw_message is not None else None

    @raw_headers.setter
    def raw_headers(self, value: Optional[str]) -> None:
        if value is None:
            self.raw_message = None
        elif self.raw_message is not None:
            self.raw_message.content = value
        else:
            self.raw_message = IrisRawMessage(content=value)


class IrisRawMessage(Base):
    """Contenido raw (cabeceras o ``.eml`` completo) de un ``IrisAnalysis``,
    en su propia fila -- separado del resultado analítico.

    Antes vivía en ``IrisAnalysis.raw_headers``, una columna en la misma
    fila que el score, el veredicto y el resumen de IA: purgar el raw
    después de un plazo (política de retención) obligaba a elegir entre
    borrar el análisis entero -- perdiendo el resultado, que sí tiene valor
    a largo plazo -- o dejarlo indefinidamente, que es justo lo que la
    retención existe para evitar. Con el raw en su propia fila,
    ``raw_message = None`` sobre el análisis (o borrar directamente esta
    fila) purga el contenido sensible sin tocar el resultado.

    ``content`` usa ``EncryptedText`` (cifrado Fernet transparente,
    ``purpose="iris_raw_message"``) en vez de cifrar/descifrar a mano en
    cada punto de lectura: el motor de reglas parsea este campo en más de
    diez sitios distintos de ``managers/analysis.py``, y repetir esa llamada
    en cada uno convertía cada lectura nueva en una oportunidad de olvidarla.

    Attributes:
        id: Primary key, auto-incrementing integer.
        analysis_id: FK al ``IrisAnalysis`` dueño de este raw; ``UNIQUE``
                 (relación 1:1) y ``ondelete="CASCADE"`` -- borrar el
                 análisis borra su raw, nunca al revés.
        content: El texto plano (cabeceras o ``.eml`` completo), cifrado en
                 la columna real vía ``EncryptedText``. Nunca ``None`` en una
                 fila que existe -- la ausencia de raw se modela con la
                 propia fila ausente (``IrisAnalysis.raw_message is None``),
                 no con este campo a ``None``.
        created_at: Cuándo se guardó -- el mismo instante en que se creó el
                 análisis, salvo que el raw se haya vuelto a asignar (no
                 ocurre hoy en el flujo normal).
        analysis: Relación inversa a ``IrisAnalysis``.
    """
    __tablename__ = "IrisRawMessage"

    id = Column(Integer, primary_key=True, autoincrement=True)
    analysis_id = Column(Integer, ForeignKey("IrisAnalysis.id", ondelete="CASCADE"),
                          nullable=False, unique=True)
    content = Column(EncryptedText(purpose="iris_raw_message"), nullable=False)
    created_at = Column(DateTime, nullable=False, default=utcnow_naive)

    analysis = relationship("IrisAnalysis", back_populates="raw_message")


class IrisMailboxConnection(Base):
    """An external mailbox (Gmail / Microsoft 365) connected by a user for
    automatic Iris ingestion.

    Stores the minimum needed to re-request access later — never the
    mailbox content itself.

    The refresh token cannot live in an Acheron vault: vault fields are only
    ever decrypted on the client, and the background sync needs the server
    to use the token on its own, with no user present. So it is stored here
    instead, encrypted at rest with a server-side key.

    Attributes:
        id: Primary key, auto-incrementing integer.
        user_id: Foreign key to the owning User.
        provider: "gmail" | "microsoft".
        account_email: The connected mailbox's address (plaintext — not a
                 secret, needed to show "which account is this").
        scopes: Space-separated OAuth scopes actually granted.
        refresh_token: Refresh token de OAuth. La columna es
                 ``EncryptedText`` (``purpose="iris_mailbox"``), así que en
                 Python es siempre el token en claro y lo cifrado es la fila.
                 Nunca lo devuelve ningún endpoint.
        access_token: Access token cacheado, con el mismo cifrado; NULL
                 cuando no está cacheado o ha caducado. Opcional -- el
                 conector siempre puede recurrir a ``refresh()``.
                 Junto con ``refresh_token`` se declara ``deferred`` en el
                 grupo ``oauth_tokens``: la mayoría de las cargas de esta
                 fila (listados, health check, planificación del sondeo) no
                 miran los tokens, y tocar cualquiera de los dos trae los
                 dos en una sola consulta, que es como los usa
                 ``_ensure_access_token``.
        access_token_expires_at: Expiry of the cached access token.
        folder: Provider-specific folder/label id to watch; NULL = default
                 inbox. Es el ``provider_id`` opaco que ``MailboxConnector``
                 usa para filtrar ``list_new`` -- nunca texto libre: solo se
                 guarda tras validarse contra ``MailboxConnector.list_folders()``,
                así que un valor no vacío siempre corresponde a una
                 carpeta real de esta cuenta en el momento en que se guardó.
        folder_display_name: Nombre legible de ``folder`` (p.ej. "Facturas",
                 "Trabajo/Clientes"); NULL junto con ``folder`` cuando se
                 vigila la bandeja de entrada por defecto.
        folder_type: "system" (Inbox, Sent, Trash... del propio proveedor) |
                 "user" (etiqueta/carpeta creada por la cuenta); NULL junto
                 con ``folder``.
        full_message_mode: If True, fetch the complete raw message
                 (attachments/body included) instead of headers only. Off
                 by default — the user must opt in explicitly per
                 connection (this is a deliberate, not a hidden,
                 choice).
        sync_cursor: Opaque provider cursor (Gmail historyId / Graph
                 deltaLink) marking how far ingestion has progressed. NULL
                 until the first bootstrap sync runs (see
                 ``services/mailbox`` connectors: the first sync never
                 backfills historical mail, it only captures the starting
                 cursor). Es ``Text`` y no ``String(n)`` a propósito: el
                 ``@odata.deltaLink`` de Graph es una URL completa con un
                 token de estado dentro y rebasa los 255 caracteres. Opaco
                 significa opaco — no se interpreta, no se recorta.
        status: "active" | "reauth_required" | "revoked" | "paused".
        ingested_today / ingested_reset_date: Per-connection daily ingest
                 counter enforcing ``iris.maxIngestedPerDay`` — reset when
                 ``ingested_reset_date`` is no longer today.
        last_sync_at: Timestamp of the last successful sync attempt
                 (successful or not — used to schedule the next poll).
        last_error: Human-readable last error, if any (e.g. why the
                 connection is ``reauth_required``).
        sync_started_at: Cuándo empezó el sync actualmente en curso; NULL
                 cuando no hay ninguno. Se limpia al terminar (éxito o
                 error) -- no confundir con ``last_sync_at``, que registra el
                 último intento *terminado*. Existe para que la UI sepa que
                 hay un sync en marcha sin tener que adivinarlo.
        sync_job_id: Id del job de TaskQueue que sostiene el lock de sync
                 actual; NULL cuando no hay ninguno en curso.
        last_success_at: Cuándo terminó el último sync que dejó la cola de
                 checkpoint (``IrisMailboxInbox``) completamente vacía -- es
                 decir, sin ningún mensaje descubierto pendiente de aceptar.
                 A diferencia de ``last_sync_at`` (que se actualiza aunque
                 queden mensajes atascados por cuota o por un fallo), esto
                 es lo que distingue "no hay correo nuevo" de "Iris está
                 atascado" sin mirar los logs del servidor. NULL si
                 nunca ha terminado un sync sin dejar nada pendiente.
        last_sync_duration_ms: Cuánto tardó el último intento de sync
                 (terminara en éxito o en error), en milisegundos. NULL si
                 nunca ha habido un intento con ``sync_started_at`` registrado
                 -- una latencia que crece sync a sync es la señal de
                 que el proveedor se está degradando antes de que llegue a
                 fallar del todo.
        messages_discovered_total: Cuántos mensajes ha descubierto esta
                 conexión en total desde que existe, contando solo los que de
                 verdad eran nuevos (no un reenvío del proveedor de algo ya
                 encolado). Es un contador acumulado porque, a diferencia de
                 "aceptados" (la tabla ``IrisAnalysis``) o "pendientes"/
                 "fallidos" (la tabla ``IrisMailboxInbox``), la fila de
                 checkpoint de un mensaje aceptado se borra al resolverse, así
                 que sin este contador ese dato desaparecería con ella.
        stuck_alert_sent_at: Cuándo se avisó por última vez de que esta
                 conexión lleva atascada más de ``iris.stuckSyncAfterMinutes``.
                Se limpia en cuanto un sync vuelve a dejar la cola de
                 checkpoint vacía (mismo punto que actualiza
                 ``last_success_at``), así que un problema que se resuelve y
                 vuelve a aparecer más tarde genera un aviso nuevo en vez de
                 quedar silenciado para siempre por el primero.
        created_at: When the connection was established.
        user: SQLAlchemy relationship to User.
        analyses: Analyses ingested through this connection.
        inbox_entries: Cola de checkpoint de mensajes descubiertos y aún no
                 resueltos (ver ``IrisMailboxInbox``).
    """
    __tablename__ = "IrisMailboxConnection"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("User.id"), nullable=False)
    provider = Column(String(20), nullable=False)
    account_email = Column(String(320), nullable=False)
    scopes = Column(String(512), nullable=False)

    refresh_token = deferred(
        Column(EncryptedText(purpose="iris_mailbox"), nullable=False), group="oauth_tokens")
    access_token = deferred(
        Column(EncryptedText(purpose="iris_mailbox"), nullable=True), group="oauth_tokens")
    access_token_expires_at = Column(DateTime, nullable=True)

    folder = Column(String(255), nullable=True)
    folder_display_name = Column(String(255), nullable=True)
    folder_type = Column(String(20), nullable=True)
    full_message_mode = Column(Boolean, nullable=False, default=False)
    sync_cursor = Column(Text, nullable=True)

    status = Column(String(20), nullable=False, default="active")
    ingested_today = Column(Integer, nullable=False, default=0)
    ingested_reset_date = Column(Date, nullable=True)
    last_sync_at = Column(DateTime, nullable=True)
    last_error = Column(Text, nullable=True)
    sync_started_at = Column(DateTime, nullable=True)
    sync_job_id = Column(String(64), nullable=True)
    last_success_at = Column(DateTime, nullable=True)
    last_sync_duration_ms = Column(Integer, nullable=True)
    messages_discovered_total = Column(Integer, nullable=False, default=0)
    stuck_alert_sent_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, default=utcnow_naive)

    user = relationship("User")
    analyses = relationship("IrisAnalysis", back_populates="connection")
    inbox_entries = relationship(
        "IrisMailboxInbox", back_populates="connection",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        UniqueConstraint("user_id", "provider", "account_email",
                          name="uq_iris_mailbox_connection_user_provider_email"),
    )


class IrisMailboxInbox(Base):
    """Cola de checkpoint por mensaje entre el listado del proveedor y su ingesta.

    ``IrisMailboxManager._sync_connection`` confirmaba el cursor del
    proveedor tanto si el lote se ingería entero como si no: una cuota
    agotada o un fallo a mitad de lote perdían en silencio los mensajes que
    quedaban sin procesar, porque el proveedor nunca los vuelve a devolver
    una vez el cursor avanza. Cada mensaje que devuelve ``list_new``
    se encola aquí antes de intentar ingerirlo, y el cursor del proveedor
    solo avanza cuando la cola de la conexión queda vacía.

    Attributes:
        id: Primary key, auto-incrementing integer.
        connection_id: FK a la IrisMailboxConnection que descubrió el
                 mensaje. ``ondelete="CASCADE"``: la cola de una conexión
                 borrada no tiene sentido sin ella.
        provider_message_id: Id opaco del proveedor -- mismo valor que
                 ``IrisAnalysis.source_message_uid`` una vez ingerido.
        raw_ref: Datos crudos que ``list_new`` ya trajo sin round-trip extra
                 (``MessageRef.raw``) -- necesarios para reintentar sin
                 volver a listar (p.ej. Graph guarda aquí las cabeceras).
        status: "pending" (reintentable) | "dead" (agotó los reintentos de
                 ``iris.maxInboxAttempts``; queda visible pero ya no
                 bloquea el avance del cursor -- una única referencia rota
                 no puede detener la ingesta del resto para siempre).
        attempts: Intentos de ingesta fallidos.
        last_error: Motivo del último fallo, si alguno.
        created_at: Cuándo se encoló.
        updated_at: Cuándo se tocó por última vez (reintento o dead-letter).
    """
    __tablename__ = "IrisMailboxInbox"

    id = Column(Integer, primary_key=True, autoincrement=True)
    connection_id = Column(Integer, ForeignKey("IrisMailboxConnection.id", ondelete="CASCADE"),
                            nullable=False, index=True)
    provider_message_id = Column(String(255), nullable=False)
    raw_ref = Column(JSONB, nullable=True)
    status = Column(String(20), nullable=False, default="pending")
    attempts = Column(Integer, nullable=False, default=0)
    last_error = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=False, default=utcnow_naive)
    updated_at = Column(DateTime, nullable=False, default=utcnow_naive, onupdate=utcnow_naive)

    connection = relationship("IrisMailboxConnection", back_populates="inbox_entries")

    __table_args__ = (
        UniqueConstraint("connection_id", "provider_message_id",
                          name="uq_iris_mailbox_inbox_connection_message"),
    )


class IrisRuleResult(Base):
    """Outcome of a single rule during an Iris analysis.

    Stores the score, verdict, details, and optional recommendation
    produced by one rule execution.  Each analysis produces N rows
    (one per registered rule).

    Attributes:
        id: Primary key, auto-incrementing integer.
        analysis_id: Foreign key to the parent IrisAnalysis.
        rule_name: Human-readable rule name (e.g. "SPF", "DKIM").
        category: Rule category (e.g. "authentication", "header_analysis").
        score: Numerical contribution to the total credibility score.
        verdict: Rule-specific result — "pass", "fail", "neutral", etc.
        details: JSONB blob with rule-specific findings and evidence.
        recommendation: Human-readable advice for the user when the
                        rule flagged a problem; null if the rule passed.
        position: Execution order (0-based) within the analysis.
        analysis: SQLAlchemy back-reference to the parent IrisAnalysis.
    """
    __tablename__ = "IrisRuleResult"

    id = Column(Integer, primary_key=True, autoincrement=True)
    analysis_id = Column(Integer, ForeignKey("IrisAnalysis.id"), nullable=False)
    rule_name = Column(String(64), nullable=False)
    category = Column(String(32), nullable=True)
    score = Column(Float, nullable=False)
    verdict = Column(String(20), nullable=False)
    details = Column(JSONB, nullable=True)
    recommendation = Column(Text, nullable=True)
    position = Column(SmallInteger, nullable=False, default=0)

    analysis = relationship("IrisAnalysis", back_populates="rule_results")

    __table_args__ = (
        Index("ix_iris_rule_result_analysis_id", "analysis_id"),
    )


class IrisDocument(Document):
    """PDF report generated from a finished Iris analysis.

    Inherits from Document (shared model) and adds analysis-specific
    fields. Stores the generated PDF path and a snapshot of the verdict
    so listings can filter/display without joining IrisAnalysis.

    Inherits from Document:
        id, document_type, filename, format, status,
        created_at, generated_at, user_id, user

    Attributes:
        id: Primary key (foreign key to Document.id).
        analysis_id: Foreign key to IrisAnalysis.id (cascade delete).
        verdict: Snapshot of the analysis verdict at generation time.
        analysis: Relationship to the source IrisAnalysis.
    """
    __tablename__ = "IrisDocument"

    id = Column(Integer, ForeignKey("Document.id"), primary_key=True)
    analysis_id = Column(Integer, ForeignKey("IrisAnalysis.id", ondelete="CASCADE"), nullable=False)
    verdict = Column(String(20), nullable=True)

    analysis = relationship("IrisAnalysis", back_populates="documents")

    __mapper_args__ = {
        "polymorphic_identity": "iris",
    }

    def __repr__(self) -> str:
        return (
            f"<IrisDocument(id={self.id}, analysis_id={self.analysis_id}, "
            f"status='{self.status}')>"
        )


class IrisNotificationPreference(Base):
    """Preferencias de notificación de un usuario para las alertas
    automáticas de Iris: una fila por usuario, creada perezosamente
    la primera vez que la modifica (ver ``IrisNotificationPreferenceManager``).

    Deliberadamente por usuario y no por conexión: hoy Iris solo tiene un
    canal de envío (correo, vía ``herald``), y separar preferencias por
    conexión antes de que exista una segunda variable real que lo justifique
    sería una tabla más ancha sin ningún control que la necesite todavía.
    Si en el futuro hace falta silenciar una conexión concreta sin tocar las
    demás, este es el sitio donde añadir esa columna.

    Attributes:
        id: Primary key, auto-incrementing integer.
        user_id: FK al ``User`` dueño de estas preferencias; único, porque
                 solo existe una fila por usuario.
        digest_enabled: Si está activo, los veredictos Phishing que no sean
                 de alta confianza (``total_score`` por encima de
                 ``iris.criticalPhishingScoreThreshold``) no se notifican al
                 momento -- se agrupan en el resumen diario que envía el
                 scheduler de Iris (``services/notifications/scheduling.py``).
                 Los de alta confianza siempre se notifican de inmediato,
                 esté o no activo el digest.
        muted_until: Si tiene una fecha futura, ninguna notificación no
                 crítica se envía hasta entonces (silenciado temporal). Igual
                 que con el digest, un veredicto Phishing de alta confianza
                 ignora este campo -- nunca se pierde una incidencia crítica
                 por estar silenciada. ``None`` cuando no hay silenciado
                 activo.
        notify_reauth_required: Si se avisa por correo cuando una conexión
                 pasa a necesitar reautorización (``status="reauth_required"``).
                 Por defecto ``True``.
        notify_sync_stuck: Si se avisa quando una conexión activa lleva más
                 de ``iris.stuckSyncAfterMinutes`` sin completar un sync
                 limpio (ver ``IrisMailboxConnection.last_success_at``).
                 Por defecto ``True``.
        digest_last_sent_at: Cuándo se envió el último digest a este usuario;
                 ``None`` si nunca se ha enviado uno. El scheduler lo usa
                 para saber si ya pasó ``iris.digestIntervalHours`` desde
                 entonces, y para acotar qué análisis entran en el próximo
                 envío.
        created_at: Cuándo se creó esta fila (primera vez que el usuario
                 tocó sus preferencias).
        updated_at: Última vez que se modificó cualquier campo.
        user: SQLAlchemy relationship al ``User`` dueño.
    """
    __tablename__ = "IrisNotificationPreference"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("User.id"), nullable=False, unique=True)
    digest_enabled = Column(Boolean, nullable=False, default=False)
    muted_until = Column(DateTime, nullable=True)
    notify_reauth_required = Column(Boolean, nullable=False, default=True)
    notify_sync_stuck = Column(Boolean, nullable=False, default=True)
    digest_last_sent_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, default=utcnow_naive)
    updated_at = Column(DateTime, nullable=False, default=utcnow_naive, onupdate=utcnow_naive)

    user = relationship("User")
