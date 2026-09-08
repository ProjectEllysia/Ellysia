"""
Database models for Iris email header analysis.

IrisAnalysis stores each submitted email header analysis request, its
lifecycle status, and the final score/verdict.  IrisRuleResult stores
the output of every individual rule that was executed during the analysis.
"""

from __future__ import annotations

from sqlalchemy import (
    Boolean, Column, Date, DateTime, Float, ForeignKey, Integer,
    SmallInteger, String, Text, UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship

from src.modules.shared import Base, Document, utcnow_naive


class IrisAnalysis(Base):
    """Email header analysis request and its final result.

    Each row represents one analysis: the raw headers submitted by the
    user, the lifecycle status, and (once finished) the aggregated score
    and textual verdict.

    Attributes:
        id: Primary key, auto-incrementing integer.
        title: Optional user-defined label for quick identification.
        raw_headers: Original email headers as plain text.
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
    raw_headers = Column(Text, nullable=False)
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

    __table_args__ = (
        UniqueConstraint("connection_id", "source_message_uid",
                          name="uq_iris_analysis_connection_source_message"),
    )


class IrisMailboxConnection(Base):
    """An external mailbox (Gmail / Microsoft 365) connected by a user for
    automatic Iris ingestion.

    Stores the minimum needed to re-request access later — never the
    mailbox content itself. See ``plans/feature/iris/iris-mailbox-connector.md``
    Fase 2/3 for the full design rationale (why this can't live in Acheron,
    why the refresh token is encrypted with ``shared._crypto`` instead).

    Attributes:
        id: Primary key, auto-incrementing integer.
        user_id: Foreign key to the owning User.
        provider: "gmail" | "microsoft".
        account_email: The connected mailbox's address (plaintext — not a
                 secret, needed to show "which account is this").
        scopes: Space-separated OAuth scopes actually granted.
        refresh_token_enc: Refresh token, encrypted at rest
                 (``shared._crypto.encrypt_at_rest(..., purpose="iris_mailbox")``).
                 Never returned by any endpoint.
        access_token_enc: Cached access token, encrypted at rest; NULL when
                 not cached or expired. Optional — the connector can always
                 fall back to ``refresh()``.
        access_token_expires_at: Expiry of the cached access token.
        folder: Provider-specific folder/label to watch; NULL = default
                 inbox.
        full_message_mode: If True, fetch the complete raw message
                 (attachments/body included) instead of headers only. Off
                 by default — the user must opt in explicitly per
                 connection (see Fase 5 frontend design: this is a
                 deliberate, not a hidden, choice).
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
        created_at: When the connection was established.
        user: SQLAlchemy relationship to User.
        analyses: Analyses ingested through this connection.
        inbox_entries: Cola de checkpoint de mensajes descubiertos y aún no
                 resueltos (ver ``IrisMailboxInbox`` / B01).
    """
    __tablename__ = "IrisMailboxConnection"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("User.id"), nullable=False)
    provider = Column(String(20), nullable=False)
    account_email = Column(String(320), nullable=False)
    scopes = Column(String(512), nullable=False)

    refresh_token_enc = Column(Text, nullable=False)
    access_token_enc = Column(Text, nullable=True)
    access_token_expires_at = Column(DateTime, nullable=True)

    folder = Column(String(255), nullable=True)
    full_message_mode = Column(Boolean, nullable=False, default=False)
    sync_cursor = Column(Text, nullable=True)

    status = Column(String(20), nullable=False, default="active")
    ingested_today = Column(Integer, nullable=False, default=0)
    ingested_reset_date = Column(Date, nullable=True)
    last_sync_at = Column(DateTime, nullable=True)
    last_error = Column(Text, nullable=True)
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
    una vez el cursor avanza (B01). Cada mensaje que devuelve ``list_new``
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
