"""
Marshmallow schemas for Iris REST API request/response validation.
Fields use camelCase for JSON keys as per the project convention.
"""

from __future__ import annotations

from marshmallow import Schema, ValidationError, fields, validate, validates_schema

import src.modules.system.config_reading as CR
from src.modules.shared import UTCDateTime


class AnalyzeRequestSchema(Schema):
    """Request body for ``POST /iris/analyze``.

    Accepts either ``headers`` (a headers-only block, original behaviour)
    or ``message`` (a full raw ``.eml`` message — Fase 2). At least one of
    the two is required; if both are present, ``message`` takes priority
    since it is a superset of the header information.
    """
    title = fields.String(load_default=None, validate=validate.Length(max=120))
    headers = fields.String(load_default=None, validate=validate.Length(min=10))
    message = fields.String(load_default=None, validate=validate.Length(min=10))

    @validates_schema
    def validate_has_input(self, data, **kwargs):
        if not data.get("headers") and not data.get("message"):
            raise ValidationError(
                "Debe proporcionar 'headers' (cabeceras) o 'message' (mensaje completo .eml).",
                field_name="headers",
            )

    @validates_schema
    def validate_max_size(self, data, **kwargs):
        """C4: sin tope superior, un .eml de decenas de MB (adjuntos incluidos)
        entraba entero a una columna Text y se re-parseaba completo (incluida
        la decodificación base64) en cada lectura posterior. Leído con CR en
        cada validación, no horneado al importar el módulo, para que un
        cambio vía PUT /system surta efecto sin reiniciar la API (mismo
        patrón que ``hygeia/schemas.py::validate_array_limits``).
        """
        max_bytes = CR.iris_config().max_message_bytes
        for field_name in ("headers", "message"):
            value = data.get(field_name)
            if value and len(value.encode("utf-8", errors="ignore")) > max_bytes:
                raise ValidationError(
                    f"'{field_name}' excede el tamaño máximo permitido ({max_bytes} bytes).",
                    field_name=field_name,
                )


class AnalysisIdQuerySchema(Schema):
    """Query parameter for ``GET /iris/status`` — supplied as ``?id=...``."""
    id = fields.Integer(required=True)


class ResultsQuerySchema(Schema):
    """Query parameters for the paginated results list.

    ``search``/``verdict``/``status``/``source`` are optional filters (all
    default to "no filter" so existing callers are unaffected); ``sort_by``/
    ``sort_dir`` control server-side ordering — previously the endpoint only
    ever returned ``created_at DESC``, so any client-side "sort by score"
    only reordered whatever page happened to be loaded.
    """
    page = fields.Integer(load_default=1, validate=validate.Range(min=1))
    per_page = fields.Integer(load_default=10, validate=validate.Range(min=1, max=100))
    search = fields.String(load_default=None, validate=validate.Length(max=120))
    verdict = fields.String(load_default=None,
                             validate=validate.OneOf(["Legitimate", "Suspicious", "Phishing"]))
    status = fields.String(load_default=None,
                            validate=validate.OneOf(["pending", "running", "finished", "failed", "cancelled"]))
    source = fields.String(load_default=None, validate=validate.OneOf(["manual", "mailbox"]))
    sort_by = fields.String(load_default="date",
                             validate=validate.OneOf(["date", "score", "verdict", "title", "status"]))
    sort_dir = fields.String(load_default="desc", validate=validate.OneOf(["asc", "desc"]))


class AnalyzeResponseSchema(Schema):
    """Response returned immediately after submitting headers."""
    message = fields.String()
    analysisId = fields.Integer()
    status = fields.String()


class AnalysisStatusResponseSchema(Schema):
    """Current lifecycle status and optional progress of an analysis.

    ``failureCode``/``failureReason`` solo viajan cuando ``status`` es
    ``failed``. Es aquí donde se consultan, y no en el informe completo,
    porque ``GET /iris/results/<id>`` exige un análisis ``finished``: un
    análisis que murió no tiene informe que devolver, solo un motivo.
    """
    analysisId = fields.Integer()
    status = fields.String()
    progress = fields.Integer(load_default=None)
    totalScore = fields.Float(load_default=None)
    verdict = fields.String(load_default=None)
    failureCode = fields.String(load_default=None, allow_none=True)
    failureReason = fields.String(load_default=None, allow_none=True)


class RuleResultSchema(Schema):
    """Outcome of a single rule within a finished analysis."""
    ruleName = fields.String()
    category = fields.String(load_default=None)
    score = fields.Float()
    verdict = fields.String()
    details = fields.Dict(load_default=None)
    recommendation = fields.String(load_default=None)


class TopSignalSchema(Schema):
    """One of the highest-penalty rules for a finished analysis (S2)."""
    ruleName = fields.String()
    category = fields.String(load_default=None)
    score = fields.Float()
    index = fields.Integer()


class AiSummarySchema(Schema):
    """AI-generated executive narrative for a finished analysis (IA1)."""
    executive_summary = fields.String()
    attacker_intent = fields.String()
    recommendations = fields.List(fields.String())
    confidence = fields.String()


class FailedRuleSchema(Schema):
    """Regla que no se pudo **ejecutar** durante un análisis (B05).

    No confundir con una regla que detectó algo: esas van en ``rules`` con su
    puntuación negativa. Estas son las que lanzaron una excepción, así que su
    parte del mensaje se quedó sin inspeccionar.
    """
    name = fields.String()
    family = fields.String(load_default=None, allow_none=True)
    category = fields.String(load_default=None, allow_none=True)


class AnalysisDetailResponseSchema(Schema):
    """Full analysis report: headers, per-rule results, verdict."""
    analysisId = fields.Integer()
    title = fields.String(load_default=None)
    status = fields.String()
    rawHeaders = fields.String()
    totalScore = fields.Float(load_default=None)
    verdict = fields.String(load_default=None)
    gateReasons = fields.List(fields.String(), load_default=None)
    analysisQuality = fields.String(load_default=None, allow_none=True)
    failedRules = fields.List(fields.Nested(FailedRuleSchema), load_default=None)
    detectorVersion = fields.String(load_default=None, allow_none=True)
    topSignals = fields.List(fields.Nested(TopSignalSchema), load_default=None)
    aiSummary = fields.Nested(AiSummarySchema, load_default=None, allow_none=True)
    unwrappedFromForward = fields.Boolean(load_default=False)
    wrapperFrom = fields.String(load_default=None, allow_none=True)
    wrapperSubject = fields.String(load_default=None, allow_none=True)
    startedAt = fields.String(load_default=None)
    finishedAt = fields.String(load_default=None)
    failureCode = fields.String(load_default=None, allow_none=True)
    failureReason = fields.String(load_default=None, allow_none=True)
    user = fields.String()
    rules = fields.List(fields.Nested(RuleResultSchema))
    recommendations = fields.List(fields.String())


class AnalysisListItemSchema(Schema):
    """Summary of a single analysis shown in a paginated list."""
    analysisId = fields.Integer()
    title = fields.String(load_default=None)
    status = fields.String()
    failureCode = fields.String(load_default=None, allow_none=True)
    analysisQuality = fields.String(load_default=None, allow_none=True)
    totalScore = fields.Float(load_default=None)
    verdict = fields.String(load_default=None)
    startedAt = fields.String(load_default=None)
    finishedAt = fields.String(load_default=None)
    connectionId = fields.Integer(load_default=None)
    provider = fields.String(load_default=None)
    accountEmail = fields.String(load_default=None)


class VerdictThresholdsSchema(Schema):
    """Score thresholds used to classify a verdict — sent alongside the list
    so the frontend can render them (e.g. a score rail) without hardcoding
    ``iris.legitimate_threshold``/``iris.suspicious_threshold``.
    """
    legitimate = fields.Float()
    suspicious = fields.Float()


class AnalysisListResponseSchema(Schema):
    """Paginated list of analyses for the current user."""
    analyses = fields.List(fields.Nested(AnalysisListItemSchema))
    total = fields.Integer()
    page = fields.Integer()
    perPage = fields.Integer()
    thresholds = fields.Nested(VerdictThresholdsSchema)


class AnalysisDeleteResponseSchema(Schema):
    """Confirmation after deleting an analysis."""
    message = fields.String()
    analysisId = fields.Integer()


class AnalysisCancelResponseSchema(Schema):
    """Confirmation after cancelling a running analysis."""
    message = fields.String()
    analysisId = fields.Integer()
    status = fields.String()


class ReceivedHopSchema(Schema):
    """Single hop inside a Received-chain path.

    Ordered oldest -> newest when returned by the API.
    """
    hop = fields.Integer()
    index = fields.Integer()
    fromAddress = fields.String(attribute="from", allow_none=True)
    fromIp = fields.String(allow_none=True)
    by = fields.String(allow_none=True)
    withProtocol = fields.String(attribute="with", allow_none=True)
    protocol = fields.String(allow_none=True)
    id = fields.String(allow_none=True)
    forAddress = fields.String(attribute="for", allow_none=True)
    tls = fields.Boolean()
    timestamp = fields.String(allow_none=True)
    flags = fields.List(fields.String())
    raw = fields.String()


class ReceivedTransitionSchema(Schema):
    """Edge between two consecutive hops (oldest -> newest direction)."""
    from_ = fields.Integer(attribute="from")
    to = fields.Integer()
    delayMs = fields.Integer(allow_none=True)
    suspicious = fields.Boolean()
    reasons = fields.List(fields.String())


class ReceivedPathResponseSchema(Schema):
    """Response for ``GET /iris/results/<id>/path``.

    ``hops`` and ``transitions`` are empty when no Received chain is
    available (e.g. headers-only submissions).
    """
    analysisId = fields.Integer()
    available = fields.Boolean()
    hopsCount = fields.Integer()
    hops = fields.List(fields.Nested(ReceivedHopSchema))
    transitions = fields.List(fields.Nested(ReceivedTransitionSchema))
    reason = fields.String(load_default=None)


class AnalysisIocsResponseSchema(Schema):
    """Response for ``GET /iris/results/<id>/iocs`` (O1).

    Each field is a sorted, deduplicated list of pivotable indicators
    derived from the analyzed message — empty lists (not null) when a
    category yields nothing (e.g. no body links in a headers-only
    submission).
    """
    analysisId = fields.Integer()
    domains = fields.List(fields.String())
    urls = fields.List(fields.String())
    ips = fields.List(fields.String())
    emails = fields.List(fields.String())
    hashes = fields.List(fields.String())


class GenerateDocumentResponseSchema(Schema):
    """Response returned immediately after queuing PDF generation."""
    message = fields.String()
    documentId = fields.Integer()
    analysisId = fields.Integer()
    status = fields.String()
    downloadUrl = fields.String(load_default=None)


class GenerateAiSummaryResponseSchema(Schema):
    """Response returned immediately after queuing AI summary generation (IA1).

    There is no separate status to poll: the caller re-fetches
    ``GET /iris/results/<id>`` (``aiSummary``) to see the result once the
    background task finishes.
    """
    message = fields.String()
    analysisId = fields.Integer()
    status = fields.String()


class DocumentStatusQuerySchema(Schema):
    """Query parameters for ``GET /iris/document-status``.

    Accepts either ``documentId`` (specific document) or ``analysisId``
    (latest document for that analysis) — at least one is required.
    """
    documentId = fields.Integer(load_default=None)
    analysisId = fields.Integer(load_default=None)

    @validates_schema
    def validate_has_id(self, data, **kwargs):
        if not data.get("documentId") and not data.get("analysisId"):
            raise ValidationError(
                "Debe proporcionar 'documentId' o 'analysisId'.",
                field_name="documentId",
            )


class IrisDocumentStatusResponseSchema(Schema):
    """Current generation status of a single IrisDocument."""
    documentId = fields.Integer()
    analysisId = fields.Integer()
    status = fields.String()
    verdict = fields.String(allow_none=True)
    createdAt = UTCDateTime(allow_none=True)
    generatedAt = UTCDateTime(allow_none=True)
    downloadUrl = fields.String(allow_none=True)


class IrisDocumentItemSchema(Schema):
    """Summary of a single IrisDocument shown in a listing."""
    documentId = fields.Integer()
    analysisId = fields.Integer()
    status = fields.String()
    verdict = fields.String(allow_none=True)
    createdAt = UTCDateTime(allow_none=True)
    generatedAt = UTCDateTime(allow_none=True)
    downloadUrl = fields.String(allow_none=True)


class IrisDocumentListResponseSchema(Schema):
    """All IrisDocuments belonging to the current user."""
    documents = fields.List(fields.Nested(IrisDocumentItemSchema))
    total = fields.Integer()


class AnalysisDocumentsResponseSchema(Schema):
    """All IrisDocuments generated for a specific analysis."""
    analysisId = fields.Integer()
    documents = fields.List(fields.Nested(IrisDocumentItemSchema))
    total = fields.Integer()


class IrisDocumentDeleteResponseSchema(Schema):
    """Confirmation after deleting an IrisDocument."""
    message = fields.String()
    documentId = fields.Integer()


# =============================================================================
# Mailbox connector (Fase 4) — Gmail / Microsoft Graph
# =============================================================================

class IrisMailboxProvidersResponseSchema(Schema):
    """Providers configured/supported for the mailbox connector."""
    providers = fields.List(fields.String())


class IrisMailboxConnectRequestSchema(Schema):
    """Request body for ``POST /iris/mailbox/connect``."""
    provider = fields.String(required=True)
    fullMessageMode = fields.Boolean(load_default=False)
    folder = fields.String(load_default=None, allow_none=True)


class IrisMailboxConnectResponseSchema(Schema):
    """Authorization URL to redirect the user to."""
    authorizeUrl = fields.String()


class IrisMailboxConnectionItemSchema(Schema):
    """A connected mailbox — never includes tokens, encrypted or otherwise."""
    connectionId = fields.Integer()
    provider = fields.String()
    accountEmail = fields.String()
    folder = fields.String(allow_none=True)
    fullMessageMode = fields.Boolean()
    status = fields.String()
    lastSyncAt = UTCDateTime(allow_none=True)
    lastError = fields.String(allow_none=True)
    createdAt = UTCDateTime(allow_none=True)


class IrisMailboxConnectionListResponseSchema(Schema):
    """All mailbox connections belonging to the current user."""
    connections = fields.List(fields.Nested(IrisMailboxConnectionItemSchema))
    total = fields.Integer()


class IrisMailboxUpdateConnectionRequestSchema(Schema):
    """Request body for ``PATCH /iris/mailbox/connections/<id>``."""
    folder = fields.String(load_default=None, allow_none=True)
    status = fields.String(load_default=None, allow_none=True,
                            validate=validate.OneOf(["active", "paused"]))


class IrisMailboxConnectionDeleteResponseSchema(Schema):
    """Confirmation after deleting a mailbox connection."""
    message = fields.String()
    connectionId = fields.Integer()


class IrisMailboxSyncResponseSchema(Schema):
    """Confirmation after queuing a manual sync."""
    message = fields.String()
    connectionId = fields.Integer()


class IrisMailboxCallbackQuerySchema(Schema):
    """Query params on the OAuth redirect back from Google/Microsoft.

    ``error`` is present instead of ``code`` when the user denies consent —
    both are optional here so the endpoint can distinguish and redirect
    accordingly rather than failing schema validation on a normal decline.
    """
    state = fields.String(required=True)
    code = fields.String(load_default=None)
    error = fields.String(load_default=None)
