"""
Marshmallow schemas for Iris REST API request/response validation.
Fields use camelCase for JSON keys as per the project convention.
"""

from __future__ import annotations

from marshmallow import Schema, ValidationError, fields, validate, validates_schema


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


class AnalysisIdQuerySchema(Schema):
    """Query parameter for ``GET /iris/status`` — supplied as ``?id=...``."""
    id = fields.Integer(required=True)


class ResultsQuerySchema(Schema):
    """Query parameters for the paginated results list."""
    page = fields.Integer(load_default=1, validate=validate.Range(min=1))
    per_page = fields.Integer(load_default=10, validate=validate.Range(min=1, max=100))


class AnalyzeResponseSchema(Schema):
    """Response returned immediately after submitting headers."""
    message = fields.String()
    analysisId = fields.Integer()
    status = fields.String()


class AnalysisStatusResponseSchema(Schema):
    """Current lifecycle status and optional progress of an analysis."""
    analysisId = fields.Integer()
    status = fields.String()
    progress = fields.Integer(load_default=None)
    totalScore = fields.Float(load_default=None)
    verdict = fields.String(load_default=None)


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


class AnalysisDetailResponseSchema(Schema):
    """Full analysis report: headers, per-rule results, verdict."""
    analysisId = fields.Integer()
    title = fields.String(load_default=None)
    status = fields.String()
    rawHeaders = fields.String()
    totalScore = fields.Float(load_default=None)
    verdict = fields.String(load_default=None)
    gateReasons = fields.List(fields.String(), load_default=None)
    topSignals = fields.List(fields.Nested(TopSignalSchema), load_default=None)
    startedAt = fields.String(load_default=None)
    finishedAt = fields.String(load_default=None)
    user = fields.String()
    rules = fields.List(fields.Nested(RuleResultSchema))
    recommendations = fields.List(fields.String())


class AnalysisListItemSchema(Schema):
    """Summary of a single analysis shown in a paginated list."""
    analysisId = fields.Integer()
    title = fields.String(load_default=None)
    status = fields.String()
    totalScore = fields.Float(load_default=None)
    verdict = fields.String(load_default=None)
    startedAt = fields.String(load_default=None)
    finishedAt = fields.String(load_default=None)


class AnalysisListResponseSchema(Schema):
    """Paginated list of analyses for the current user."""
    analyses = fields.List(fields.Nested(AnalysisListItemSchema))
    total = fields.Integer()
    page = fields.Integer()
    perPage = fields.Integer()


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


class GenerateDocumentResponseSchema(Schema):
    """Response returned immediately after queuing PDF generation."""
    message = fields.String()
    documentId = fields.Integer()
    analysisId = fields.Integer()
    status = fields.String()
    downloadUrl = fields.String(load_default=None)


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
    createdAt = fields.DateTime(format="iso", allow_none=True)
    generatedAt = fields.DateTime(format="iso", allow_none=True)
    downloadUrl = fields.String(allow_none=True)


class IrisDocumentItemSchema(Schema):
    """Summary of a single IrisDocument shown in a listing."""
    documentId = fields.Integer()
    analysisId = fields.Integer()
    status = fields.String()
    verdict = fields.String(allow_none=True)
    createdAt = fields.DateTime(format="iso", allow_none=True)
    generatedAt = fields.DateTime(format="iso", allow_none=True)
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
