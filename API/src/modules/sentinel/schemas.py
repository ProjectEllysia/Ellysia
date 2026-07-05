from marshmallow import Schema, fields, validate, validates_schema, ValidationError


class ScanIdQuerySchema(Schema):
    id = fields.Integer(required=True)


class NmapScanRequestSchema(Schema):
    target = fields.String(required=True)
    ports = fields.String(required=True)
    timeout = fields.Integer(load_default=300, validate=validate.Range(min=1))


class NiktoScanRequestSchema(Schema):
    target = fields.String(required=True)
    timeout = fields.Integer(load_default=900, validate=validate.Range(min=1))


class OpenVASScanRequestSchema(Schema):
    target = fields.String(required=True)
    scanConfig = fields.String(load_default="full_fast", validate=validate.OneOf(["full_fast", "full_deep", "full_ultimate"]))


class EllysiaScanRequestSchema(Schema):
    # Two modes: analyse a prior Nmap scan (sourceScanId) OR self-discover a
    # target's ports (target [+ optional ports]). Exactly one must be provided.
    sourceScanId = fields.Integer()
    target = fields.String()
    ports = fields.String()
    timeout = fields.Integer(load_default=120, validate=validate.Range(min=1))

    @validates_schema
    def _require_one_mode(self, data, **kwargs):
        if not data.get("sourceScanId") and not data.get("target"):
            raise ValidationError("sourceScanId or target is required")


class FindingStateRequestSchema(Schema):
    state = fields.String(required=True, validate=validate.OneOf(["accepted", "open"]))


class FindingStateResponseSchema(Schema):
    message = fields.String()
    findingId = fields.Integer()
    state = fields.String()
    user = fields.String()


class ResultsQuerySchema(Schema):
    type = fields.String(load_default="all", validate=validate.OneOf(["nmap", "nikto", "openvas", "ellysia", "all"]))
    page = fields.Integer(load_default=1, validate=validate.Range(min=1))
    per_page = fields.Integer(load_default=10, validate=validate.Range(min=1, max=100))


class GeneratePdfRequestSchema(Schema):
    id = fields.Integer(required=True)
    aiReport = fields.Boolean(load_default=False)


class DocumentStatusQuerySchema(Schema):
    document_id = fields.Integer()
    scan_id = fields.Integer()

    @validates_schema
    def validate_at_least_one(self, data, **kwargs):
        if not data.get("document_id") and not data.get("scan_id"):
            raise ValidationError("document_id or scan_id is required")


class DocumentsQuerySchema(Schema):
    scan_type = fields.String(load_default="all", validate=validate.OneOf(["nmap", "nikto", "openvas", "all"]))


class ScheduledScanRequestSchema(Schema):
    scan_type = fields.String(required=True)
    arguments = fields.Dict(required=True)
    schedule_type = fields.String(required=True)
    schedule_config = fields.Dict(required=True)


class ScanResponseSchema(Schema):
    message = fields.String()
    scanId = fields.Integer()
    scanType = fields.String()
    user = fields.String()


class NmapScanResponseSchema(Schema):
    message = fields.String()
    scanIds = fields.List(fields.Integer())
    target = fields.Dict()
    totalScans = fields.Integer()
    user = fields.String()


class ScanStatusResponseSchema(Schema):
    message = fields.String()
    scanId = fields.Integer()
    status = fields.String()
    scanType = fields.String()
    progress = fields.Float(required=False)
    scan = fields.Dict(required=False)


class IsFinishedResponseSchema(Schema):
    message = fields.String()
    scanId = fields.Integer()
    isFinished = fields.Boolean()
    scanType = fields.String()


class ResultsResponseSchema(Schema):
    message = fields.String()
    filter = fields.String()
    count = fields.Integer()
    results = fields.List(fields.Dict())
    page = fields.Integer(required=False)
    perPage = fields.Integer(required=False)
    totalCount = fields.Integer(required=False)
    totalPages = fields.Integer(required=False)
    user = fields.String()


class ScanDetailResponseSchema(Schema):
    message = fields.String()
    result = fields.Dict()
    user = fields.String()


class DocumentStatusResponseSchema(Schema):
    documentId = fields.Integer()
    scanId = fields.Integer()
    status = fields.String()
    aiReport = fields.Boolean()
    createdAt = fields.DateTime(format="iso", allow_none=True)
    generatedAt = fields.DateTime(format="iso", allow_none=True)
    downloadUrl = fields.String(allow_none=True)


class DocumentListResponseSchema(Schema):
    documents = fields.List(fields.Dict())
    total = fields.Integer()
    filter = fields.String(required=False)


class ScanDocumentsResponseSchema(Schema):
    scanId = fields.Integer()
    documents = fields.List(fields.Dict())
    total = fields.Integer()


class DocumentDeleteResponseSchema(Schema):
    message = fields.String()
    documentId = fields.Integer()


class PdfGenerateResponseSchema(Schema):
    message = fields.String()
    documentId = fields.Integer()
    scanId = fields.Integer()
    status = fields.String()
    aiReport = fields.Boolean()
    downloadUrl = fields.String()


class ScheduledScanResponseSchema(Schema):
    message = fields.String()
    programedScanId = fields.Integer()
    scanType = fields.String()
    scheduleType = fields.String()
    scheduleConfig = fields.Dict()
    nextRunAt = fields.DateTime(format="iso", allow_none=True)
    user = fields.String()


class ScheduledScanListItemSchema(Schema):
    id = fields.Integer()
    scanType = fields.String()
    arguments = fields.Dict()
    scheduleType = fields.String()
    scheduleConfig = fields.Dict()
    isActive = fields.Boolean()
    lastRunAt = fields.DateTime(format="iso", allow_none=True)
    nextRunAt = fields.DateTime(format="iso", allow_none=True)
    createdAt = fields.DateTime(format="iso", allow_none=True)


class ScheduledScanListResponseSchema(Schema):
    message = fields.String()
    count = fields.Integer()
    scheduledScans = fields.List(fields.Dict())
    user = fields.String()


class ScheduledScanActionResponseSchema(Schema):
    message = fields.String()
    programedScanId = fields.Integer()
    scanType = fields.String()
    user = fields.String()


# =========================================================================
# FOLDER SCHEMAS
# =========================================================================

class CreateFolderSchema(Schema):
    name = fields.String(required=True, validate=validate.Length(min=1, max=255))


class RenameFolderSchema(Schema):
    name = fields.String(required=True, validate=validate.Length(min=1, max=255))


class MoveScanToFolderSchema(Schema):
    scanId = fields.Integer(required=True)


class AddScansToFolderSchema(Schema):
    scanIds = fields.List(fields.Integer(), required=True, validate=validate.Length(min=1))


class FolderSchema(Schema):
    id = fields.Integer(allow_none=True)
    name = fields.String()
    createdAt = fields.DateTime(format="iso", allow_none=True)
    updatedAt = fields.DateTime(format="iso", allow_none=True)
    scanCount = fields.Integer()
    scans = fields.List(fields.Dict())


class FolderListResponseSchema(Schema):
    message = fields.String()
    folders = fields.List(fields.Nested(FolderSchema))
    unfoldered = fields.Nested(FolderSchema)
    user = fields.String()


class FolderActionResponseSchema(Schema):
    message = fields.String()
    folderId = fields.Integer()
    name = fields.String()
    user = fields.String()


class ScanFolderActionResponseSchema(Schema):
    message = fields.String()
    scanId = fields.Integer(allow_none=True)
    folderId = fields.Integer(allow_none=True)
    user = fields.String()


class BulkDeleteScansSchema(Schema):
    scanIds = fields.List(fields.Integer(), required=True, validate=validate.Length(min=1, max=100))


class BulkDeleteResultSchema(Schema):
    scanId = fields.Integer()
    status = fields.String()
    error = fields.String(allow_none=True)


class BulkDeleteScansResponseSchema(Schema):
    message = fields.String()
    deletedCount = fields.Integer()
    failedCount = fields.Integer()
    results = fields.List(fields.Nested(BulkDeleteResultSchema))
    user = fields.String()


# =========================================================================
# HISTORY / STATISTICS SCHEMAS
# =========================================================================

class HistoryHostItemSchema(Schema):
    target = fields.String()
    scanType = fields.String()
    scanCount = fields.Integer()
    lastScannedAt = fields.DateTime(format="iso", allow_none=True)


class HistoryHostsResponseSchema(Schema):
    message = fields.String()
    hosts = fields.List(fields.Nested(HistoryHostItemSchema))
    user = fields.String()


class HistoryStatsQuerySchema(Schema):
    target = fields.String(required=True)
    type = fields.String(required=True, validate=validate.OneOf(["nmap", "nikto", "openvas"]))


class HistoryStatsResponseSchema(Schema):
    message = fields.String()
    scanType = fields.String()
    target = fields.String()
    metricLabel = fields.String()
    axes = fields.Dict()
    series = fields.List(fields.Dict())
    diff = fields.Dict()
    legend = fields.List(fields.Dict())
    scanCount = fields.Integer()
    user = fields.String()


# =========================================================================
# TRACEROUTE SCHEMAS
# =========================================================================

class TracerouteResponseSchema(Schema):
    message = fields.String()
    target = fields.String()
    hops = fields.List(fields.Dict())
    hopCount = fields.Integer()
    computedAt = fields.String(allow_none=True)
    cached = fields.Boolean()
    status = fields.String()  # "pending" | "done" | "failed"
    user = fields.String()
