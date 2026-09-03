from marshmallow import Schema, fields, validate, validates_schema, ValidationError

from src.modules.shared import UTCDateTime
from .model import ScanType


class ScanIdQuerySchema(Schema):
    id = fields.Integer(required=True)


class NmapScanRequestSchema(Schema):
    target = fields.String(required=True)
    ports = fields.String(required=True)
    timeout = fields.Integer(load_default=300, validate=validate.Range(min=1))


class NiktoScanRequestSchema(Schema):
    target = fields.String(required=True)
    timeout = fields.Integer(load_default=900, validate=validate.Range(min=1))


class NucleiScanRequestSchema(Schema):
    target = fields.String(required=True)
    # Perfil acotado por defecto (roadmap Fase U1, punto 1): sin esto, Nuclei
    # con el feed completo contra un solo host son miles de peticiones. "info"
    # queda fuera del default a propósito — son miles de plantillas de
    # tech-detect y, al ser confirmed=True sin CVSS, el suelo de
    # score_finding las subiría todas a MEDIUM.
    severities = fields.List(
        fields.String(validate=validate.OneOf(["info", "low", "medium", "high", "critical"])),
        load_default=None,
    )
    tags = fields.List(fields.String(), load_default=None)
    rateLimit = fields.Integer(load_default=None, validate=validate.Range(min=1, max=1000))
    requestTimeout = fields.Integer(load_default=None, validate=validate.Range(min=1, max=120))
    timeout = fields.Integer(load_default=None, validate=validate.Range(min=1))


class LybraScanRequestSchema(Schema):
    # Un solo modo por HTTP: Lybra descubre los puertos del objetivo con su
    # propio transporte (Fase T). El modo de payload externo existe en el
    # manager, pero no se expone aquí — llega en proceso desde Hygeia.
    #
    # Hasta L52 había un segundo modo, ``sourceScanId``: analizar los servicios
    # que un escaneo Nmap previo ya había descubierto. Retirado con el resto
    # del acoplamiento con escáneres de terceros, junto al flag ``deep`` que
    # lanzaba Nmap/Nikto/Nuclei como corroboradores.
    target = fields.String(required=True)
    ports = fields.String()
    timeout = fields.Integer(load_default=120, validate=validate.Range(min=1))
    # La doble puerta del modo agresivo (L40): esta petición explícita del
    # usuario es sólo la mitad. El manager sólo la honra cuando el objetivo
    # está además en el registro de autorización — un registro no autoriza
    # cualquier cosa contra el objetivo, sólo el escaneo pasivo.
    aggressive = fields.Boolean(load_default=False)


class UnresolvedProductsQuerySchema(Schema):
    limit = fields.Integer(load_default=50, validate=validate.Range(min=1, max=500))
    # El origen separa dos frentes de trabajo distintos: los banners de red
    # aportan muestras desde el primer escaneo, mientras que el inventario
    # necesita agentes desplegados.
    origin = fields.String(load_default=None, allow_none=True,
                           validate=validate.OneOf(["network", "inventory"]))


class FindingStateRequestSchema(Schema):
    # ``accepted`` y ``false_positive`` dicen cosas opuestas y hasta L35
    # compartían casilla: aceptar un riesgo es "esto es real, lo asumo";
    # desmentirlo es "esto no es real, el motor se equivocó". Un informe que
    # cuenta los segundos como riesgos aceptados miente sobre la postura de
    # seguridad. ``fixed`` y ``regressed`` no están porque los pone el ciclo de
    # vida al comparar escaneos: dejarlos escribir aquí permitiría falsear el
    # historial.
    state = fields.String(
        required=True,
        validate=validate.OneOf(["accepted", "false_positive", "open"]),
    )
    reason = fields.String(load_default=None, allow_none=True,
                           validate=validate.Length(max=500))


class FindingStateResponseSchema(Schema):
    message = fields.String()
    findingId = fields.Integer()
    state = fields.String()
    user = fields.String()


class AddAuthorizedTargetSchema(Schema):
    target = fields.String(required=True, validate=validate.Length(min=1, max=64))
    label = fields.String(load_default=None, allow_none=True, validate=validate.Length(max=255))


class AuthorizedTargetSchema(Schema):
    id = fields.Integer()
    target = fields.String()
    label = fields.String(allow_none=True)
    createdAt = UTCDateTime()


class AuthorizedTargetListResponseSchema(Schema):
    message = fields.String()
    targets = fields.List(fields.Nested(AuthorizedTargetSchema))
    user = fields.String()


class AuthorizedTargetActionResponseSchema(Schema):
    message = fields.String()
    targetId = fields.Integer()
    target = fields.String()
    user = fields.String()


class ResultsQuerySchema(Schema):
    type = fields.String(load_default="all", validate=validate.OneOf([scan_type.value for scan_type in ScanType] + ["all"]))
    page = fields.Integer(load_default=1, validate=validate.Range(min=1))
    per_page = fields.Integer(load_default=10, validate=validate.Range(min=1, max=100))
    # Fase I, solo con type=lybra: acota la lista a los escaneos originados por
    # el inventario de un activo de Hygeia. Omitirlo devuelve los escaneos
    # lanzados desde el panel de Themis (los de agente se ven por agente, no
    # mezclados en la feed general).
    assetId = fields.Integer(load_default=None, allow_none=True)


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
    # Derived from ScanType, not hand-listed: a new scan type is filterable
    # here automatically, no schema edit needed.
    scan_type = fields.String(load_default="all", validate=validate.OneOf([scan_type.value for scan_type in ScanType] + ["all"]))


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
    createdAt = UTCDateTime(allow_none=True)
    generatedAt = UTCDateTime(allow_none=True)
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
    nextRunAt = UTCDateTime(allow_none=True)
    user = fields.String()


class ScheduledScanListItemSchema(Schema):
    id = fields.Integer()
    scanType = fields.String()
    arguments = fields.Dict()
    scheduleType = fields.String()
    scheduleConfig = fields.Dict()
    isActive = fields.Boolean()
    lastRunAt = UTCDateTime(allow_none=True)
    nextRunAt = UTCDateTime(allow_none=True)
    createdAt = UTCDateTime(allow_none=True)


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
    createdAt = UTCDateTime(allow_none=True)
    updatedAt = UTCDateTime(allow_none=True)
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
    lastScannedAt = UTCDateTime(allow_none=True)


class HistoryHostsResponseSchema(Schema):
    message = fields.String()
    hosts = fields.List(fields.Nested(HistoryHostItemSchema))
    user = fields.String()


class HistoryStatsQuerySchema(Schema):
    target = fields.String(required=True)
    type = fields.String(required=True, validate=validate.OneOf([scan_type.value for scan_type in ScanType]))


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
