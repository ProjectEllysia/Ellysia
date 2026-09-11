"""
Marshmallow schemas for Iris REST API request/response validation.
Fields use camelCase for JSON keys as per the project convention.
"""

from __future__ import annotations

from marshmallow import Schema, ValidationError, fields, validate, validates_schema

import src.modules.system.config_reading as CR
from src.modules.shared import UTCDateTime

from .services.feedback_metrics import FEEDBACK_LABELS


class AnalyzeRequestSchema(Schema):
    """Request body for ``POST /iris/analyze``.

    Accepts either ``headers`` (a headers-only block, original behaviour)
    or ``message`` (a full raw ``.eml`` message). At least one of
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
        """Sin tope superior, un .eml de decenas de MB (adjuntos incluidos)
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


class IrisCapabilitiesResponseSchema(Schema):
    """Límites y modos que la interfaz necesita para decidir igual que el API.

    Existe para que el frontend no tenga que replicar constantes del backend:
    una copia en el navegador deriva en cuanto alguien cambia la config del
    servidor, y el usuario se lleva el rechazo después de haber cargado el
    fichero entero en memoria.

    ``verdictThresholds`` viaja ya en la respuesta del listado; se repite aquí
    para que una vista que aún no ha listado nada pueda pintar la escala de
    riesgo sin pedir primero una página de resultados.
    """
    maxMessageBytes = fields.Integer()
    minHeaders = fields.Integer()
    analysisModes = fields.List(fields.String())
    verdictThresholds = fields.Nested(lambda: VerdictThresholdsSchema())


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


class EvidenceSchema(Schema):
    """Dónde está, dentro del mensaje, lo que una regla encontró.

    ``kind`` es ``header``, ``body``, ``mime_part``, ``attachment`` o ``url``;
    ``locator`` dice cómo encontrarlo (p. ej. ``{"header": "from",
    "occurrence": 0}`` o ``{"linkIndex": 2}``) y ``excerpt`` es el fragmento
    con URLs, dominios y direcciones ya desactivados (``hxxp``, ``[.]``,
    ``[@]``). Ver ``services/evidence.py``.
    """
    kind = fields.String()
    locator = fields.Dict()
    excerpt = fields.String()


class RuleResultSchema(Schema):
    """Outcome of a single rule within a finished analysis.

    Una regla que penaliza trae ``evidence`` o, si su hallazgo no se puede
    anclar a un fragmento del mensaje, ``evidenceUnavailableReason``.
    """
    ruleName = fields.String()
    category = fields.String(load_default=None)
    score = fields.Float()
    verdict = fields.String()
    details = fields.Dict(load_default=None)
    recommendation = fields.String(load_default=None)
    evidence = fields.List(fields.Nested(EvidenceSchema), load_default=None)
    evidenceUnavailableReason = fields.String(load_default=None, allow_none=True)


class TopSignalSchema(Schema):
    """One of the highest-penalty rules for a finished analysis."""
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
    """Regla que no se pudo **ejecutar** durante un análisis.

    No confundir con una regla que detectó algo: esas van en ``rules`` con su
    puntuación negativa. Estas son las que lanzaron una excepción, así que su
    parte del mensaje se quedó sin inspeccionar.
    """
    name = fields.String()
    family = fields.String(load_default=None, allow_none=True)
    category = fields.String(load_default=None, allow_none=True)


class IrisFeedbackRequestSchema(Schema):
    """Corrección del analista sobre el veredicto de un análisis terminado.

    ``label`` es ``malicious``, ``legitimate`` o ``unknown`` (revisado, pero
    no se puede decidir). No modifica el veredicto: se guarda aparte y
    alimenta las métricas.
    """
    label = fields.String(required=True, validate=validate.OneOf(FEEDBACK_LABELS))
    note = fields.String(load_default=None, allow_none=True, validate=validate.Length(max=2000))


class IrisFeedbackItemSchema(Schema):
    """Una corrección registrada: etiqueta, nota, autor y fecha."""
    feedbackId = fields.Integer()
    analysisId = fields.Integer()
    label = fields.String()
    note = fields.String(load_default=None, allow_none=True)
    author = fields.String()
    createdAt = fields.String()


class IrisFeedbackListResponseSchema(Schema):
    """Historial de correcciones de un análisis, de la más reciente a la más antigua."""
    analysisId = fields.Integer()
    feedback = fields.List(fields.Nested(IrisFeedbackItemSchema))


class IrisFeedbackOverallMetricsSchema(Schema):
    """Matriz de confusión y tasas globales del detector frente a las etiquetas.

    Un veredicto positivo es cualquiera que avisa (``Suspicious`` o
    ``Phishing``). Las tasas valen ``null`` cuando no hay datos.
    """
    truePositives = fields.Integer()
    falsePositives = fields.Integer()
    falseNegatives = fields.Integer()
    trueNegatives = fields.Integer()
    precision = fields.Float(allow_none=True)
    recall = fields.Float(allow_none=True)
    disagreementRate = fields.Float(allow_none=True)


class IrisFeedbackFamilyMetricsSchema(Schema):
    """Métricas de una familia de reglas: ¿disparar esta familia coincide con malicioso?"""
    family = fields.String()
    fired = fields.Integer()
    precision = fields.Float(allow_none=True)
    recall = fields.Float(allow_none=True)
    disagreementRate = fields.Float(allow_none=True)
    coverage = fields.Float(allow_none=True)


class IrisFeedbackMetricsResponseSchema(Schema):
    """Métricas del detector calculadas con las correcciones vigentes del usuario."""
    analysesTotal = fields.Integer()
    reviewed = fields.Integer()
    unknown = fields.Integer()
    feedbackCoverage = fields.Float(allow_none=True)
    overall = fields.Nested(IrisFeedbackOverallMetricsSchema)
    families = fields.List(fields.Nested(IrisFeedbackFamilyMetricsSchema))


class CoverageSchema(Schema):
    """Qué partes del mensaje se pudieron inspeccionar.

    ``mode`` es ``full_message`` (había cuerpo o adjuntos) o ``headers_only``;
    en este último, ``uncoveredRules`` lista las reglas de cuerpo, enlaces y
    adjuntos que no tuvieron nada que mirar.
    """
    mode = fields.String()
    uncoveredRules = fields.List(fields.String(), load_default=None)


class PreviewHeadersSchema(Schema):
    """Cabeceras de la vista previa del mensaje que produjo el veredicto.

    Salen del contexto ganador (ver ``winningContext``): en un reenvío cuyo
    envoltorio es más grave que el original, son las del envoltorio.
    """
    subject = fields.String(load_default=None, allow_none=True)
    from_ = fields.String(data_key="from", attribute="from", load_default=None, allow_none=True)
    to = fields.String(load_default=None, allow_none=True)
    replyTo = fields.String(load_default=None, allow_none=True)
    returnPath = fields.String(load_default=None, allow_none=True)
    date = fields.String(load_default=None, allow_none=True)


class SecondaryContextSchema(Schema):
    """El otro mensaje de un reenvío: el que **no** decidió el veredicto.

    Se conserva entero —veredicto, score y reglas— para que el analista pueda
    ver por qué perdió sin que se mezcle con la evidencia del ganador.
    """
    contextType = fields.String()
    verdict = fields.String(load_default=None, allow_none=True)
    totalScore = fields.Float(load_default=None, allow_none=True)
    analysisQuality = fields.String(load_default=None, allow_none=True)
    rules = fields.List(fields.Nested(RuleResultSchema), load_default=None)


class AnalysisDetailResponseSchema(Schema):
    """Full analysis report: headers, per-rule results, verdict.

    ``winningContext`` dice qué mensaje produjo el veredicto (``inner`` o
    ``wrapper``); ``rules``, ``topSignals``, ``previewHeaders`` y los IOCs
    describen siempre ese mensaje. ``secondaryContext`` trae el otro, solo
    en reenvíos.

    ``confidence`` es ordinal (``high``/``medium``/``low``), **no** una
    probabilidad; ``uncertaintyReasons`` explica por qué no es ``high`` y
    ``coverage`` dice si se inspeccionó el mensaje completo o solo cabeceras.
    """
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
    confidence = fields.String(load_default=None, allow_none=True)
    coverage = fields.Nested(CoverageSchema, load_default=None, allow_none=True)
    uncertaintyReasons = fields.List(fields.String(), load_default=None)
    topSignals = fields.List(fields.Nested(TopSignalSchema), load_default=None)
    aiSummary = fields.Nested(AiSummarySchema, load_default=None, allow_none=True)
    aiSummaryStatus = fields.String(load_default=None, allow_none=True)
    aiSummaryModel = fields.String(load_default=None, allow_none=True)
    aiSummaryPromptVersion = fields.String(load_default=None, allow_none=True)
    unwrappedFromForward = fields.Boolean(load_default=False)
    wrapperFrom = fields.String(load_default=None, allow_none=True)
    wrapperSubject = fields.String(load_default=None, allow_none=True)
    winningContext = fields.String(load_default=None, allow_none=True)
    winningReason = fields.String(load_default=None, allow_none=True)
    secondaryContext = fields.Nested(SecondaryContextSchema, load_default=None, allow_none=True)
    previewHeaders = fields.Nested(PreviewHeadersSchema, load_default=None, allow_none=True)
    startedAt = fields.String(load_default=None)
    finishedAt = fields.String(load_default=None)
    failureCode = fields.String(load_default=None, allow_none=True)
    failureReason = fields.String(load_default=None, allow_none=True)
    user = fields.String()
    rules = fields.List(fields.Nested(RuleResultSchema))
    recommendations = fields.List(fields.String())
    latestFeedback = fields.Nested(IrisFeedbackItemSchema, load_default=None, allow_none=True)


class AnalysisListItemSchema(Schema):
    """Summary of a single analysis shown in a paginated list."""
    analysisId = fields.Integer()
    title = fields.String(load_default=None)
    status = fields.String()
    failureCode = fields.String(load_default=None, allow_none=True)
    analysisQuality = fields.String(load_default=None, allow_none=True)
    confidence = fields.String(load_default=None, allow_none=True)
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
    available (e.g. headers-only submissions). ``contextType`` dice de qué
    mensaje del reenvío sale la cadena: el mismo que decidió el veredicto.
    """
    analysisId = fields.Integer()
    contextType = fields.String(load_default=None, allow_none=True)
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
    submission). ``contextType`` dice de qué mensaje del reenvío salen: el
    mismo que decidió el veredicto.
    """
    analysisId = fields.Integer()
    contextType = fields.String(load_default=None, allow_none=True)
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


class GenerateAiSummaryRequestSchema(Schema):
    """Parámetros de ``POST /iris/results/<id>/ai-summary``.

    ``regenerate`` distingue las dos intenciones que antes eran una sola
    petición indistinguible: repetirla porque el navegador reintentó o porque
    el usuario hizo doble clic (y entonces lo correcto es devolver el resumen
    que ya hay, sin cobrar), o pedir explícitamente otra redacción (y entonces
    sí se genera de nuevo, y se cobra).
    """
    regenerate = fields.Boolean(load_default=False)


class GenerateAiSummaryResponseSchema(Schema):
    """Response returned immediately after queuing AI summary generation (IA1).

    There is no separate status to poll: the caller re-fetches
    ``GET /iris/results/<id>`` (``aiSummary``) to see the result once the
    background task finishes.

    ``status`` dice qué pasó de verdad con esta llamada: ``running`` si encoló
    la generación (o si ya había una en curso) y ``done`` si el resumen ya
    existía y se devolvió sin trabajo ni cobro.
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


class IrisDocumentsQuerySchema(Schema):
    """Query parameters for ``GET /iris/documents``: antes devolvía
    todos los documentos del usuario de golpe, sin límite -- misma
    convención página/tamaño que ``ResultsQuerySchema`` para el listado de
    análisis."""
    page = fields.Integer(load_default=1, validate=validate.Range(min=1))
    per_page = fields.Integer(load_default=10, validate=validate.Range(min=1, max=100))


class IrisDocumentListResponseSchema(Schema):
    """Página de los IrisDocument del usuario actual."""
    documents = fields.List(fields.Nested(IrisDocumentItemSchema))
    total = fields.Integer()
    page = fields.Integer()
    perPage = fields.Integer()


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
# Mailbox connector — Gmail / Microsoft Graph
# =============================================================================

class IrisMailboxProvidersResponseSchema(Schema):
    """Providers configured/supported for the mailbox connector."""
    providers = fields.List(fields.String())


class IrisMailboxConnectRequestSchema(Schema):
    """Request body for ``POST /iris/mailbox/connect``."""
    provider = fields.String(required=True)
    fullMessageMode = fields.Boolean(load_default=False)
    # La validación real (existe, pertenece a esta cuenta/proveedor) es
    # de red y solo se puede hacer con un access_token en la mano -- ver
    # IrisMailboxManager._validate_folder(), llamada desde handle_callback().
    # Aquí solo se descarta lo evidentemente inválido antes de firmar el
    # state y mandar al usuario al proveedor.
    folder = fields.String(load_default=None, allow_none=True, validate=validate.Length(max=255))


class IrisMailboxConnectResponseSchema(Schema):
    """Authorization URL to redirect the user to."""
    authorizeUrl = fields.String()


class IrisMailboxConnectionItemSchema(Schema):
    """A connected mailbox — never includes tokens, encrypted or otherwise."""
    connectionId = fields.Integer()
    provider = fields.String()
    accountEmail = fields.String()
    folder = fields.String(allow_none=True)
    folderDisplayName = fields.String(allow_none=True)
    folderType = fields.String(allow_none=True)
    fullMessageMode = fields.Boolean()
    status = fields.String()
    lastSyncAt = UTCDateTime(allow_none=True)
    lastError = fields.String(allow_none=True)
    syncStartedAt = UTCDateTime(allow_none=True)
    createdAt = UTCDateTime(allow_none=True)


class IrisMailboxConnectionListResponseSchema(Schema):
    """All mailbox connections belonging to the current user."""
    connections = fields.List(fields.Nested(IrisMailboxConnectionItemSchema))
    total = fields.Integer()


class IrisMailboxUpdateConnectionRequestSchema(Schema):
    """Request body for ``PATCH /iris/mailbox/connections/<id>``."""
    folder = fields.String(load_default=None, allow_none=True, validate=validate.Length(max=255))
    status = fields.String(load_default=None, allow_none=True,
                            validate=validate.OneOf(["active", "paused"]))


class IrisMailboxFolderSchema(Schema):
    """Una carpeta/etiqueta real de la cuenta conectada."""
    providerId = fields.String()
    displayName = fields.String()
    folderType = fields.String()


class IrisMailboxFoldersResponseSchema(Schema):
    """Carpetas que expone la cuenta de una conexión -- los únicos valores
    válidos para ``folder`` en ``PATCH /iris/mailbox/connections/<id>``."""
    folders = fields.List(fields.Nested(IrisMailboxFolderSchema))


class IrisMailboxHealthResponseSchema(Schema):
    """Estado observable de una conexión de buzón, sin tener que leer los
    logs del servidor."""
    status = fields.String()
    lastSyncAt = UTCDateTime(allow_none=True)
    lastSuccessAt = UTCDateTime(allow_none=True)
    lastError = fields.String(allow_none=True)
    syncStartedAt = UTCDateTime(allow_none=True)
    lastSyncDurationMs = fields.Integer(allow_none=True)
    cursorEstablished = fields.Boolean()
    ingestedToday = fields.Integer()
    maxIngestedPerDay = fields.Integer()
    messagesDiscoveredTotal = fields.Integer()
    messagesAcceptedTotal = fields.Integer()
    messagesPending = fields.Integer()
    messagesRetrying = fields.Integer()
    messagesDead = fields.Integer()
    oldestPendingMessageAgeSeconds = fields.Integer(allow_none=True)


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


class IrisRetentionReportResponseSchema(Schema):
    """Política de retención vigente y estado real de los análisis del
    usuario frente a ella."""
    rawMessageRetentionDays = fields.Integer()
    analysisRetentionDays = fields.Integer(allow_none=True)
    totalAnalyses = fields.Integer()
    analysesWithRawRetained = fields.Integer()
    analysesWithRawPurged = fields.Integer()


class IrisNotificationPreferenceResponseSchema(Schema):
    """Preferencias de notificación del usuario actual."""
    digestEnabled = fields.Boolean()
    mutedUntil = UTCDateTime(allow_none=True)
    notifyReauthRequired = fields.Boolean()
    notifySyncStuck = fields.Boolean()
    digestLastSentAt = UTCDateTime(allow_none=True)


class IrisNotificationPreferenceUpdateRequestSchema(Schema):
    """Request body for ``PUT /iris/notification-preferences``.

    Los cuatro campos son opcionales e independientes -- omitir uno deja su
    valor actual intacto (actualización parcial, mismo patrón que
    ``IrisMailboxUpdateConnectionRequestSchema``); el endpoint distingue
    "no venía en el cuerpo" mirando si la clave está en los datos cargados.

    ``mutedForMinutes`` en vez de una fecha absoluta: el cliente sabe "cuánto
    tiempo" (silenciar 1 hora / 1 día / 1 semana), no una marca de tiempo en
    UTC, y resolverla en el servidor evita todo el terreno resbaladizo de
    aceptar una fecha con zona horaria ambigua desde fuera. ``0`` quita un
    silenciado activo (poner ``mutedUntil`` a ``None``); cualquier valor
    positivo lo fija a ``ahora + esos minutos``.
    """
    digestEnabled = fields.Boolean()
    mutedForMinutes = fields.Integer(validate=validate.Range(min=0))
    notifyReauthRequired = fields.Boolean()
    notifySyncStuck = fields.Boolean()
