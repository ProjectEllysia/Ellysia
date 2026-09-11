"""
Iris REST API endpoints for email header analysis.

Provides:
- POST /iris/analyze         — submit headers for analysis
- GET  /iris/capabilities     — server-side limits the UI must honour
- GET  /iris/status?id=...   — check analysis status/progress
- GET  /iris/results         — list all analyses for the current user
- GET  /iris/results/{id}    — full analysis report
- POST /iris/analyze/{id}/cancel — cancel a running analysis
- DELETE /iris/results/{id}  — delete an analysis
"""

from __future__ import annotations

import json
import logging
import os

from flask import redirect, request, send_file, Response
from flask_smorest import Blueprint as SmorestBlueprint

from src.modules.users import (
    require_oauth_token,
    require_attributes,
    require_role,
    AttributeType,
    Role,
    get_current_user,
)
from src.modules.shared import handle_exceptions, limiter
from src.modules.shared.schemas import ErrorSchema
from src.modules.shared._exceptions import DocumentError, DocumentNotReadyError

import src.modules.system.config_reading as CR

from .managers import (
    IrisFeedbackManager, IrisManager, IrisReportManager, IrisMailboxManager,
    IrisNotificationPreferenceManager, IrisReplayManager, IrisTriageManager, IrisTrustPolicyManager,
    IrisCaseManager, IrisBatchManager,
)
from .exceptions import (
    IrisAnalysisNotFoundError,
    IrisExecutionError,
    IrisInvalidInputError,
    IrisMailboxConnectionNotFoundError,
    IrisMailboxOAuthStateError,
    IrisBatchNotFoundError,
    IrisCaseNotFoundError,
    IrisSavedViewNotFoundError,
    IrisTrustedSenderNotFoundError,
)
from .schemas import (
    AnalysisIdQuerySchema,
    IrisCapabilitiesResponseSchema,
    AnalyzeRequestSchema,
    AnalyzeResponseSchema,
    AnalysisStatusResponseSchema,
    AnalysisDetailResponseSchema,
    AnalysisListResponseSchema,
    AnalysisDeleteResponseSchema,
    AnalysisCancelResponseSchema,
    ReceivedPathResponseSchema,
    AnalysisIocsResponseSchema,
    ResultsQuerySchema,
    GenerateDocumentResponseSchema,
    GenerateAiSummaryRequestSchema,
    GenerateAiSummaryResponseSchema,
    DocumentStatusQuerySchema,
    IrisDocumentStatusResponseSchema,
    IrisDocumentsQuerySchema,
    IrisDocumentListResponseSchema,
    AnalysisDocumentsResponseSchema,
    IrisDocumentDeleteResponseSchema,
    IrisMailboxProvidersResponseSchema,
    IrisMailboxConnectRequestSchema,
    IrisMailboxConnectResponseSchema,
    IrisMailboxConnectionItemSchema,
    IrisMailboxConnectionListResponseSchema,
    IrisMailboxUpdateConnectionRequestSchema,
    IrisMailboxConnectionDeleteResponseSchema,
    IrisMailboxSyncResponseSchema,
    IrisMailboxCallbackQuerySchema,
    IrisMailboxFoldersResponseSchema,
    IrisMailboxHealthResponseSchema,
    IrisNotificationPreferenceResponseSchema,
    IrisNotificationPreferenceUpdateRequestSchema,
    IrisRetentionReportResponseSchema,
    IrisFeedbackRequestSchema,
    IrisFeedbackItemSchema,
    IrisFeedbackListResponseSchema,
    IrisFeedbackMetricsResponseSchema,
    IrisReplayRequestSchema,
    IrisReplayResponseSchema,
    IrisTrustedSenderItemSchema,
    IrisTrustedSenderListResponseSchema,
    IrisTrustedSenderRequestSchema,
    IrisTrustedSendersQuerySchema,
    IrisAnalysisTagsRequestSchema,
    IrisAnalysisTagsResponseSchema,
    IrisSavedViewDeleteResponseSchema,
    IrisSavedViewItemSchema,
    IrisSavedViewListResponseSchema,
    IrisSavedViewRequestSchema,
    IrisTagListResponseSchema,
    IrisCaseCreateRequestSchema,
    IrisCaseDetailSchema,
    IrisCaseLinkRequestSchema,
    IrisCaseListResponseSchema,
    IrisCaseNoteRequestSchema,
    IrisCaseStatusRequestSchema,
    IrisCasesQuerySchema,
    IrisCaseUpdateRequestSchema,
    IrisBatchListResponseSchema,
    IrisBatchResponseSchema,
)


iris_blp = SmorestBlueprint(
    "iris", __name__,
    description="Analisis de cabeceras de correo electronico (anti-phishing)"
)

logger = logging.getLogger(__name__)


@iris_blp.post("/admin/replay")
@iris_blp.arguments(IrisReplayRequestSchema)
@iris_blp.response(200, IrisReplayResponseSchema, description="Replay of the corpus under two scoring policies")
@iris_blp.alt_response(400, schema=ErrorSchema, description="Invalid policy or message")
@iris_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@iris_blp.alt_response(403, schema=ErrorSchema, description="Administrators only")
@require_oauth_token
@require_role(Role.ADMIN)
@limiter.limit("30 per hour; 200 per day")
@handle_exceptions(default_exception=IrisExecutionError, logger=logger)
def run_rule_replay(data):
    """Simulador de reglas: comparar la política vigente con una candidata sobre el corpus (solo administradores)"""
    # Una política o un mensaje inválidos lanzan IrisInvalidInputError, que el
    # manejador de EllysiaException de la aplicación convierte en un 400 con
    # su descripción. No se captura aquí: una tupla (cuerpo, 400) pasaría por
    # el schema de respuesta del 200 y perdería los campos del error.
    report = IrisReplayManager().run(
        data["candidate"], data.get("baseline"), data.get("messages"), data["includeCorpus"],
    )
    logger.info(
        f"Replay de reglas por {get_current_user().username}: "
        f"{len(report['samples'])} muestras, {report['changedCount']} cambian de veredicto"
    )
    return report


@iris_blp.post("/analyze")
@iris_blp.arguments(AnalyzeRequestSchema)
@iris_blp.response(201, AnalyzeResponseSchema, description="Analysis started")
@iris_blp.alt_response(400, schema=ErrorSchema, description="Validation error")
@iris_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@iris_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.IRIS_CREATE])
@limiter.limit("20 per hour; 100 per day")
@handle_exceptions(default_exception=IrisExecutionError, logger=logger)
def analyze_headers(data):
    """Enviar cabeceras (o un mensaje .eml completo) para un analisis anti-phishing"""
    raw_headers = data.get("headers")
    raw_message = data.get("message")
    title = data.get("title")
    user = get_current_user()

    manager = IrisManager()
    try:
        analysis_id = manager.analyze(raw_headers, user.id, title=title, raw_message=raw_message)
    except IrisInvalidInputError as e:
        return {
            "error": e.__class__.__name__,
            "error_description": str(e.user_message or e),
            "code": e.code.value if e.code else 1100,
        }, 400

    logger.info(f"Iris analysis {analysis_id} started by user {user.username}")
    return {
        "message": "Analisis de cabeceras iniciado correctamente",
        "analysisId": analysis_id,
        "status": "pending",
    }


@iris_blp.post("/analyze/batch")
@iris_blp.response(201, IrisBatchResponseSchema, description="Batch accepted: summary and one item per message")
@iris_blp.alt_response(400, schema=ErrorSchema, description="Empty batch or over the batch limits")
@iris_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@iris_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@iris_blp.alt_response(429, schema=ErrorSchema, description="Too many analyses in flight; nothing was created")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.IRIS_CREATE])
@limiter.limit("10 per hour; 50 per day")
@handle_exceptions(default_exception=IrisExecutionError, logger=logger)
def analyze_batch():
    """Analizar varios .eml o un ZIP de una vez (campo multipart «files», repetible)"""
    # Los flujos se pasan sin leer: el manager los lee con tope, para no cargar
    # en memoria más de lo que admite un lote.
    uploads = [(storage.filename or "", storage.stream) for storage in request.files.getlist("files")]
    return IrisBatchManager().submit_batch(get_current_user().id, uploads)


@iris_blp.get("/batches")
@iris_blp.response(200, IrisBatchListResponseSchema, description="Recent batches")
@iris_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@iris_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.IRIS_READ])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(logger=logger)
def list_batches():
    """Lotes recientes del usuario"""
    return IrisBatchManager().list_batches(get_current_user().id)


@iris_blp.get("/batches/<int:batch_id>")
@iris_blp.response(200, IrisBatchResponseSchema, description="Batch with each analysis' current status")
@iris_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@iris_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@iris_blp.alt_response(404, schema=ErrorSchema, description="Batch not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.IRIS_READ])
@limiter.limit("600 per hour; 4000 per day")
@handle_exceptions(default_exception=IrisBatchNotFoundError, logger=logger)
def get_batch(batch_id: int):
    """Un lote con el estado actual de cada análisis (para sondear el progreso)"""
    return IrisBatchManager().get_batch(batch_id, get_current_user().id)


@iris_blp.get("/capabilities")
@iris_blp.response(200, IrisCapabilitiesResponseSchema, description="Iris limits and analysis modes")
@iris_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@iris_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.IRIS_READ])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(logger=logger)
def get_capabilities():
    """Limites y modos de analisis que aplica el servidor"""
    return IrisManager.get_capabilities()


@iris_blp.post("/results/<int:analysis_id>/feedback")
@iris_blp.arguments(IrisFeedbackRequestSchema)
@iris_blp.response(201, IrisFeedbackItemSchema, description="Analyst feedback recorded")
@iris_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@iris_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@iris_blp.alt_response(404, schema=ErrorSchema, description="Analysis not found")
@iris_blp.alt_response(409, schema=ErrorSchema, description="Analysis not finished")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.IRIS_UPDATE])
@limiter.limit("120 per hour; 1000 per day")
@handle_exceptions(default_exception=IrisAnalysisNotFoundError, logger=logger)
def submit_analysis_feedback(data, analysis_id: int):
    """Registrar si el veredicto de un análisis era correcto (no lo modifica)"""
    user = get_current_user()
    feedback = IrisFeedbackManager().submit_feedback(
        analysis_id, user.id, data["label"], data.get("note"),
    )
    logger.info(f"Feedback '{data['label']}' sobre el análisis {analysis_id} por {user.username}")
    return feedback


@iris_blp.get("/results/<int:analysis_id>/feedback")
@iris_blp.response(200, IrisFeedbackListResponseSchema, description="Analyst feedback history")
@iris_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@iris_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@iris_blp.alt_response(404, schema=ErrorSchema, description="Analysis not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.IRIS_READ])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(default_exception=IrisAnalysisNotFoundError, logger=logger)
def list_analysis_feedback(analysis_id: int):
    """Historial de correcciones de un análisis, de la más reciente a la más antigua"""
    user = get_current_user()
    return {
        "analysisId": analysis_id,
        "feedback": IrisFeedbackManager().list_feedback(analysis_id, user.id),
    }


@iris_blp.get("/feedback/metrics")
@iris_blp.response(200, IrisFeedbackMetricsResponseSchema, description="Detector metrics from analyst feedback")
@iris_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@iris_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.IRIS_READ])
@limiter.limit("60 per hour; 300 per day")
@handle_exceptions(logger=logger)
def get_feedback_metrics():
    """Precisión, recall, cobertura y desacuerdo del detector según tus correcciones"""
    user = get_current_user()
    return IrisFeedbackManager().get_metrics(user.id)


@iris_blp.get("/trusted-senders")
@iris_blp.arguments(IrisTrustedSendersQuerySchema, location="query")
@iris_blp.response(200, IrisTrustedSenderListResponseSchema, description="Trusted-sender exceptions")
@iris_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@iris_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.IRIS_READ])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(logger=logger)
def list_trusted_senders(args: dict):
    """Excepciones de confianza del usuario (con includeInactive, también caducadas y revocadas)"""
    user = get_current_user()
    entries = IrisTrustPolicyManager().list_entries(user.id, args["includeInactive"])
    return {"trustedSenders": entries, "total": len(entries)}


@iris_blp.post("/trusted-senders")
@iris_blp.arguments(IrisTrustedSenderRequestSchema)
@iris_blp.response(201, IrisTrustedSenderItemSchema, description="Trusted-sender exception created")
@iris_blp.alt_response(400, schema=ErrorSchema, description="Invalid value or duplicate exception")
@iris_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@iris_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.IRIS_CREATE])
@limiter.limit("60 per hour; 300 per day")
@handle_exceptions(default_exception=IrisExecutionError, logger=logger)
def create_trusted_sender(data):
    """Declarar un remitente o dominio de confianza para los próximos análisis del usuario"""
    user = get_current_user()
    entry = IrisTrustPolicyManager().create_entry(
        user.id, data["kind"], data["value"], data["reason"], data.get("expiresInDays"),
    )
    logger.info(f"Excepción de confianza {entry['trustedSenderId']} creada por {user.username}")
    return entry


@iris_blp.delete("/trusted-senders/<int:trusted_sender_id>")
@iris_blp.response(200, IrisTrustedSenderItemSchema, description="Trusted-sender exception revoked")
@iris_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@iris_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@iris_blp.alt_response(404, schema=ErrorSchema, description="Exception not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.IRIS_DELETE])
@limiter.limit("60 per hour; 300 per day")
@handle_exceptions(default_exception=IrisTrustedSenderNotFoundError, logger=logger)
def revoke_trusted_sender(trusted_sender_id: int):
    """Revocar una excepción de confianza; no se borra, queda en la auditoría"""
    user = get_current_user()
    entry = IrisTrustPolicyManager().revoke_entry(trusted_sender_id, user.id)
    logger.info(f"Excepción de confianza {trusted_sender_id} revocada por {user.username}")
    return entry


@iris_blp.get("/triage/views")
@iris_blp.response(200, IrisSavedViewListResponseSchema, description="Saved triage views")
@iris_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@iris_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.IRIS_READ])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(logger=logger)
def list_saved_views():
    """Vistas guardadas del historial de análisis del usuario"""
    user = get_current_user()
    return {"views": IrisTriageManager().list_views(user.id)}


@iris_blp.post("/triage/views")
@iris_blp.arguments(IrisSavedViewRequestSchema)
@iris_blp.response(201, IrisSavedViewItemSchema, description="Saved view created")
@iris_blp.alt_response(400, schema=ErrorSchema, description="Duplicate name or too many views")
@iris_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@iris_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.IRIS_UPDATE])
@limiter.limit("60 per hour; 300 per day")
@handle_exceptions(default_exception=IrisExecutionError, logger=logger)
def create_saved_view(data):
    """Guardar con nombre una combinación de filtros del historial"""
    user = get_current_user()
    return IrisTriageManager().create_view(user.id, data["name"], data["filters"])


@iris_blp.delete("/triage/views/<int:view_id>")
@iris_blp.response(200, IrisSavedViewDeleteResponseSchema, description="Saved view deleted")
@iris_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@iris_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@iris_blp.alt_response(404, schema=ErrorSchema, description="View not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.IRIS_UPDATE])
@limiter.limit("60 per hour; 300 per day")
@handle_exceptions(default_exception=IrisSavedViewNotFoundError, logger=logger)
def delete_saved_view(view_id: int):
    """Borrar una vista guardada"""
    user = get_current_user()
    IrisTriageManager().delete_view(view_id, user.id)
    return {"message": "Vista borrada", "viewId": view_id}


@iris_blp.get("/tags")
@iris_blp.response(200, IrisTagListResponseSchema, description="Tags in use and how many analyses carry each")
@iris_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@iris_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.IRIS_READ])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(logger=logger)
def list_tags():
    """Etiquetas que usa el usuario, de la más usada a la menos"""
    user = get_current_user()
    return {"tags": IrisTriageManager().list_tags(user.id)}


@iris_blp.put("/results/<int:analysis_id>/tags")
@iris_blp.arguments(IrisAnalysisTagsRequestSchema)
@iris_blp.response(200, IrisAnalysisTagsResponseSchema, description="Tags replaced")
@iris_blp.alt_response(400, schema=ErrorSchema, description="Tag too long or too many tags")
@iris_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@iris_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@iris_blp.alt_response(404, schema=ErrorSchema, description="Analysis not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.IRIS_UPDATE])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(default_exception=IrisAnalysisNotFoundError, logger=logger)
def set_analysis_tags(data, analysis_id: int):
    """Sustituir las etiquetas de un análisis (no cambia el análisis)"""
    user = get_current_user()
    tags = IrisTriageManager().set_tags(analysis_id, user.id, data["tags"])
    return {"analysisId": analysis_id, "tags": tags}


# =============================================================================
# Casos de analista
# =============================================================================

@iris_blp.post("/cases")
@iris_blp.arguments(IrisCaseCreateRequestSchema)
@iris_blp.response(201, IrisCaseDetailSchema, description="Case opened")
@iris_blp.alt_response(400, schema=ErrorSchema, description="Invalid title, tags or too many analyses")
@iris_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@iris_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@iris_blp.alt_response(404, schema=ErrorSchema, description="Analysis not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.IRIS_CREATE])
@limiter.limit("60 per hour; 300 per day")
@handle_exceptions(default_exception=IrisExecutionError, logger=logger)
def create_case(data):
    """Abrir un caso de analista, opcionalmente con análisis ya vinculados"""
    user = get_current_user()
    case = IrisCaseManager().create_case(user.id, data["title"], data["priority"],
                                         data["analysisIds"], data["tags"])
    logger.info(f"Caso {case['caseId']} abierto por {user.username}")
    return case


@iris_blp.get("/cases")
@iris_blp.arguments(IrisCasesQuerySchema, location="query")
@iris_blp.response(200, IrisCaseListResponseSchema, description="Analyst cases and counts by status")
@iris_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@iris_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.IRIS_READ])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(logger=logger)
def list_cases(args: dict):
    """Casos del usuario, con cuántos tiene en cada estado"""
    user = get_current_user()
    return IrisCaseManager().list_cases(user.id, args["status"], args["priority"], args["assignedToMe"])


@iris_blp.get("/cases/<int:case_id>")
@iris_blp.response(200, IrisCaseDetailSchema, description="Case with its analyses and timeline")
@iris_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@iris_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@iris_blp.alt_response(404, schema=ErrorSchema, description="Case not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.IRIS_READ])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(default_exception=IrisCaseNotFoundError, logger=logger)
def get_case(case_id: int):
    """Un caso con sus análisis y su timeline"""
    return IrisCaseManager().get_case(case_id, get_current_user().id)


@iris_blp.patch("/cases/<int:case_id>")
@iris_blp.arguments(IrisCaseUpdateRequestSchema)
@iris_blp.response(200, IrisCaseDetailSchema, description="Case updated")
@iris_blp.alt_response(400, schema=ErrorSchema, description="Invalid value or assignee")
@iris_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@iris_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@iris_blp.alt_response(404, schema=ErrorSchema, description="Case not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.IRIS_UPDATE])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(default_exception=IrisCaseNotFoundError, logger=logger)
def update_case(data, case_id: int):
    """Cambiar título, prioridad, etiquetas o asignación de un caso"""
    # Solo se pasan los campos presentes: assigneeId a null (quitar la
    # asignación) no es lo mismo que no enviarlo.
    fields_by_key = {"title": "title", "priority": "priority", "tags": "tags", "assigneeId": "assignee_id"}
    changes = {argument: data[key] for key, argument in fields_by_key.items() if key in data}
    return IrisCaseManager().update_case(case_id, get_current_user().id, **changes)


@iris_blp.post("/cases/<int:case_id>/status")
@iris_blp.arguments(IrisCaseStatusRequestSchema)
@iris_blp.response(200, IrisCaseDetailSchema, description="Case moved to a new status")
@iris_blp.alt_response(400, schema=ErrorSchema, description="Transition not allowed or missing reason")
@iris_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@iris_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@iris_blp.alt_response(404, schema=ErrorSchema, description="Case not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.IRIS_UPDATE])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(default_exception=IrisCaseNotFoundError, logger=logger)
def change_case_status(data, case_id: int):
    """Mover un caso por su ciclo de vida; cerrarlo exige una razón"""
    user = get_current_user()
    case = IrisCaseManager().change_status(case_id, user.id, data["status"], data.get("reason"))
    logger.info(f"Caso {case_id} pasa a {data['status']} por {user.username}")
    return case


@iris_blp.post("/cases/<int:case_id>/notes")
@iris_blp.arguments(IrisCaseNoteRequestSchema)
@iris_blp.response(201, IrisCaseDetailSchema, description="Note added")
@iris_blp.alt_response(400, schema=ErrorSchema, description="Empty note")
@iris_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@iris_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@iris_blp.alt_response(404, schema=ErrorSchema, description="Case not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.IRIS_UPDATE])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(default_exception=IrisCaseNotFoundError, logger=logger)
def add_case_note(data, case_id: int):
    """Añadir una nota a la timeline de un caso"""
    return IrisCaseManager().add_note(case_id, get_current_user().id, data["note"])


@iris_blp.post("/cases/<int:case_id>/analyses")
@iris_blp.arguments(IrisCaseLinkRequestSchema)
@iris_blp.response(201, IrisCaseDetailSchema, description="Analysis linked")
@iris_blp.alt_response(400, schema=ErrorSchema, description="Analysis already in the case")
@iris_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@iris_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@iris_blp.alt_response(404, schema=ErrorSchema, description="Case or analysis not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.IRIS_UPDATE])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(default_exception=IrisCaseNotFoundError, logger=logger)
def link_case_analysis(data, case_id: int):
    """Vincular un análisis a un caso (el análisis no cambia)"""
    return IrisCaseManager().link_analysis(case_id, get_current_user().id, data["analysisId"])


@iris_blp.delete("/cases/<int:case_id>/analyses/<int:analysis_id>")
@iris_blp.response(200, IrisCaseDetailSchema, description="Analysis unlinked")
@iris_blp.alt_response(400, schema=ErrorSchema, description="Analysis not in the case")
@iris_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@iris_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@iris_blp.alt_response(404, schema=ErrorSchema, description="Case not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.IRIS_UPDATE])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(default_exception=IrisCaseNotFoundError, logger=logger)
def unlink_case_analysis(case_id: int, analysis_id: int):
    """Desvincular un análisis de un caso (el análisis no se borra)"""
    return IrisCaseManager().unlink_analysis(case_id, get_current_user().id, analysis_id)


@iris_blp.get("/retention-policy")
@iris_blp.response(200, IrisRetentionReportResponseSchema, description="Retention policy and current status")
@iris_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@iris_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.IRIS_READ])
@limiter.limit("60 per hour; 300 per day")
@handle_exceptions(logger=logger)
def get_retention_policy():
    """Política de retención de Iris y cuántos de tus análisis la reflejan
    ya: cuántos conservan el raw todavía y cuántos ya lo perdieron."""
    user = get_current_user()
    report = IrisManager.get_retention_report(user.id)
    return {
        "rawMessageRetentionDays": report["raw_message_retention_days"],
        "analysisRetentionDays": (
            report["analysis_retention_days"] if report["analysis_retention_days"] > 0 else None
        ),
        "totalAnalyses": report["total_analyses"],
        "analysesWithRawRetained": report["analyses_with_raw_retained"],
        "analysesWithRawPurged": report["analyses_with_raw_purged"],
    }


@iris_blp.get("/status")
@iris_blp.arguments(AnalysisIdQuerySchema, location="query")
@iris_blp.response(200, AnalysisStatusResponseSchema, description="Analysis status")
@iris_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@iris_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@iris_blp.alt_response(404, schema=ErrorSchema, description="Analysis not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.IRIS_READ])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(default_exception=IrisAnalysisNotFoundError, logger=logger)
def get_analysis_status(args: dict):
    """Estado y progreso de un analisis"""
    analysis_id = args["id"]
    user = get_current_user()

    manager = IrisManager()
    IrisManager.assert_analysis_ownership(analysis_id, user.id)

    status = manager.get_analysis_status(analysis_id)
    progress = manager.get_analysis_progress(analysis_id)
    analysis = manager.get_analysis(analysis_id)

    response = {
        "analysisId": analysis_id,
        "status": status,
        "totalScore": analysis.total_score if analysis else None,
        "verdict": analysis.verdict if analysis else None,
        # El motivo solo tiene sentido cuando el análisis murió. Enviarlo
        # siempre dejaría un `failureReason` colgando de un análisis que
        # terminó bien tras un reintento y confundiría a quien lea el estado.
        "failureCode": analysis.failure_code if analysis else None,
        "failureReason": analysis.failure_reason if analysis else None,
    }
    if progress is not None:
        response["progress"] = progress

    return response


@iris_blp.get("/results")
@iris_blp.arguments(ResultsQuerySchema, location="query")
@iris_blp.response(200, AnalysisListResponseSchema, description="List of analyses")
@iris_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@iris_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.IRIS_READ])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(default_exception=IrisAnalysisNotFoundError, logger=logger)
def list_analyses(args):
    """Listar todos los analisis del usuario con paginacion, filtros y orden"""
    page = args["page"]
    per_page = args["per_page"]
    user = get_current_user()

    manager = IrisManager()
    results, total, thresholds = manager.get_analyses_for_user(
        user.id, page, per_page,
        search=args["search"], verdict=args["verdict"], status=args["status"], source=args["source"],
        tag=args["tag"], ioc=args["ioc"], review=args["review"],
        sort_by=args["sort_by"], sort_dir=args["sort_dir"],
    )

    return {
        "analyses": results,
        "total": total,
        "page": page,
        "perPage": per_page,
        "thresholds": thresholds,
    }


@iris_blp.get("/results/<int:analysis_id>")
@iris_blp.response(200, AnalysisDetailResponseSchema, description="Full analysis report")
@iris_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@iris_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@iris_blp.alt_response(404, schema=ErrorSchema, description="Analysis not found")
@iris_blp.alt_response(409, schema=ErrorSchema, description="Analysis not ready")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.IRIS_READ])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(default_exception=IrisAnalysisNotFoundError, logger=logger)
def get_analysis_result(analysis_id: int):
    """Informe completo de un analisis"""
    user = get_current_user()

    manager = IrisManager()
    IrisManager.assert_analysis_ownership(analysis_id, user.id)

    result = manager.get_analysis_results(analysis_id)
    return result


@iris_blp.get("/results/<int:analysis_id>/path")
@iris_blp.response(200, ReceivedPathResponseSchema, description="Parsed Received chain")
@iris_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@iris_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@iris_blp.alt_response(404, schema=ErrorSchema, description="Analysis not found")
@iris_blp.alt_response(410, schema=ErrorSchema, description="Raw message purged by retention")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.IRIS_READ])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(default_exception=IrisAnalysisNotFoundError, logger=logger)
def get_analysis_path(analysis_id: int):
    """Recorrido Received: del correo (oldest -> newest)"""
    user = get_current_user()

    manager = IrisManager()
    return manager.get_analysis_path(analysis_id, user.id)


@iris_blp.get("/results/<int:analysis_id>/iocs")
@iris_blp.response(200, AnalysisIocsResponseSchema, description="Extracted IOCs")
@iris_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@iris_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@iris_blp.alt_response(404, schema=ErrorSchema, description="Analysis not found")
@iris_blp.alt_response(410, schema=ErrorSchema, description="Raw message purged by retention")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.IRIS_READ])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(default_exception=IrisAnalysisNotFoundError, logger=logger)
def get_analysis_iocs(analysis_id: int):
    """Indicadores de compromiso (dominios, URLs, IPs, emails) del analisis"""
    user = get_current_user()

    manager = IrisManager()
    return manager.get_analysis_iocs(analysis_id, user.id)


@iris_blp.get("/results/<int:analysis_id>/export")
@iris_blp.response(200, description="Full analysis export (JSON file download)")
@iris_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@iris_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@iris_blp.alt_response(404, schema=ErrorSchema, description="Analysis not found")
@iris_blp.alt_response(409, schema=ErrorSchema, description="Analysis not ready")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.IRIS_READ])
@limiter.limit("30 per hour; 100 per day")
@handle_exceptions(default_exception=IrisAnalysisNotFoundError, logger=logger)
def export_analysis(analysis_id: int):
    """Exportar el análisis completo (resultado, reglas, raw si sigue
    disponible, Received-path e IOCs) como fichero JSON descargable --
    pensado para guardar una copia antes de que la retención purgue el raw."""
    user = get_current_user()
    manager = IrisManager()
    bundle = manager.export_analysis(analysis_id, user.id)

    logger.info(f"Análisis {analysis_id} exportado por usuario {user.username}")
    return Response(
        json.dumps(bundle, default=str, ensure_ascii=False, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": f'attachment; filename="iris-analysis-{analysis_id}.json"'},
    )


@iris_blp.post("/results/<int:analysis_id>/reanalyze")
@iris_blp.response(201, AnalyzeResponseSchema, description="New analysis started")
@iris_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@iris_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@iris_blp.alt_response(404, schema=ErrorSchema, description="Analysis not found")
@iris_blp.alt_response(410, schema=ErrorSchema, description="Raw message purged by retention")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.IRIS_CREATE])
@limiter.limit("20 per hour; 100 per day")
@handle_exceptions(default_exception=IrisAnalysisNotFoundError, logger=logger)
def reanalyze_analysis(analysis_id: int):
    """Re-lanzar el analisis con el ruleset actual sobre el mismo correo original"""
    user = get_current_user()

    manager = IrisManager()
    new_analysis_id = manager.reanalyze(analysis_id, user.id)

    logger.info(f"Analysis {analysis_id} re-analyzed as {new_analysis_id} by user {user.username}")
    return {
        "message": "Reanalisis iniciado correctamente",
        "analysisId": new_analysis_id,
        "status": "pending",
    }, 201


@iris_blp.post("/results/<int:analysis_id>/ai-summary")
@iris_blp.arguments(GenerateAiSummaryRequestSchema, location="query")
@iris_blp.response(202, GenerateAiSummaryResponseSchema, description="AI summary generation started")
@iris_blp.alt_response(400, schema=ErrorSchema, description="Analysis not finished")
@iris_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@iris_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@iris_blp.alt_response(404, schema=ErrorSchema, description="Analysis not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.IRIS_CREATE])
@limiter.limit("20 per hour; 100 per day")
@handle_exceptions(default_exception=IrisAnalysisNotFoundError, logger=logger)
def generate_ai_summary(args: dict, analysis_id: int):
    """Solicitar la generacion asincrona de la narrativa ejecutiva IA (IrisAIWriter)"""
    user = get_current_user()

    manager = IrisManager()
    status = manager.generate_ai_summary(analysis_id, user.id,
                                         regenerate=args["regenerate"])

    logger.info(f"AI summary solicitado para analysis {analysis_id} por usuario {user.username}")
    return {
        "message": ("Resumen ejecutivo IA ya disponible" if status == "done"
                    else "Generacion de resumen ejecutivo IA iniciada"),
        "analysisId": analysis_id,
        "status": status,
    }, 202


@iris_blp.post("/analyze/<int:analysis_id>/cancel")
@iris_blp.response(200, AnalysisCancelResponseSchema, description="Analysis cancelled")
@iris_blp.alt_response(400, schema=ErrorSchema, description="Invalid state")
@iris_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@iris_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@iris_blp.alt_response(404, schema=ErrorSchema, description="Analysis not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.IRIS_UPDATE])
@limiter.limit("60 per hour; 200 per day")
@handle_exceptions(default_exception=IrisAnalysisNotFoundError, logger=logger)
def cancel_analysis(analysis_id: int):
    """Cancelar un analisis en curso"""
    user = get_current_user()

    manager = IrisManager()
    IrisManager.assert_analysis_ownership(analysis_id, user.id)

    if not manager.cancel_analysis(analysis_id, user.id):
        raise IrisExecutionError("No se pudo cancelar el analisis")

    analysis = manager.get_analysis(analysis_id)
    logger.info(f"Analysis {analysis_id} cancelled by user {user.username}")
    return {
        "message": "Analisis cancelado exitosamente",
        "analysisId": analysis_id,
        "status": analysis.status if analysis else "cancelled",
    }


@iris_blp.delete("/results/<int:analysis_id>")
@iris_blp.response(200, AnalysisDeleteResponseSchema, description="Analysis deleted")
@iris_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@iris_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@iris_blp.alt_response(404, schema=ErrorSchema, description="Analysis not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.IRIS_DELETE])
@limiter.limit("60 per hour; 200 per day")
@handle_exceptions(default_exception=IrisAnalysisNotFoundError, logger=logger)
def delete_analysis(analysis_id: int):
    """Eliminar un analisis del sistema"""
    user = get_current_user()

    manager = IrisManager()
    IrisManager.assert_analysis_ownership(analysis_id, user.id)

    if not manager.delete_analysis(analysis_id):
        raise IrisExecutionError("No se pudo eliminar el analisis")

    logger.info(f"Analysis {analysis_id} deleted by user {user.username}")
    return {
        "message": "Analisis eliminado correctamente",
        "analysisId": analysis_id,
    }


def _download_url_for(document) -> str | None:
    if document.status == "done" and document.filename:
        return f"/iris/document/{document.id}/download"
    return None


@iris_blp.post("/results/<int:analysis_id>/document")
@iris_blp.response(202, GenerateDocumentResponseSchema, description="PDF generation started")
@iris_blp.alt_response(400, schema=ErrorSchema, description="Analysis not finished")
@iris_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@iris_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@iris_blp.alt_response(404, schema=ErrorSchema, description="Analysis not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.IRIS_CREATE])
@limiter.limit("30 per hour; 100 per day")
@handle_exceptions(default_exception=IrisAnalysisNotFoundError, logger=logger)
def generate_document(analysis_id: int):
    """Solicitar generacion asincrona de un informe PDF de un analisis"""
    user = get_current_user()

    doc_mgr = IrisReportManager()
    doc_id = doc_mgr.generate_report(analysis_id, user.id)

    logger.info(f"Generacion de PDF solicitada para analisis {analysis_id} (documento {doc_id}) por usuario {user.username}")
    return {
        "message": "Generacion de informe iniciada",
        "documentId": doc_id,
        "analysisId": analysis_id,
        "status": "running",
        "downloadUrl": None,
    }


@iris_blp.get("/document-status")
@iris_blp.arguments(DocumentStatusQuerySchema, location="query")
@iris_blp.response(200, IrisDocumentStatusResponseSchema, description="Document status")
@iris_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@iris_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@iris_blp.alt_response(404, schema=ErrorSchema, description="Document not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.IRIS_READ])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(default_exception=DocumentError, logger=logger)
def get_document_status(args):
    """Consultar estado de generacion de un documento"""
    user = get_current_user()
    document_id = args.get("documentId")
    analysis_id = args.get("analysisId")

    doc_mgr = IrisReportManager()
    # Lookup dual (por documentId o, si no, el último documento del
    # análisis) + verificación de ownership viven en el manager, no aquí.
    document = doc_mgr.get_document_status(document_id, analysis_id, user.id)

    return {
        "documentId": document.id,
        "analysisId": document.analysis_id,
        "status": document.status,
        "verdict": document.verdict,
        "createdAt": document.created_at,
        "generatedAt": document.generated_at,
        "downloadUrl": _download_url_for(document),
    }


@iris_blp.get("/documents")
@iris_blp.arguments(IrisDocumentsQuerySchema, location="query")
@iris_blp.response(200, IrisDocumentListResponseSchema, description="Paginated documents")
@iris_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@iris_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.IRIS_READ])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(default_exception=DocumentError, logger=logger)
def get_all_documents(args):
    """Documentos del usuario, paginados (antes devolvía la lista
    completa sin límite)."""
    user = get_current_user()

    doc_mgr = IrisReportManager()
    documents, total = doc_mgr.get_documents_for_user_paginated(
        user.id, args["page"], args["per_page"],
    )

    docs_list = [{
        "documentId": document.id,
        "analysisId": document.analysis_id,
        "status": document.status,
        "verdict": document.verdict,
        "createdAt": document.created_at,
        "generatedAt": document.generated_at,
        "downloadUrl": _download_url_for(document),
    } for document in documents]

    return {
        "documents": docs_list, "total": total,
        "page": args["page"], "perPage": args["per_page"],
    }


@iris_blp.get("/results/<int:analysis_id>/documents")
@iris_blp.response(200, AnalysisDocumentsResponseSchema, description="Analysis documents")
@iris_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@iris_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@iris_blp.alt_response(404, schema=ErrorSchema, description="Analysis not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.IRIS_READ])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(default_exception=IrisAnalysisNotFoundError, logger=logger)
def get_documents_by_analysis(analysis_id: int):
    """Obtener todos los documentos de un analisis concreto"""
    user = get_current_user()
    IrisManager.assert_analysis_ownership(analysis_id, user.id)

    doc_mgr = IrisReportManager()
    documents = doc_mgr.get_documents_by_parent(analysis_id)

    docs_list = [{
        "documentId": document.id,
        "analysisId": document.analysis_id,
        "status": document.status,
        "verdict": document.verdict,
        "createdAt": document.created_at,
        "generatedAt": document.generated_at,
        "downloadUrl": _download_url_for(document),
    } for document in documents]

    return {"analysisId": analysis_id, "documents": docs_list, "total": len(docs_list)}


@iris_blp.get("/document/<int:document_id>/download")
@iris_blp.response(200, description="PDF file download")
@iris_blp.alt_response(400, schema=ErrorSchema, description="Document not ready")
@iris_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@iris_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@iris_blp.alt_response(404, schema=ErrorSchema, description="Document not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.IRIS_READ])
@handle_exceptions(default_exception=DocumentError, logger=logger)
def download_document(document_id: int):
    """Descargar un documento PDF generado"""
    user = get_current_user()

    doc_mgr = IrisReportManager()
    document = doc_mgr.assert_document_ownership(document_id, user.id)

    if document.status != "done" or not document.filename or not os.path.exists(document.filename):
        raise DocumentNotReadyError(document_id, document.status)

    logger.info(f"Serving Iris document {document_id}: {document.filename}")
    return send_file(
        document.filename,
        mimetype="application/pdf",
        as_attachment=True,
        # El nombre descargable identifica el documento, no solo el
        # análisis. Dos informes del mismo análisis llegaban al navegador con
        # el mismo nombre y el segundo sobrescribía al primero en la carpeta
        # de descargas.
        download_name=f"iris_analysis_{document.analysis_id}_{document.id}.pdf",
    )


@iris_blp.delete("/document/<int:document_id>")
@iris_blp.response(200, IrisDocumentDeleteResponseSchema, description="Document deleted")
@iris_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@iris_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@iris_blp.alt_response(404, schema=ErrorSchema, description="Document not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.IRIS_DELETE])
@limiter.limit("60 per hour; 200 per day")
@handle_exceptions(default_exception=DocumentError, logger=logger)
def delete_document(document_id: int):
    """Eliminar un documento"""
    user = get_current_user()

    doc_mgr = IrisReportManager()
    doc_mgr.assert_document_ownership(document_id, user.id)
    doc_mgr.delete_document(document_id)

    logger.info(f"Documento {document_id} eliminado por usuario {user.username}")
    return {"message": "Documento eliminado correctamente", "documentId": document_id}


# =============================================================================
# Mailbox connector — Gmail / Microsoft Graph
# =============================================================================

def _serialize_connection(connection) -> dict:
    """Never includes refresh_token/access_token — those must not leave the
    server under any circumstance. Ambas columnas son ``deferred``, así que
    no serializarlas aquí es además lo que evita que se lleguen a leer de la
    base de datos al montar la respuesta."""
    return {
        "connectionId": connection.id,
        "provider": connection.provider,
        "accountEmail": connection.account_email,
        "folder": connection.folder,
        "folderDisplayName": connection.folder_display_name,
        "folderType": connection.folder_type,
        "fullMessageMode": connection.full_message_mode,
        "status": connection.status,
        "lastSyncAt": connection.last_sync_at,
        "lastError": connection.last_error,
        "syncStartedAt": connection.sync_started_at,
        "createdAt": connection.created_at,
    }


@iris_blp.get("/mailbox/providers")
@iris_blp.response(200, IrisMailboxProvidersResponseSchema, description="Supported mailbox providers")
@iris_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@iris_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.IRIS_READ])
def list_mailbox_providers():
    """Proveedores de buzón soportados por el conector"""
    return {"providers": IrisMailboxManager.list_providers()}


@iris_blp.post("/mailbox/connect")
@iris_blp.arguments(IrisMailboxConnectRequestSchema)
@iris_blp.response(201, IrisMailboxConnectResponseSchema, description="Authorization URL")
@iris_blp.alt_response(400, schema=ErrorSchema, description="Invalid provider or quota exceeded")
@iris_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@iris_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.IRIS_CREATE])
@limiter.limit("20 per hour; 100 per day")
@handle_exceptions(default_exception=IrisExecutionError, logger=logger)
def connect_mailbox(data):
    """Iniciar la conexión de un buzón externo (Gmail / Microsoft 365).

    Devuelve la URL de autorización del proveedor; el frontend debe abrir
    una ventana/redirigir ahí. El proveedor redirige de vuelta a
    ``GET /iris/mailbox/callback`` cuando el usuario consiente (o lo rechaza).
    """
    user = get_current_user()
    authorize_url = IrisMailboxManager().start_connect(
        user.id, data["provider"],
        full_message_mode=data.get("fullMessageMode", False),
        folder=data.get("folder"),
    )
    logger.info(f"Usuario {user.username} inició conexión de buzón ({data['provider']})")
    return {"authorizeUrl": authorize_url}, 201


@iris_blp.get("/mailbox/callback")
@iris_blp.arguments(IrisMailboxCallbackQuerySchema, location="query")
@iris_blp.response(302, description="Redirect to the frontend")
def mailbox_oauth_callback(args: dict):
    """Callback OAuth de Google/Microsoft.

    Sin ``require_oauth_token``: llega como navegación directa del
    navegador tras el redirect del proveedor, sin Authorization header
    posible. El ``state`` firmado (ver ``IrisMailboxManager._verify_state``)
    hace de protección CSRF y liga la petición al usuario que inició
    ``/mailbox/connect`` — es la única identidad que este endpoint necesita.
    """
    connections_url = f"{CR.general_config().public_url}/iris/conexiones"

    if args.get("error"):
        logger.info(f"Mailbox OAuth callback: consentimiento denegado ({args['error']})")
        return redirect(f"{connections_url}?error=consent_denied")

    if not args.get("code"):
        return redirect(f"{connections_url}?error=missing_code")

    try:
        IrisMailboxManager().handle_callback(args["state"], args["code"])
    except IrisMailboxOAuthStateError:
        logger.warning("Mailbox OAuth callback: state inválido o caducado")
        return redirect(f"{connections_url}?error=invalid_state")
    except Exception as e:
        logger.error(f"Mailbox OAuth callback falló: {e}", exc_info=True)
        return redirect(f"{connections_url}?error=connection_failed")

    return redirect(f"{connections_url}?connected=1")


@iris_blp.get("/mailbox/connections")
@iris_blp.response(200, IrisMailboxConnectionListResponseSchema, description="Mailbox connections")
@iris_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@iris_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.IRIS_READ])
def list_mailbox_connections():
    """Listar las conexiones de buzón del usuario actual (nunca expone tokens)"""
    user = get_current_user()
    connections = IrisMailboxManager.list_connections(user.id)
    items = [_serialize_connection(connection) for connection in connections]
    return {"connections": items, "total": len(items)}


@iris_blp.patch("/mailbox/connections/<int:connection_id>")
@iris_blp.arguments(IrisMailboxUpdateConnectionRequestSchema)
@iris_blp.response(200, IrisMailboxConnectionItemSchema, description="Connection updated")
@iris_blp.alt_response(400, schema=ErrorSchema,
                        description="Invalid status, or folder not found for this account/provider")
@iris_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@iris_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@iris_blp.alt_response(404, schema=ErrorSchema, description="Connection not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.IRIS_UPDATE])
@limiter.limit("60 per hour; 300 per day")
@handle_exceptions(default_exception=IrisMailboxConnectionNotFoundError, logger=logger)
def update_mailbox_connection(data, connection_id: int):
    """Cambiar la carpeta vigilada o pausar/reactivar una conexión"""
    user = get_current_user()
    connection = IrisMailboxManager().update_connection(
        connection_id, user.id, folder=data.get("folder"), status=data.get("status"),
    )
    logger.info(f"Conexión {connection_id} actualizada por usuario {user.username}")
    return _serialize_connection(connection)


@iris_blp.get("/mailbox/connections/<int:connection_id>/folders")
@iris_blp.response(200, IrisMailboxFoldersResponseSchema,
                    description="Real folders/labels for this account")
@iris_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@iris_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@iris_blp.alt_response(404, schema=ErrorSchema, description="Connection not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.IRIS_READ])
@limiter.limit("30 per hour; 100 per day")
@handle_exceptions(default_exception=IrisMailboxConnectionNotFoundError, logger=logger)
def list_mailbox_connection_folders(connection_id: int):
    """Carpetas/etiquetas reales de la cuenta conectada -- únicos valores
    válidos para ``folder`` en ``PATCH /mailbox/connections/<id>``.

    Hace una llamada en vivo al proveedor (no se cachea): la lista puede
    cambiar en cualquier momento desde fuera de Iris.
    """
    user = get_current_user()
    folders = IrisMailboxManager().list_folders(connection_id, user.id)
    return {
        "folders": [
            {
                "providerId": f.provider_id, "displayName": f.display_name,
                "folderType": f.folder_type,
            }
            for f in folders
        ]
    }


@iris_blp.get("/mailbox/connections/<int:connection_id>/health")
@iris_blp.response(200, IrisMailboxHealthResponseSchema, description="Connection health status")
@iris_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@iris_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@iris_blp.alt_response(404, schema=ErrorSchema, description="Connection not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.IRIS_READ])
@limiter.limit("60 per hour; 300 per day")
@handle_exceptions(default_exception=IrisMailboxConnectionNotFoundError, logger=logger)
def get_mailbox_connection_health(connection_id: int):
    """Estado observable de una conexión de buzón.

    Distingue "no hay correo nuevo" de "Iris está atascado" sin tener que
    leer los logs del servidor: expone contadores de mensajes descubiertos/
    aceptados/pendientes/en reintento/muertos, la duración del último sync
    y cuándo terminó el último que dejó la cola de checkpoint vacía.
    """
    user = get_current_user()
    health = IrisMailboxManager().get_connection_health(connection_id, user.id)
    return {
        "status": health["status"],
        "lastSyncAt": health["last_sync_at"],
        "lastSuccessAt": health["last_success_at"],
        "lastError": health["last_error"],
        "syncStartedAt": health["sync_started_at"],
        "lastSyncDurationMs": health["last_sync_duration_ms"],
        "cursorEstablished": health["cursor_established"],
        "ingestedToday": health["ingested_today"],
        "maxIngestedPerDay": health["max_ingested_per_day"],
        "messagesDiscoveredTotal": health["messages_discovered_total"],
        "messagesAcceptedTotal": health["messages_accepted_total"],
        "messagesPending": health["messages_pending"],
        "messagesRetrying": health["messages_retrying"],
        "messagesDead": health["messages_dead"],
        "oldestPendingMessageAgeSeconds": health["oldest_pending_message_age_seconds"],
    }


@iris_blp.delete("/mailbox/connections/<int:connection_id>")
@iris_blp.response(200, IrisMailboxConnectionDeleteResponseSchema, description="Connection deleted")
@iris_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@iris_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@iris_blp.alt_response(404, schema=ErrorSchema, description="Connection not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.IRIS_DELETE])
@limiter.limit("60 per hour; 200 per day")
@handle_exceptions(default_exception=IrisMailboxConnectionNotFoundError, logger=logger)
def delete_mailbox_connection(connection_id: int):
    """Desconectar un buzón: revoca el token en el proveedor (best-effort) y borra la fila"""
    user = get_current_user()
    IrisMailboxManager().delete_connection(connection_id, user.id)
    logger.info(f"Conexión {connection_id} eliminada por usuario {user.username}")
    return {"message": "Conexión eliminada correctamente", "connectionId": connection_id}


@iris_blp.post("/mailbox/connections/<int:connection_id>/sync")
@iris_blp.response(202, IrisMailboxSyncResponseSchema, description="Sync queued")
@iris_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@iris_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@iris_blp.alt_response(404, schema=ErrorSchema, description="Connection not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.IRIS_UPDATE])
@limiter.limit("30 per hour; 100 per day")
@handle_exceptions(default_exception=IrisMailboxConnectionNotFoundError, logger=logger)
def sync_mailbox_connection(connection_id: int):
    """Sondeo manual de una conexión (fuera del ciclo periódico del scheduler)"""
    user = get_current_user()
    IrisMailboxManager().trigger_sync(connection_id, user.id)
    logger.info(f"Sync manual de la conexión {connection_id} encolado por usuario {user.username}")
    return {"message": "Sincronización encolada correctamente", "connectionId": connection_id}, 202


def _serialize_notification_preference(preference) -> dict:
    return {
        "digestEnabled": preference.digest_enabled,
        "mutedUntil": preference.muted_until,
        "notifyReauthRequired": preference.notify_reauth_required,
        "notifySyncStuck": preference.notify_sync_stuck,
        "digestLastSentAt": preference.digest_last_sent_at,
    }


@iris_blp.get("/notification-preferences")
@iris_blp.response(200, IrisNotificationPreferenceResponseSchema, description="Notification preferences")
@iris_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@iris_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.IRIS_READ])
def get_notification_preferences():
    """Preferencias de notificación del usuario actual.

    Si nunca las ha tocado, devuelve los valores por defecto sin crear una
    fila -- ver ``IrisNotificationPreferenceManager.get_or_default``.
    """
    user = get_current_user()
    preference = IrisNotificationPreferenceManager.get_or_default(user.id)
    return _serialize_notification_preference(preference)


@iris_blp.put("/notification-preferences")
@iris_blp.arguments(IrisNotificationPreferenceUpdateRequestSchema)
@iris_blp.response(200, IrisNotificationPreferenceResponseSchema, description="Preferences updated")
@iris_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@iris_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.IRIS_UPDATE])
@limiter.limit("60 per hour; 300 per day")
def update_notification_preferences(data):
    """Actualizar las preferencias de notificación del usuario actual.

    Actualización parcial: solo se tocan los campos presentes en el cuerpo
    (ver ``IrisNotificationPreferenceUpdateRequestSchema``). No exige
    ``IRIS_CREATE`` aunque la primera llamada cree la fila -- no consume
    cuota ni trae una entidad nueva al panel, es una modificación de un
    ajuste que conceptualmente siempre existe para el usuario (mismo
    criterio que ``PATCH /mailbox/connections/<id>``).
    """
    user = get_current_user()
    # Solo se pasan los campos presentes en el cuerpo: el manager distingue
    # "no venía" (kwarg ausente, valor por defecto _UNSET) de "venía con un
    # valor" -- ver IrisNotificationPreferenceManager.update().
    changes = {}
    if "digestEnabled" in data:
        changes["digest_enabled"] = data["digestEnabled"]
    if "mutedForMinutes" in data:
        changes["muted_for_minutes"] = data["mutedForMinutes"]
    if "notifyReauthRequired" in data:
        changes["notify_reauth_required"] = data["notifyReauthRequired"]
    if "notifySyncStuck" in data:
        changes["notify_sync_stuck"] = data["notifySyncStuck"]
    preference = IrisNotificationPreferenceManager.update(user.id, **changes)
    logger.info(f"Preferencias de notificación de Iris actualizadas por usuario {user.username}")
    return _serialize_notification_preference(preference)
