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

import logging
import os

from flask import redirect, send_file
from flask_smorest import Blueprint as SmorestBlueprint

from src.modules.users import (
    require_oauth_token,
    require_attributes,
    AttributeType,
    get_current_user,
)
from src.modules.shared import handle_exceptions, limiter
from src.modules.shared.schemas import ErrorSchema
from src.modules.shared._exceptions import DocumentError, DocumentNotReadyError

import src.modules.system.config_reading as CR

from .managers import IrisManager, IrisReportManager, IrisMailboxManager
from .exceptions import (
    IrisAnalysisNotFoundError,
    IrisExecutionError,
    IrisInvalidInputError,
    IrisMailboxConnectionNotFoundError,
    IrisMailboxOAuthStateError,
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
)


iris_blp = SmorestBlueprint(
    "iris", __name__,
    description="Analisis de cabeceras de correo electronico (anti-phishing)"
)

logger = logging.getLogger(__name__)


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
        # B03: el motivo solo tiene sentido cuando el análisis murió. Enviarlo
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
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.IRIS_READ])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(default_exception=IrisAnalysisNotFoundError, logger=logger)
def get_analysis_iocs(analysis_id: int):
    """Indicadores de compromiso (dominios, URLs, IPs, emails) del analisis"""
    user = get_current_user()

    manager = IrisManager()
    return manager.get_analysis_iocs(analysis_id, user.id)


@iris_blp.post("/results/<int:analysis_id>/reanalyze")
@iris_blp.response(201, AnalyzeResponseSchema, description="New analysis started")
@iris_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@iris_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@iris_blp.alt_response(404, schema=ErrorSchema, description="Analysis not found")
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
    # E4: lookup dual (por documentId o, si no, el último documento del
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
@iris_blp.response(200, IrisDocumentListResponseSchema, description="All documents")
@iris_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@iris_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.IRIS_READ])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(default_exception=DocumentError, logger=logger)
def get_all_documents():
    """Obtener todos los documentos del usuario"""
    user = get_current_user()

    doc_mgr = IrisReportManager()
    documents = doc_mgr.get_documents_for_user(user.id)

    docs_list = [{
        "documentId": document.id,
        "analysisId": document.analysis_id,
        "status": document.status,
        "verdict": document.verdict,
        "createdAt": document.created_at,
        "generatedAt": document.generated_at,
        "downloadUrl": _download_url_for(document),
    } for document in documents]

    return {"documents": docs_list, "total": len(docs_list)}


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
        # B11: el nombre descargable identifica el documento, no solo el
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
# Mailbox connector (Fase 4) — Gmail / Microsoft Graph
# =============================================================================

def _serialize_connection(connection) -> dict:
    """Never includes refresh_token_enc/access_token_enc — those must not
    leave the server under any circumstance."""
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
    """Estado observable de una conexión de buzón (M10).

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
