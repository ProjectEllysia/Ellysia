import logging

from flask import send_file, Response
from flask_smorest import Blueprint as SmorestBlueprint

import src.modules.system.config_reading as CR
from src.modules.shared import handle_exceptions, limiter, current_actor
from src.modules.shared._exceptions import ValidationError
from src.modules.shared.schemas import ErrorSchema
from src.modules.users import require_oauth_token, require_attributes, AttributeType, UserManager, get_current_user

from .managers import AegisManager, AegisOrgProfileManager, CampaignManager
from .exceptions import (
    DocumentError,
    DocumentNotFoundError,
    DocumentNotReadyError,
    CampaignError,
    EllysiaException,
)
from .services import (
    ExportData,
    ExportFormat,
    MarkdownExporter,
    MarkdownTemplate,
    JsonExporter,
    get_exporter_for_format,
)
from .schemas import (
    AegisGenerateRequestSchema,
    AegisOrgProfileSchema,
    AegisPillUpdateSchema,
    DocumentIdQuerySchema,
    ExportRequestBodySchema,
    ExportDownloadQuerySchema,
    MarkdownExportQuerySchema,
    GenerateResponseSchema,
    DeleteDocumentResponseSchema,
    DocumentListResponseSchema,
    ProductSearchQuerySchema,
    ExportFormatsResponseSchema,
    ExportResultResponseSchema,
    DistributionListCreateSchema,
    RecipientsAddSchema,
    CampaignCreateSchema,
    QuizTokenQuerySchema,
    QuizSubmitSchema,
)


aegis_blp = SmorestBlueprint(
    "aegis", __name__,
    description="Generacion y exportacion de pildoras de concienciacion (Aegis)"
)
logger = logging.getLogger(__name__)

USER_MANAGER = UserManager()


def _get_document_checked(manager, doc_id: int, user_id: int) -> dict:
    document = manager.get_document(doc_id)
    if document.get("userId") != user_id:
        logger.warning(
            "Documento %s no encontrado o acceso denegado | user=%s (userId=%s)",
            doc_id, current_actor(), user_id
        )
        raise DocumentNotFoundError(doc_id)
    if document["status"] != "done":
        raise DocumentNotReadyError(doc_id, document["status"])
    return document


# ============================================================================
# GENERATION
# ============================================================================


@aegis_blp.post("/generate")
@aegis_blp.arguments(AegisGenerateRequestSchema)
@aegis_blp.response(202, GenerateResponseSchema, description="Generation started")
@aegis_blp.alt_response(400, schema=ErrorSchema, description="Validation error")
@aegis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@aegis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@limiter.limit("10 per hour; 30 per day")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.AEGIS_CREATE])
@handle_exceptions(default_exception=DocumentError, logger=logger)
def aegis_generate(data):
    """Iniciar generacion asincrona de una pildora Aegis"""
    topic_id = data["topicId"]
    tweaks = data.get("tweaks") or {}

    user = get_current_user()
    manager = AegisManager(user)
    document_id = manager.generate(topic_id=topic_id, tweaks=tweaks)
    logger.info(
        f"Aegis generate lanzado -- topicId={topic_id} "
        f"documentId={document_id} user={get_current_user().username}"
    )
    return {
        "message": "Generacion Aegis iniciada",
        "documentId": document_id,
        "status": "pending",
    }


# ============================================================================
# DOCUMENT MANAGEMENT
# ============================================================================


@aegis_blp.get("/status")
@aegis_blp.arguments(DocumentIdQuerySchema, location="query")
@aegis_blp.response(200, description="Document status")
@aegis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@aegis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@aegis_blp.alt_response(404, schema=ErrorSchema, description="Document not found")
@limiter.limit("120 per hour; 500 per day")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.AEGIS_READ])
@handle_exceptions(default_exception=DocumentError, logger=logger)
def aegis_status(args):
    """Consultar estado de generacion de un documento"""
    doc_id = args["id"]
    user = get_current_user()

    manager = AegisManager(user)
    manager.assert_document_ownership(doc_id)
    doc_info = manager.get_document(doc_id)

    if doc_info["status"] != "done":
        raise DocumentNotReadyError(doc_id, doc_info["status"])

    return doc_info


@aegis_blp.get("/document")
@aegis_blp.arguments(DocumentIdQuerySchema, location="query")
@aegis_blp.response(200, description="Document content (JSON)")
@aegis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@aegis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@aegis_blp.alt_response(404, schema=ErrorSchema, description="Document not found")
@aegis_blp.alt_response(409, schema=ErrorSchema, description="Document not ready")
@limiter.limit("60 per hour; 300 per day")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.AEGIS_READ])
@handle_exceptions(default_exception=DocumentError, logger=logger)
def aegis_get_document(args):
    """Obtener contenido estructurado de un documento terminado"""
    doc_id = args["id"]
    user = get_current_user()
    manager = AegisManager(user)

    manager.assert_document_ownership(doc_id)

    doc_info = manager.get_document(doc_id)
    if doc_info["status"] != "done":
        raise DocumentNotReadyError(doc_id, doc_info["status"])

    return doc_info


@aegis_blp.put("/document")
@aegis_blp.arguments(DocumentIdQuerySchema, location="query")
@aegis_blp.arguments(AegisPillUpdateSchema)
@aegis_blp.response(200, description="Pill updated")
@aegis_blp.alt_response(400, schema=ErrorSchema, description="Validation error")
@aegis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@aegis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@aegis_blp.alt_response(404, schema=ErrorSchema, description="Document not found")
@aegis_blp.alt_response(409, schema=ErrorSchema, description="Document not ready")
@limiter.limit("30 per hour; 100 per day")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.AEGIS_UPDATE])
@handle_exceptions(default_exception=DocumentError, logger=logger)
def aegis_update_document(args, data):
    """Reemplazar (upsert) el contenido editable de una pildora generada"""
    doc_id = args["id"]
    user = get_current_user()
    manager = AegisManager(user)

    _get_document_checked(manager, doc_id, user.id)
    updated = manager.update_pill(doc_id, data)

    logger.info("Aegis doc %s actualizado | user=%s", doc_id, current_actor())
    return updated


# ============================================================================
# ORGANIZATION PROFILE
# ============================================================================


@aegis_blp.get("/org-profile")
@aegis_blp.response(200, AegisOrgProfileSchema, description="Perfil de organización (o defaults si no existe)")
@aegis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@aegis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@limiter.limit("120 per hour; 500 per day")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.AEGIS_READ])
@handle_exceptions(default_exception=EllysiaException, logger=logger)
def aegis_get_org_profile():
    """Obtener el perfil de organización del usuario actual (o defaults)"""
    user = get_current_user()
    manager = AegisOrgProfileManager(user)
    return manager.get_or_default()


@aegis_blp.put("/org-profile")
@aegis_blp.arguments(AegisOrgProfileSchema)
@aegis_blp.response(200, AegisOrgProfileSchema, description="Perfil guardado")
@aegis_blp.alt_response(400, schema=ErrorSchema, description="Validation error")
@aegis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@aegis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@limiter.limit("30 per hour; 100 per day")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.AEGIS_UPDATE])
@handle_exceptions(default_exception=EllysiaException, logger=logger)
def aegis_save_org_profile(data):
    """Crear o actualizar (upsert) el perfil de organización del usuario actual"""
    user = get_current_user()
    manager = AegisOrgProfileManager(user)
    saved = manager.upsert(data)
    logger.info("Perfil de organización de Aegis guardado | user=%s", current_actor())
    return saved


@aegis_blp.get("/download")
@aegis_blp.arguments(DocumentIdQuerySchema, location="query")
@aegis_blp.response(200, description="File download (JSON or Markdown)")
@aegis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@aegis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@aegis_blp.alt_response(404, schema=ErrorSchema, description="Document not found")
@aegis_blp.alt_response(409, schema=ErrorSchema, description="Document not ready")
@limiter.limit("30 per hour; 100 per day")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.AEGIS_READ])
@handle_exceptions(default_exception=DocumentError, logger=logger)
def aegis_download(args):
    """Descargar archivo original generado (.json o .md)"""
    doc_id = args["id"]
    user = get_current_user()

    manager = AegisManager(user)
    manager.assert_document_ownership(doc_id)

    doc_info = manager.get_document(doc_id)
    if doc_info["status"] != "done":
        raise DocumentNotReadyError(doc_id, doc_info["status"])

    try:
        path = manager.get_document_path(doc_id)
    except (ValueError, FileNotFoundError):
        raise DocumentNotFoundError(doc_id)

    doc_format = doc_info.get("format", "json")
    mimetype = "application/json" if doc_format == "json" else "text/markdown; charset=utf-8"

    logger.info("Descargando Aegis doc %s (%s) | user=%s", doc_id, doc_format, current_actor())
    return send_file(path, as_attachment=True, download_name=path.name, mimetype=mimetype)


@aegis_blp.delete("/document")
@aegis_blp.arguments(DocumentIdQuerySchema, location="query")
@aegis_blp.response(200, DeleteDocumentResponseSchema, description="Document deleted")
@aegis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@aegis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@aegis_blp.alt_response(404, schema=ErrorSchema, description="Document not found")
@limiter.limit("30 per hour; 100 per day")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.AEGIS_DELETE])
@handle_exceptions(default_exception=DocumentError, logger=logger)
def aegis_delete_document(args):
    """Eliminar un documento Aegis (BD + archivo en disco)"""
    doc_id = args["id"]
    user = get_current_user()
    manager = AegisManager(user)

    manager.assert_document_ownership(doc_id)
    manager.delete_document(doc_id)

    logger.info("Aegis doc %s eliminado | user=%s", doc_id, current_actor())
    return {"message": "Documento eliminado correctamente", "documentId": doc_id}


@aegis_blp.get("/documents")
@aegis_blp.response(200, DocumentListResponseSchema, description="List of documents")
@aegis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@aegis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@limiter.limit("60 per hour; 300 per day")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.AEGIS_READ])
@handle_exceptions(default_exception=DocumentError, logger=logger)
def aegis_list_user_documents():
    """Listar todos los documentos Aegis del usuario autenticado"""
    user = get_current_user()
    manager = AegisManager(user)
    docs = manager.list_user_documents()

    return {"count": len(docs), "documents": docs}


@aegis_blp.get("/topics")
@aegis_blp.response(200, description="List of available topics")
@aegis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@limiter.limit("120 per hour; 600 per day")
@require_oauth_token
@handle_exceptions(default_exception=DocumentError, logger=logger)
def aegis_get_topics():
    """Listar temas disponibles para generar pildoras"""
    user = get_current_user()
    manager = AegisManager(user)
    topics = manager.get_topics()

    return topics


@aegis_blp.get("/products")
@aegis_blp.arguments(ProductSearchQuerySchema, location="query")
@aegis_blp.response(200, description="Products matching the search term")
@aegis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@limiter.limit("120 per hour; 600 per day")
@require_oauth_token
@handle_exceptions(default_exception=DocumentError, logger=logger)
def aegis_search_products(args):
    """Buscar productos vigilables en el índice CPE del espejo local de NVD"""
    products = AegisOrgProfileManager.search_products(args["q"], limit=args["limit"])
    return {"count": len(products), "products": products}


# ============================================================================
# EXPORT
# ============================================================================


@aegis_blp.get("/export/formats")
@aegis_blp.response(200, ExportFormatsResponseSchema, description="Available export formats")
@aegis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@aegis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.AEGIS_READ])
def list_export_formats():
    """Listar todos los formatos de exportacion disponibles"""
    return {
        "default": "md",
        "formats": [
            {
                "id": "md", "name": "Markdown",
                "description": "Documento estructurado legible por humanos, ideal para revision",
                "mimetype": "text/markdown; charset=utf-8",
                "extension": ".md",
                "features": ["streaming", "human_readable", "version_control_friendly", "editable"],
            },
            {
                "id": "json", "name": "JSON",
                "description": "Formato nativo estructurado para integraciones",
                "mimetype": "application/json",
                "extension": ".json",
                "features": ["machine_readable", "structured", "api_friendly"],
            },
            {
                "id": "pdf", "name": "PDF",
                "description": "Documento final para distribucion formal (proximamente)",
                "mimetype": "application/pdf",
                "extension": ".pdf",
                "coming_soon": True,
            },
            {
                "id": "html", "name": "HTML",
                "description": "Pagina web para intranet (proximamente)",
                "mimetype": "text/html",
                "extension": ".html",
                "coming_soon": True,
            },
        ],
    }


@aegis_blp.post("/export/<int:doc_id>")
@aegis_blp.arguments(ExportRequestBodySchema)
@aegis_blp.response(200, ExportResultResponseSchema, description="Export completed")
@aegis_blp.alt_response(400, schema=ErrorSchema, description="Unsupported format")
@aegis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@aegis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@aegis_blp.alt_response(404, schema=ErrorSchema, description="Document not found")
@aegis_blp.alt_response(409, schema=ErrorSchema, description="Document not ready")
@limiter.limit("20 per hour; 100 per day")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.AEGIS_READ])
@handle_exceptions(default_exception=DocumentError, logger=logger)
def export_document(data, doc_id):
    """Exportar un documento Aegis al formato solicitado"""
    format_str = data.get("format", "md")
    options = data.get("options", {})

    try:
        export_format = ExportFormat(format_str.lower())
    except ValueError:
        raise ValidationError(
            field="format",
            message=f"Formato '{format_str}' no soportado",
            value=format_str,
        )

    user = get_current_user()
    manager = AegisManager(user)
    doc_info = _get_document_checked(manager, doc_id, user.id)

    export_data = ExportData.from_document_dict(doc_info, doc_id)

    if export_format == ExportFormat.MARKDOWN:
        exporter = MarkdownExporter(template=MarkdownTemplate(
            include_toc=options.get("includeToc", False),
            include_metadata_block=options.get("includeMetadata", True),
        ))
    elif export_format == ExportFormat.JSON:
        exporter = JsonExporter()
    else:
        exporter = get_exporter_for_format(export_format)

    result = exporter.export(export_data)

    logger.info(
        f"Exportacion {export_format.value} generada para doc {doc_id} "
        f"-- user={get_current_user().username}, size={result.size_bytes}b"
    )
    return {
        "success": True,
        "export": result.to_response_dict(),
        "document": {
            "id": doc_id,
            "title": doc_info.get("title"),
            "topicId": doc_info.get("topicId"),
            "status": doc_info.get("status"),
        },
        "downloadUrl": f"/aegis/export/{doc_id}/download?format={export_format.value}",
    }


@aegis_blp.get("/export/<int:doc_id>/download")
@aegis_blp.arguments(ExportDownloadQuerySchema, location="query")
@aegis_blp.response(200, description="File download (exported format)")
@aegis_blp.alt_response(400, schema=ErrorSchema, description="Unsupported format")
@aegis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@aegis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@aegis_blp.alt_response(404, schema=ErrorSchema, description="Document not found")
@aegis_blp.alt_response(409, schema=ErrorSchema, description="Document not ready")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.AEGIS_READ])
@limiter.limit("30 per hour; 150 per day")
@handle_exceptions(default_exception=DocumentError, logger=logger)
def download_export(args, doc_id):
    """Descargar una exportacion previamente generada"""
    format_str = args.get("format", "md")
    inline = args.get("inline", False)

    try:
        export_format = ExportFormat(format_str.lower())
    except ValueError:
        raise ValidationError(
            field="format",
            message=f"Formato '{format_str}' no soportado",
            value=format_str,
        )

    user = get_current_user()
    manager = AegisManager(user)
    doc_info = _get_document_checked(manager, doc_id, user.id)

    export_data = ExportData.from_document_dict(doc_info, doc_id)
    exporter = get_exporter_for_format(export_format)
    result = exporter.export(export_data)

    disposition = "inline" if inline else "attachment"
    logger.info(
        f"Descarga {export_format.value} doc {doc_id} "
        f"-- user={get_current_user().username}, inline={inline}"
    )

    return Response(
        result.content,
        mimetype=result.mimetype,
        headers={
            "Content-Disposition": f'{disposition}; filename="{result.filename}"',
            "Content-Length": str(result.size_bytes),
            "X-Export-Format": export_format.value,
            "X-Document-Id": str(doc_id),
        },
    )


@aegis_blp.get("/export/md/<int:doc_id>")
@aegis_blp.arguments(MarkdownExportQuerySchema, location="query")
@aegis_blp.response(200, description="File download (Markdown)")
@aegis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@aegis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@aegis_blp.alt_response(404, schema=ErrorSchema, description="Document not found")
@aegis_blp.alt_response(409, schema=ErrorSchema, description="Document not ready")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.AEGIS_READ])
@limiter.limit("30 per hour; 150 per day")
@handle_exceptions(default_exception=DocumentError, logger=logger)
def quick_export_markdown(args, doc_id):
    """Exportacion rapida a Markdown con opciones adicionales"""
    inline = args.get("inline", False)
    include_alerts = not args.get("noAlerts", False)

    user = get_current_user()
    manager = AegisManager(user)
    doc_info = _get_document_checked(manager, doc_id, user.id)

    export_data = ExportData.from_document_dict(doc_info, doc_id)
    if not include_alerts:
        from dataclasses import replace
        export_data = replace(export_data, alerts=[])

    exporter = MarkdownExporter(template=MarkdownTemplate(
        include_metadata_block=False,
        alert_section_title="## Alertas Recientes" if include_alerts else "",
    ))
    result = exporter.export(export_data)

    disposition = "inline" if inline else "attachment"
    logger.info(
        f"Quick MD export doc {doc_id} "
        f"-- user={get_current_user().username}, inline={inline}, alerts={include_alerts}"
    )

    return Response(
        result.content,
        mimetype="text/markdown; charset=utf-8",
        headers={
            "Content-Disposition": f'{disposition}; filename="{result.filename}"',
            "Content-Length": str(result.size_bytes),
        },
    )


# ============================================================================
# DISTRIBUTION LISTS (autenticado, propietario)
# ============================================================================


@aegis_blp.post("/lists")
@aegis_blp.arguments(DistributionListCreateSchema)
@aegis_blp.response(201, description="Distribution list created")
@aegis_blp.alt_response(400, schema=ErrorSchema, description="Validation error")
@aegis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@aegis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@limiter.limit("30 per hour; 100 per day")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.AEGIS_CREATE])
@handle_exceptions(default_exception=CampaignError, logger=logger)
def create_distribution_list(data):
    """Crear una lista de distribución vacía"""
    user = get_current_user()
    manager = CampaignManager(user)
    distribution_list = manager.create_list(data["name"])
    logger.info(f"Lista {distribution_list['id']} creada | user={current_actor()}")
    return distribution_list, 201


@aegis_blp.get("/lists")
@aegis_blp.response(200, description="Distribution lists owned by the authenticated user")
@aegis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@aegis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@limiter.limit("60 per hour; 300 per day")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.AEGIS_READ])
@handle_exceptions(default_exception=CampaignError, logger=logger)
def list_distribution_lists():
    """Listar las listas de distribución del usuario autenticado"""
    user = get_current_user()
    manager = CampaignManager(user)
    lists = manager.list_lists()
    return {"count": len(lists), "lists": lists}


@aegis_blp.get("/lists/<int:list_id>")
@aegis_blp.response(200, description="Distribution list detail")
@aegis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@aegis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@aegis_blp.alt_response(404, schema=ErrorSchema, description="List not found")
@limiter.limit("60 per hour; 300 per day")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.AEGIS_READ])
@handle_exceptions(default_exception=CampaignError, logger=logger)
def get_distribution_list(list_id):
    """Obtener el detalle de una lista de distribución"""
    user = get_current_user()
    manager = CampaignManager(user)
    return manager.get_list(list_id)


@aegis_blp.delete("/lists/<int:list_id>")
@aegis_blp.response(200, description="List deleted")
@aegis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@aegis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@aegis_blp.alt_response(404, schema=ErrorSchema, description="List not found")
@limiter.limit("30 per hour; 100 per day")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.AEGIS_DELETE])
@handle_exceptions(default_exception=CampaignError, logger=logger)
def delete_distribution_list(list_id):
    """Eliminar una lista de distribución y sus destinatarios"""
    user = get_current_user()
    manager = CampaignManager(user)
    manager.delete_list(list_id)
    logger.info(f"Lista {list_id} eliminada | user={current_actor()}")
    return {"message": "Lista eliminada correctamente", "listId": list_id}


@aegis_blp.post("/lists/<int:list_id>/recipients")
@aegis_blp.arguments(RecipientsAddSchema)
@aegis_blp.response(201, description="Recipients added")
@aegis_blp.alt_response(400, schema=ErrorSchema, description="Validation error")
@aegis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@aegis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@aegis_blp.alt_response(404, schema=ErrorSchema, description="List not found")
@limiter.limit("30 per hour; 100 per day")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.AEGIS_CREATE])
@handle_exceptions(default_exception=CampaignError, logger=logger)
def add_list_recipients(data, list_id):
    """Añadir destinatarios a una lista (los emails duplicados se ignoran)"""
    user = get_current_user()
    manager = CampaignManager(user)
    created = manager.add_recipients(list_id, data["recipients"])
    logger.info(f"{len(created)} destinatarios añadidos a lista {list_id} | user={current_actor()}")
    return {"count": len(created), "recipients": created}, 201


@aegis_blp.get("/lists/<int:list_id>/recipients")
@aegis_blp.response(200, description="Recipients of a distribution list")
@aegis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@aegis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@aegis_blp.alt_response(404, schema=ErrorSchema, description="List not found")
@limiter.limit("60 per hour; 300 per day")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.AEGIS_READ])
@handle_exceptions(default_exception=CampaignError, logger=logger)
def get_list_recipients(list_id):
    """Listar los destinatarios de una lista"""
    user = get_current_user()
    manager = CampaignManager(user)
    recipients = manager.get_recipients(list_id)
    return {"count": len(recipients), "recipients": recipients}


@aegis_blp.delete("/lists/<int:list_id>/recipients/<int:recipient_id>")
@aegis_blp.response(200, description="Recipient removed")
@aegis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@aegis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@aegis_blp.alt_response(404, schema=ErrorSchema, description="List not found")
@limiter.limit("30 per hour; 100 per day")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.AEGIS_DELETE])
@handle_exceptions(default_exception=CampaignError, logger=logger)
def delete_list_recipient(list_id, recipient_id):
    """Eliminar un destinatario de una lista"""
    user = get_current_user()
    manager = CampaignManager(user)
    manager.remove_recipient(list_id, recipient_id)
    logger.info(f"Destinatario {recipient_id} eliminado de lista {list_id} | user={current_actor()}")
    return {"message": "Destinatario eliminado correctamente"}


# ============================================================================
# CAMPAIGNS (autenticado, propietario)
# ============================================================================


@aegis_blp.post("/campaigns")
@aegis_blp.arguments(CampaignCreateSchema)
@aegis_blp.response(201, description="Campaign created (draft)")
@aegis_blp.alt_response(400, schema=ErrorSchema, description="Validation error")
@aegis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@aegis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@aegis_blp.alt_response(404, schema=ErrorSchema, description="Document or list not found")
@limiter.limit("20 per hour; 60 per day")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.AEGIS_CREATE])
@handle_exceptions(default_exception=CampaignError, logger=logger)
def create_campaign(data):
    """Crear una campaña en borrador (píldora + lista, aún sin lanzar)"""
    user = get_current_user()
    manager = CampaignManager(user)
    campaign = manager.create_campaign(data["documentId"], data["listId"], data["name"])
    logger.info(f"Campaña {campaign['id']} creada (draft) | user={current_actor()}")
    return campaign, 201


@aegis_blp.get("/campaigns")
@aegis_blp.response(200, description="Campaigns owned by the authenticated user")
@aegis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@aegis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@limiter.limit("60 per hour; 300 per day")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.AEGIS_READ])
@handle_exceptions(default_exception=CampaignError, logger=logger)
def list_campaigns():
    """Listar las campañas del usuario autenticado"""
    user = get_current_user()
    manager = CampaignManager(user)
    campaigns = manager.list_campaigns()
    return {"count": len(campaigns), "campaigns": campaigns}


@aegis_blp.get("/campaigns/<int:campaign_id>")
@aegis_blp.response(200, description="Campaign detail including per-recipient tracking")
@aegis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@aegis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@aegis_blp.alt_response(404, schema=ErrorSchema, description="Campaign not found")
@limiter.limit("60 per hour; 300 per day")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.AEGIS_READ])
@handle_exceptions(default_exception=CampaignError, logger=logger)
def get_campaign(campaign_id):
    """Obtener el detalle de una campaña, incluyendo el tracking por destinatario"""
    user = get_current_user()
    manager = CampaignManager(user)
    return manager.get_campaign(campaign_id)


@aegis_blp.delete("/campaigns/<int:campaign_id>")
@aegis_blp.response(200, description="Campaign deleted")
@aegis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@aegis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@aegis_blp.alt_response(404, schema=ErrorSchema, description="Campaign not found")
@limiter.limit("30 per hour; 100 per day")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.AEGIS_DELETE])
@handle_exceptions(default_exception=CampaignError, logger=logger)
def delete_campaign(campaign_id):
    """Eliminar una campaña y su tracking — invalida los enlaces de quiz ya enviados"""
    user = get_current_user()
    manager = CampaignManager(user)
    manager.delete_campaign(campaign_id)
    logger.info(f"Campaña {campaign_id} eliminada | user={current_actor()}")
    return {"message": "Campaña eliminada correctamente", "campaignId": campaign_id}


@aegis_blp.post("/campaigns/<int:campaign_id>/launch")
@aegis_blp.response(200, description="Campaign launched — sending in background")
@aegis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@aegis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@aegis_blp.alt_response(404, schema=ErrorSchema, description="Campaign not found")
@aegis_blp.alt_response(409, schema=ErrorSchema, description="Campaign already launched")
@limiter.limit("10 per hour; 30 per day")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.AEGIS_UPDATE])
@handle_exceptions(default_exception=CampaignError, logger=logger)
def launch_campaign(campaign_id):
    """Lanzar una campaña: congela el quiz, genera tokens y encola el envío"""
    user = get_current_user()
    manager = CampaignManager(user)
    campaign = manager.launch_campaign(campaign_id)
    logger.info(f"Campaña {campaign_id} lanzada | user={current_actor()}")
    return {"message": "Campaña lanzada correctamente", "campaign": campaign}


# ============================================================================
# PUBLIC QUIZ — SIN AUTENTICACIÓN (el token es la única identidad)
# ============================================================================
#
# Deliberadamente sin @require_oauth_token / @require_attributes: el
# destinatario de una campaña nunca tiene cuenta en Ellysia. El token opaco de
# CampaignRecipient (nunca derivado del email) es la única credencial, y su
# estado ('completed' es inmutable) impone la regla de no-repetición.


@aegis_blp.get("/quiz")
@aegis_blp.arguments(QuizTokenQuerySchema, location="query")
@aegis_blp.response(200, description="Quiz content for this token (never includes correct answers)")
@aegis_blp.alt_response(404, schema=ErrorSchema, description="Invalid or unknown token")
@limiter.limit("30 per hour")
@handle_exceptions(default_exception=CampaignError, logger=logger)
def get_public_quiz(args):
    """Obtener el contenido del quiz asociado a un token de campaña (sin login)"""
    return CampaignManager.get_public_quiz(args["t"])


@aegis_blp.post("/quiz")
@aegis_blp.arguments(QuizTokenQuerySchema, location="query")
@aegis_blp.arguments(QuizSubmitSchema)
@aegis_blp.response(200, description="Quiz graded and recorded")
@aegis_blp.alt_response(400, schema=ErrorSchema, description="Validation error")
@aegis_blp.alt_response(404, schema=ErrorSchema, description="Invalid or unknown token")
@aegis_blp.alt_response(409, schema=ErrorSchema, description="Quiz already completed")
@limiter.limit("10 per hour")
@handle_exceptions(default_exception=CampaignError, logger=logger)
def submit_public_quiz(args, data):
    """Enviar las respuestas del quiz asociado a un token (sin login, no repetible)"""
    token = args["t"]
    result = CampaignManager.submit_public_quiz(token, data["answers"])
    logger.info(f"Quiz completado | token=***{token[-6:]} score={result['score']}/{result['total']}")
    return result
