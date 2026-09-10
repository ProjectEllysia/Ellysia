from __future__ import annotations

import logging
import os

from flask import send_file
from flask_smorest import Blueprint as SmorestBlueprint

from src.modules.users import require_oauth_token, require_attributes, AttributeType, get_current_user
from src.modules.shared import (
    handle_exceptions,
    limiter,
    normalize_target,
    CANCELLABLE_STATES,
)
from src.modules.shared._exceptions import (
    ValidationError,
    IllegalStateError,
    EllysiaException,
    DocumentError,
    DocumentNotFoundError,
    DocumentNotReadyError,
)
from src.modules.shared.schemas import ErrorSchema

from .managers import (
    ScanManager,
    NmapScanManager,
    NiktoScanManager,
    NucleiScanManager,
    LybraEngineManager,
    ProgramedScanManager,
    ThemisReportManager,
    ScanFolderManager,
    ScanHistoryManager,
    TracerouteManager,
    AuthorizedTargetManager,
    KbSyncManager,
)
from .model import ScanType
from .exceptions import (
    ScanError,
    ScanExecutionError,
    ScanNotFoundError,
    FindingNotFoundError,
    PortValidationError,
    PrivateIPRequested,
    ProgramedScanError,
    ProgramedScanNotFoundError,
    FolderNotFoundError,
    FolderNameInvalidError,
    AuthorizedTargetNotFoundError,
    DuplicateAuthorizedTargetError,
    TargetNotAuthorizedError,
)
from .schemas import (
    ScanIdQuerySchema,
    NmapScanRequestSchema,
    NiktoScanRequestSchema,
    NucleiScanRequestSchema,
    LybraScanRequestSchema,
    FindingStateRequestSchema,
    FindingStateResponseSchema,
    AddAuthorizedTargetSchema,
    AuthorizedTargetListResponseSchema,
    AuthorizedTargetActionResponseSchema,
    ResultsQuerySchema,
    UnresolvedProductsQuerySchema,
    GeneratePdfRequestSchema,
    DocumentStatusQuerySchema,
    DocumentsQuerySchema,
    ScheduledScanRequestSchema,
    ScanResponseSchema,
    NmapScanResponseSchema,
    ScanStatusResponseSchema,
    IsFinishedResponseSchema,
    ResultsResponseSchema,
    ScanDetailResponseSchema,
    DocumentStatusResponseSchema,
    DocumentListResponseSchema,
    ScanDocumentsResponseSchema,
    DocumentDeleteResponseSchema,
    PdfGenerateResponseSchema,
    ScheduledScanResponseSchema,
    ScheduledScanListResponseSchema,
    ScheduledScanActionResponseSchema,
    CreateFolderSchema,
    RenameFolderSchema,
    MoveScanToFolderSchema,
    AddScansToFolderSchema,
    FolderListResponseSchema,
    FolderActionResponseSchema,
    ScanFolderActionResponseSchema,
    BulkDeleteScansSchema,
    BulkDeleteScansResponseSchema,
    HistoryHostsResponseSchema,
    HistoryStatsQuerySchema,
    HistoryStatsResponseSchema,
    TracerouteResponseSchema,
)


themis_blp = SmorestBlueprint(
    "themis", __name__,
    description="Escaneos de seguridad (Nmap, Nikto, Lybra, Nuclei) y PDFs"
)
logger = logging.getLogger(__name__)

# Nota sobre los `# type: ignore` de este fichero (Q3): los modelos usan
# `Column(...)` clásico de SQLAlchemy en vez de `Mapped[...]`, así que mypy a
# veces infiere `user.id`/`scan.campo` como `Column[T]` en vez de `T` — ruido
# de tipado estático, no una inseguridad real de `None` (el ORM ya hidrató el
# valor real en tiempo de ejecución). Se auditaron todos al hacer Q3; los que
# escondían un bug real (una variable reasignada que perdía el narrowing de
# tipo, un argumento con el tipo equivocado) se corrigieron en la fuente, no
# con un ignore — ver `cancel_scan` y `ScanManager.get_manager_for_type`.


def _download_url_for(document) -> str | None:
    """URL de descarga del documento, o None si no está listo."""
    if document.status == "done" and document.filename:
        return f"/themis/document/{document.id}/download"
    return None


def _serialize_document(document) -> dict:
    """Serializa un ThemisDocument al formato de los endpoints de listado.

    Unifica la lógica de downloadUrl y los campos comunes que antes estaban
    duplicados en get_all_documents y get_documents_by_scan.
    """
    return {
        "documentId": document.id,
        "scanId": document.scan_id,
        "scanType": document.scan_type,
        "status": document.status,
        "isAiGenerated": document.is_ai_generated == 1 if document.is_ai_generated is not None else False,
        "createdAt": document.created_at if document.created_at else None,
        "generatedAt": document.generated_at if document.generated_at else None,
        "downloadUrl": _download_url_for(document),
    }

def validate_web_target(raw: str) -> str:
    """
    Nikto y Nuclei escanean por hostname/URL, no por un spec de CIDR/rango, así
    que ninguno puede reusar ``validate_targets``. Resuelve el target a IP y
    rechaza esa IP si es privada — cierra el hueco SSRF donde un hostname/DNS
    resuelve a una dirección local o de metadata (127.0.0.1, 169.254.169.254,
    ...).

    Returns:
        La IP resuelta — Nuclei la necesita además para el gate de objetivos
        autorizados (``AuthorizedTargetManager.is_authorized`` solo entiende
        IPs desnudas, no URLs).
    """
    try:
        ip, _ = normalize_target(raw)
    except ValueError as exc:
        raise ValidationError(field="target", message=str(exc), value=raw) from exc
    try:
        ScanManager.reject_private_ip(ip)
    except PrivateIPRequested as exc:
        raise EllysiaException(str(exc.user_message or exc), status_code=403)
    return ip


@themis_blp.get("/scan-status")
@themis_blp.arguments(ScanIdQuerySchema, location="query")
@themis_blp.response(200, ScanStatusResponseSchema, description="Scan status")
@themis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@themis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@themis_blp.alt_response(404, schema=ErrorSchema, description="Scan not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.THEMIS_READ])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(default_exception=ScanNotFoundError, logger=logger)
def get_scan_status(args):
    """Estado y progreso de un escaneo"""
    scan_id = args["id"]
    user = get_current_user()
    manager, scan = ScanManager.resolve_owned_scan(scan_id, user.id)

    status = manager.get_scan_status(scan_id)
    progress = manager.get_scan_progress(scan_id)
    result = manager.format_scan(scan_id)

    response = {
        "message": f"Estado del escaneo {scan_id}: {status}",
        "scanId": scan_id,
        "status": status,
        "scanType": scan.scan_type,
    }
    if progress is not None:
        response["progress"] = progress
    response["scan"] = result

    return response


@themis_blp.post("/scans/<int:scan_id>/cancel")
@themis_blp.response(200, ScanResponseSchema, description="Scan cancelled")
@themis_blp.alt_response(400, schema=ErrorSchema, description="Invalid state")
@themis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@themis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@themis_blp.alt_response(500, schema=ErrorSchema, description="Cancellation failed")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.THEMIS_UPDATE])
@limiter.limit("60 per hour; 200 per day")
@handle_exceptions(default_exception=ScanNotFoundError, logger=logger)
def cancel_scan(scan_id: int):
    """Cancelar un escaneo en curso"""
    user = get_current_user()

    manager, scan = ScanManager.resolve_owned_scan(scan_id, user.id) # type: ignore

    if scan.status not in CANCELLABLE_STATES:
        raise IllegalStateError(
            f"El escaneo no se puede cancelar en estado: {scan.status}"
        )

    if not manager.cancel_scan(scan_id, user.id): # type: ignore
        raise ScanExecutionError(
            scan_type=scan.scan_type,
            target=scan.target,
            reason="No se pudo cancelar",
        )

    # Q3: variable nueva en vez de reasignar `scan` — reusar el mismo nombre
    # con un tipo distinto (Scan | None aquí, Scan más arriba) es lo que
    # forzaba el type: ignore en esta función completa.
    refreshed_scan = manager.get_scan_by_id(scan_id)
    if not refreshed_scan:
        raise ScanNotFoundError(scan_id)

    logger.info(f"Escaneo {refreshed_scan.scan_type} {scan_id} cancelado por {user.username}")
    return {
        "message": "Escaneo cancelado exitosamente",
        "scanId": scan_id,
        "scanType": scan.scan_type,
        "status": scan.status,
        "user": user.username,
    }


@themis_blp.post("/nmap")
@themis_blp.arguments(NmapScanRequestSchema)
@themis_blp.response(201, NmapScanResponseSchema, description="Nmap scan started")
@themis_blp.alt_response(400, schema=ErrorSchema, description="Validation error")
@themis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@themis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.THEMIS_CREATE])
@limiter.limit("20 per hour; 100 per day")
@handle_exceptions(default_exception=ScanExecutionError, logger=logger)
def start_nmap_scan(data: dict):
    """Lanzar uno o mas escaneos Nmap (soporta rangos CIDR)"""
    host = data["target"]
    ports = data["ports"]
    timeout = data["timeout"]
    user = get_current_user()

    nmap_manager = NmapScanManager()
    hosts = ScanManager.validate_targets(host)

    try:
        ScanManager.validate_port(ports)
    except PortValidationError as exc:
        raise ValidationError(field="ports", message=str(exc), value=ports) from exc

    scan_ids = []
    for target_host in hosts:
        scan_id = nmap_manager.run_scan(
            target_host=target_host,
            target_ports=ports,
            user_id=user.id,
            timeout=timeout,
        )
        scan_ids.append(scan_id)
        logger.info(f"Nmap lanzado: ID={scan_id} host={target_host} ports={ports} user={user.username}")

    return {
        "message": "Escaneo(s) Nmap iniciado(s) correctamente",
        "scanIds": scan_ids,
        "target": {"hosts": hosts, "ports": ports},
        "totalScans": len(scan_ids),
        "user": user.username,
    }


@themis_blp.post("/nikto")
@themis_blp.arguments(NiktoScanRequestSchema)
@themis_blp.response(201, ScanResponseSchema, description="Nikto scan started")
@themis_blp.alt_response(400, schema=ErrorSchema, description="Validation error")
@themis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@themis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@limiter.limit("20 per hour; 100 per day")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.THEMIS_CREATE])
@handle_exceptions(default_exception=ScanExecutionError, logger=logger)
def start_nikto_scan(data):
    """Lanzar un escaneo Nikto"""
    target = data["target"]
    timeout = data["timeout"]
    user = get_current_user()

    validate_web_target(target)

    nikto_manager = NiktoScanManager()
    scan_id = nikto_manager.run_scan(target, user_id=user.id, timeout=timeout)
    logger.info(f"Nikto lanzado: ID={scan_id} target={target} timeout={timeout} user={user.username}")
    return {
        "message": "Escaneo Nikto iniciado correctamente",
        "scanId": scan_id,
        "target": target,
        "timeout": timeout,
        "user": user.username,
    }


@themis_blp.post("/nuclei")
@themis_blp.arguments(NucleiScanRequestSchema)
@themis_blp.response(201, ScanResponseSchema, description="Nuclei scan started")
@themis_blp.alt_response(400, schema=ErrorSchema, description="Validation error")
@themis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@themis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions / target not authorized")
@limiter.limit("20 per hour; 100 per day")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.THEMIS_CREATE])
@handle_exceptions(default_exception=ScanExecutionError, logger=logger)
def start_nuclei_scan(data):
    """Lanzar un escaneo Nuclei (roadmap Fase U1).

    A diferencia de Nikto, Nuclei toca el objetivo bastante más — nace sujeto
    al registro de objetivos autorizados desde el día uno, no se le añade
    después (roadmap Fase U1, punto 3).
    """
    target = data["target"]
    user = get_current_user()

    ip = validate_web_target(target)
    if not AuthorizedTargetManager.is_authorized(user.id, ip):
        raise TargetNotAuthorizedError(target)

    nuclei_manager = NucleiScanManager()
    scan_id = nuclei_manager.run_scan(
        target=target,
        user_id=user.id,
        severities=data.get("severities"),
        tags=data.get("tags"),
        rate_limit=data.get("rateLimit"),
        request_timeout=data.get("requestTimeout"),
        timeout=data.get("timeout"),
    )
    logger.info(f"Nuclei lanzado: ID={scan_id} target={target} user={user.username}")
    return {
        "message": "Escaneo Nuclei iniciado correctamente",
        "scanId": scan_id,
        "scanType": "nuclei",
        "user": user.username,
    }


@themis_blp.post("/lybra")
@themis_blp.arguments(LybraScanRequestSchema)
@themis_blp.response(201, ScanResponseSchema, description="Lybra engine scan started")
@themis_blp.alt_response(400, schema=ErrorSchema, description="Validation error")
@themis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@themis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.THEMIS_CREATE])
@limiter.limit("20 per hour; 100 per day")
@handle_exceptions(default_exception=ScanExecutionError, logger=logger)
def start_lybra_scan(data):
    """Lanzar un escaneo Lybra: descubre los servicios del objetivo por su cuenta."""
    timeout = data["timeout"]
    user = get_current_user()
    manager = LybraEngineManager()

    # Autodescubrimiento: valida el objetivo (rechaza IPs privadas, etc.)
    # igual que un escaneo Nmap, ya que el transporte propio toca el objetivo.
    target = ScanManager.validate_targets(data["target"], max_hosts=1)[0]
    discover_ports = None
    if data.get("ports"):
        try:
            discover_ports = ScanManager.validate_port(data["ports"])
        except PortValidationError as exc:
            raise ValidationError(field="ports", message=str(exc), value=data["ports"]) from exc

    scan_id = manager.run_scan(
        user_id=user.id,
        target=target,
        discover_ports=discover_ports,
        timeout=timeout,
        aggressive=data.get("aggressive", False),
    )
    logger.info(f"Lybra lanzado: ID={scan_id} autodescubrimiento target={target} user={user.username}")

    return {
        "message": "Escaneo Lybra iniciado correctamente",
        "scanId": scan_id,
        "scanType": "lybra",
        "user": user.username,
    }


@themis_blp.post("/authorized-targets")
@themis_blp.arguments(AddAuthorizedTargetSchema)
@themis_blp.response(201, AuthorizedTargetActionResponseSchema, description="Authorized target added")
@themis_blp.alt_response(400, schema=ErrorSchema, description="Validation error")
@themis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@themis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@themis_blp.alt_response(409, schema=ErrorSchema, description="Target already registered")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.THEMIS_CREATE])
@limiter.limit("60 per hour; 200 per day")
@handle_exceptions(default_exception=DuplicateAuthorizedTargetError, logger=logger)
def add_authorized_target(data):
    """Añadir un objetivo (IP o CIDR) al registro de objetivos autorizados (roadmap §6)."""
    user = get_current_user()
    entry = AuthorizedTargetManager().add(user.id, data["target"], data.get("label"))
    logger.info(f"Objetivo autorizado {entry.id} ('{entry.target}') añadido por {user.username}")
    return {
        "message": "Objetivo autorizado añadido correctamente",
        "targetId": entry.id,
        "target": entry.target,
        "user": user.username,
    }


@themis_blp.get("/authorized-targets")
@themis_blp.response(200, AuthorizedTargetListResponseSchema, description="User's authorized targets")
@themis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@themis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.THEMIS_READ])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(default_exception=AuthorizedTargetNotFoundError, logger=logger)
def list_authorized_targets():
    """Listar el registro de objetivos autorizados del usuario."""
    user = get_current_user()
    entries = AuthorizedTargetManager().list(user.id)
    return {
        "message": "Objetivos autorizados obtenidos correctamente",
        "targets": [
            {"id": entry.id, "target": entry.target, "label": entry.label, "createdAt": entry.created_at}
            for entry in entries
        ],
        "user": user.username,
    }


@themis_blp.delete("/authorized-targets/<int:target_id>")
@themis_blp.response(200, AuthorizedTargetActionResponseSchema, description="Authorized target removed")
@themis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@themis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@themis_blp.alt_response(404, schema=ErrorSchema, description="Authorized target not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.THEMIS_DELETE])
@limiter.limit("60 per hour; 200 per day")
@handle_exceptions(default_exception=AuthorizedTargetNotFoundError, logger=logger)
def delete_authorized_target(target_id: int):
    """Eliminar una entrada del registro de objetivos autorizados."""
    user = get_current_user()
    target = AuthorizedTargetManager().remove(target_id, user.id)
    logger.info(f"Objetivo autorizado {target_id} eliminado por {user.username}")
    return {
        "message": "Objetivo autorizado eliminado correctamente",
        "targetId": target_id,
        "target": target,
        "user": user.username,
    }


@themis_blp.get("/findings/false-positives")
@themis_blp.response(200, description="Findings the user has refuted")
@themis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@themis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.THEMIS_READ])
@limiter.limit("120 per hour; 400 per day")
@handle_exceptions(default_exception=ScanError, logger=logger)
def get_false_positives():
    """Los hallazgos que el usuario ha desmentido.

    Cada uno es una muestra etiquetada gratis: dice contra qué check y contra
    qué producto se equivoca el motor. Es la entrada que convierte el marcado
    de falsos positivos en un bucle de mejora en vez de una casilla de
    interfaz — el banco de falsos positivos y el ranking de qué familias fallan
    más se alimentan de aquí.
    """
    user = get_current_user()
    items = LybraEngineManager().false_positives(user.id)
    return {
        "message": "Falsos positivos obtenidos correctamente",
        "count": len(items),
        "falsePositives": items,
        "user": user.username,
    }


@themis_blp.get("/lybra/unresolved-products")
@themis_blp.arguments(UnresolvedProductsQuerySchema, location="query")
@themis_blp.response(200, description="Product names the matcher could not resolve")
@themis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@themis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.THEMIS_READ])
@limiter.limit("120 per hour; 400 per day")
@handle_exceptions(default_exception=ScanError, logger=logger)
def get_unresolved_products(args):
    """Los nombres de producto que el motor no consigue convertir en un CPE.

    Cuando ninguna de las tres estrategias de resolución acierta, el motor no
    inventa un CPE —uno fabricado no casaría con nada, en silencio— pero sí
    apunta el nombre. Cada línea de esta lista es un alias que merece la pena
    escribir, ordenado por cuántas veces ha hecho falta.

    En cuanto el alias existe, el nombre resuelve y desaparece de aquí en el
    siguiente escaneo: la lista mide el trabajo que queda, no el que hubo.
    """
    user = get_current_user()
    items = LybraEngineManager.unresolved_products(args["limit"], args["origin"])
    return {
        "message": "Nombres sin resolver obtenidos correctamente",
        "count": len(items),
        "unresolvedProducts": items,
        "user": user.username,
    }


@themis_blp.get("/kb/status")
@themis_blp.response(200, description="Knowledge-base freshness per source")
@themis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@themis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.THEMIS_READ])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(default_exception=ScanError, logger=logger)
def get_kb_status():
    """Cuándo se sincronizó por última vez cada fuente de la base de conocimiento.

    Toda la detección por versión depende de un espejo local de NVD, KEV y
    EPSS. Si ese espejo deja de refrescarse, los escaneos siguen saliendo en
    verde contra un catálogo congelado y nada lo dice: un CVE publicado ayer no
    existe para el motor, y el informe afirma que el host está limpio.

    Responde a las dos preguntas por separado, porque son distintas: cuándo se
    intentó sincronizar cada fuente y si funcionó, y cuán reciente es lo que
    de hecho sabemos.
    """
    user = get_current_user()
    status = KbSyncManager().status()
    return {
        "message": "Estado de la base de conocimiento obtenido correctamente",
        **status,
        "user": user.username,
    }


@themis_blp.get("/lybra/scans/<int:scan_id>/findings")
@themis_blp.response(200, description="Lybra findings grouped by remediable unit")
@themis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@themis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@themis_blp.alt_response(404, schema=ErrorSchema, description="Scan not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.THEMIS_READ])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(default_exception=ScanNotFoundError, logger=logger)
def get_lybra_grouped_findings(scan_id: int):
    """Hallazgos de un escaneo Lybra, agrupados por la unidad que se remedia.

    El listado (`GET /themis/results`) devuelve los contadores de cada escaneo;
    el detalle está aquí, y se pide al desplegar una tarjeta. Son dos peticiones
    en vez de una porque el detalle no es barato —incluye una consulta a la base
    de conocimiento para resolver la versión corregida— y de los diez escaneos
    de una página el usuario abre uno.
    """
    user = get_current_user()
    result = LybraEngineManager().grouped_findings(scan_id, user.id)
    return {
        "message": "Hallazgos agrupados obtenidos correctamente",
        **result,
        "user": user.username,
    }


@themis_blp.patch("/findings/<int:finding_id>")
@themis_blp.arguments(FindingStateRequestSchema)
@themis_blp.response(200, FindingStateResponseSchema, description="Finding state updated")
@themis_blp.alt_response(400, schema=ErrorSchema, description="Validation error")
@themis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@themis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@themis_blp.alt_response(404, schema=ErrorSchema, description="Finding not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.THEMIS_UPDATE])
@limiter.limit("120 per hour; 400 per day")
@handle_exceptions(default_exception=FindingNotFoundError, logger=logger)
def update_finding_state(data, finding_id: int):
    """Marcar el estado de un hallazgo (p. ej. aceptar un riesgo)."""
    user = get_current_user()
    finding = LybraEngineManager().set_finding_state(
        finding_id, user.id, data["state"], reason=data.get("reason"))
    logger.info(f"Hallazgo {finding_id} marcado como '{data['state']}' por {user.username}")
    return {
        "message": "Estado del hallazgo actualizado correctamente",
        "findingId": finding.id,
        "state": finding.state,
        "user": user.username,
    }


@themis_blp.get("/findings/<int:finding_id>/evidence")
@themis_blp.response(200, description="Raw evidence for a finding")
@themis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@themis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@themis_blp.alt_response(404, schema=ErrorSchema, description="Finding not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.THEMIS_READ])
@limiter.limit("120 per hour; 400 per day")
@handle_exceptions(default_exception=FindingNotFoundError, logger=logger)
def get_finding_evidence(finding_id: int):
    """Devolver la evidencia cruda que respalda un hallazgo (Fase E).

    La respuesta que el objetivo dio y que provocó el hallazgo, redactada, con
    su hash y su fecha — lo que convierte «te lo digo yo» en «míralo». Sólo
    sobre hallazgos propios: uno ajeno se reporta como no encontrado.
    """
    user = get_current_user()
    evidence = LybraEngineManager().get_finding_evidence(finding_id, user.id)
    return {"findingId": finding_id, "evidence": evidence}


@themis_blp.get("/results")
@themis_blp.arguments(ResultsQuerySchema, location="query")
@themis_blp.response(200, ResultsResponseSchema, description="Scan results")
@themis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@themis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.THEMIS_READ])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(default_exception=ScanError, logger=logger)
def retrieve_all_scans(args):
    """Listar todos los escaneos del usuario con paginacion opcional"""
    scan_type = args["type"]
    page = args["page"]
    per_page = args["per_page"]

    user = get_current_user()
    user_id = user.id

    if scan_type != "all":
        manager = ScanManager.get_manager_for_type(scan_type)
        # `assetId` solo lo entiende Lybra (Fase I): es el que separa los
        # escaneos de un agente Hygeia de los lanzados desde el panel.
        if scan_type == "lybra" and args.get("assetId") is not None:
            results, total_count = manager.get_scans_paginated(user_id, page, per_page, asset_id=args["assetId"])
        else:
            results, total_count = manager.get_scans_paginated(user_id, page, per_page)
        total_pages = (total_count + per_page - 1) // per_page

        return {
            "message": "Escaneos obtenidos correctamente",
            "filter": scan_type,
            "count": total_count,
            "results": results,
            "page": page,
            "perPage": per_page,
            "totalCount": total_count,
            "totalPages": total_pages,
            "user": user.username,
        }

    all_results = []
    for manager in ScanManager.all_managers():
        try:
            for scan in manager.get_scans_for_user(user_id):
                all_results.append(manager.format_scan(scan.id, _scan=scan))
        except (OSError, RuntimeError) as exc:
            logger.error(f"Error obteniendo scans: {exc}", exc_info=True)

    return {
        "message": "Escaneos obtenidos correctamente",
        "filter": scan_type,
        "count": len(all_results),
        "results": all_results,
        "user": user.username,
    }


@themis_blp.get("/stats")
@themis_blp.response(200, description="Scan statistics")
@themis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@themis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.THEMIS_READ])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(default_exception=ScanNotFoundError, logger=logger)
def get_scan_stats():
    """Contadores de escaneos por tipo"""
    user = get_current_user()
    return ScanHistoryManager().get_stats(user.id)


@themis_blp.get("/history/hosts")
@themis_blp.response(200, HistoryHostsResponseSchema, description="Scanned hosts")
@themis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@themis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.THEMIS_READ])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(default_exception=ScanNotFoundError, logger=logger)
def list_history_hosts():
    """Listar los hosts escaneados por el usuario (para el selector de estadísticas)"""
    user = get_current_user()
    hosts = ScanHistoryManager().list_scanned_hosts(user.id)
    return {
        "message": "Hosts obtenidos correctamente",
        "hosts": hosts,
        "user": user.username,
    }


@themis_blp.get("/history/stats")
@themis_blp.arguments(HistoryStatsQuerySchema, location="query")
@themis_blp.response(200, HistoryStatsResponseSchema, description="Host historical statistics")
@themis_blp.alt_response(400, schema=ErrorSchema, description="Validation error")
@themis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@themis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.THEMIS_READ])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(default_exception=ScanNotFoundError, logger=logger)
def get_history_stats(args):
    """Estadísticas históricas de un host para los últimos escaneos del usuario"""
    target = args["target"]
    scan_type = ScanType(args["type"])

    user = get_current_user()
    payload = ScanHistoryManager().get_host_history(user.id, target, scan_type)
    payload["message"] = "Estadísticas obtenidas correctamente"
    payload["user"] = user.username
    return payload


@themis_blp.get("/results/<int:scan_id>")
@themis_blp.response(200, ScanDetailResponseSchema, description="Scan detail")
@themis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@themis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@themis_blp.alt_response(404, schema=ErrorSchema, description="Scan not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.THEMIS_READ])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(default_exception=ScanNotFoundError, logger=logger)
def retrieve_scan_by_id(scan_id: int):
    """Detalle completo de un escaneo especifico"""
    user = get_current_user()

    manager, scan = ScanManager.resolve_owned_scan(scan_id, user.id) # type: ignore

    logger.info(f"Obteniendo detalles para escaneo {scan_id} de tipo {scan.scan_type} por usuario {user.username}")
    result = manager.format_scan(scan_id, _scan=scan)

    return {
        "message": "Escaneo obtenido correctamente",
        "result": result,
        "user": user.username,
    }


@themis_blp.get("/scan/<int:scan_id>/traceroute")
@themis_blp.response(200, TracerouteResponseSchema, description="Cached traceroute to the scan target")
@themis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@themis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@themis_blp.alt_response(404, schema=ErrorSchema, description="Scan not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.THEMIS_READ])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(default_exception=ScanNotFoundError, logger=logger)
def get_scan_traceroute(scan_id: int):
    """Traceroute (cacheado) desde el servidor Ellysia hasta el objetivo del escaneo."""
    user = get_current_user()
    payload = TracerouteManager().get_for_scan(scan_id, user.id)  # type: ignore
    payload["message"] = "Traceroute obtenido correctamente"
    payload["user"] = user.username
    return payload


@themis_blp.post("/scan/<int:scan_id>/traceroute/refresh")
@themis_blp.response(200, TracerouteResponseSchema, description="Recomputed traceroute to the scan target")
@themis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@themis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@themis_blp.alt_response(404, schema=ErrorSchema, description="Scan not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.THEMIS_READ])
@limiter.limit("60 per hour; 300 per day")
@handle_exceptions(default_exception=ScanNotFoundError, logger=logger)
def refresh_scan_traceroute(scan_id: int):
    """Fuerza el recálculo del traceroute hasta el objetivo del escaneo."""
    user = get_current_user()
    payload = TracerouteManager().get_for_scan(scan_id, user.id, force_refresh=True)  # type: ignore
    payload["message"] = "Traceroute recalculado correctamente"
    payload["user"] = user.username
    return payload


@themis_blp.get("/is-finished")
@themis_blp.arguments(ScanIdQuerySchema, location="query")
@themis_blp.response(200, IsFinishedResponseSchema, description="Scan finished status")
@themis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@themis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@themis_blp.alt_response(404, schema=ErrorSchema, description="Scan not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.THEMIS_READ])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(default_exception=ScanNotFoundError, logger=logger)
def is_scan_finished(args):
    """Indicar si un escaneo ha finalizado"""
    user = get_current_user()
    scan_id = args["id"]
    manager, scan = ScanManager.resolve_owned_scan(scan_id, user.id)

    is_finished = manager.is_scan_finished(scan.id)

    return {
        "message": f"El escaneo {scan_id} {'esta' if is_finished else 'no esta'} terminado",
        "scanId": scan_id,
        "isFinished": is_finished,
        "scanType": scan.scan_type,
    }


@themis_blp.delete("/<int:scan_id>")
@themis_blp.response(200, ScanResponseSchema, description="Scan deleted")
@themis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@themis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@themis_blp.alt_response(404, schema=ErrorSchema, description="Scan not found")
@themis_blp.alt_response(500, schema=ErrorSchema, description="Deletion failed")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.THEMIS_DELETE])
@limiter.limit("60 per hour; 200 per day")
@handle_exceptions(default_exception=ScanNotFoundError, logger=logger)
def delete_scan(scan_id: int):
    """Eliminar un escaneo del sistema"""
    user = get_current_user()

    manager, scan = ScanManager.resolve_owned_scan(scan_id, user.id) # type: ignore

    if scan.status in CANCELLABLE_STATES:
        logger.info(f"Cancelando escaneo {scan_id} antes de eliminar")
        # La cancelación es cooperativa (solo señaliza al worker, no mata el
        # proceso — ver TaskQueue.cancel): si falla, el subproceso (nmap/nikto)
        # puede seguir vivo. Borrar la fila igualmente lo dejaría
        # huérfano y para siempre invisible para la app, así que no se procede.
        if not manager.cancel_scan(scan_id, user.id): # type: ignore
            raise ScanExecutionError(
                scan_type=scan.scan_type,
                target=scan.target,
                reason="No se pudo cancelar el escaneo en curso; no se ha eliminado para evitar dejar el proceso huérfano",
            )

    if not manager.delete_scan(scan_id):
        raise ScanExecutionError(
            scan_type=scan.scan_type,
            target=scan.target,
            reason="No se pudo eliminar el escaneo",
        )

    logger.info(f"Escaneo {scan.scan_type} {scan_id} eliminado por {user.username}")
    return {
        "message": "Escaneo eliminado correctamente",
        "scanId": scan_id,
        "scanType": scan.scan_type,
        "user": user.username,
    }


@themis_blp.delete("/scans")
@themis_blp.arguments(BulkDeleteScansSchema)
@themis_blp.response(200, BulkDeleteScansResponseSchema, description="Scans bulk deleted")
@themis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@themis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@themis_blp.alt_response(500, schema=ErrorSchema, description="Deletion failed")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.THEMIS_DELETE])
@limiter.limit("30 per hour; 100 per day")
@handle_exceptions(default_exception=ScanNotFoundError, logger=logger)
def bulk_delete_scans(data):
    """Eliminar multiples escaneos de forma masiva"""
    user = get_current_user()
    result = ScanManager.bulk_delete_scans(data["scanIds"], user.id)
    logger.info(f"Bulk delete: {result['deletedCount']} eliminados, {result['failedCount']} fallidos por {user.username}")
    return {
        "message": f"{result['deletedCount']} escaneo(s) eliminado(s), {result['failedCount']} fallido(s)",
        "deletedCount": result["deletedCount"],
        "failedCount": result["failedCount"],
        "results": result["results"],
        "user": user.username,
    }


@themis_blp.post("/generate-pdf")
@themis_blp.arguments(GeneratePdfRequestSchema)
@themis_blp.response(202, PdfGenerateResponseSchema, description="PDF generation started")
@themis_blp.alt_response(400, schema=ErrorSchema, description="Scan not finished")
@themis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@themis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.THEMIS_CREATE])
@limiter.limit("30 per hour; 100 per day")
@handle_exceptions(default_exception=ScanNotFoundError, logger=logger)
def generate_pdf(args):
    """Solicitar generacion asincrona de un PDF"""
    scan_id = args["id"]
    ai_report = args["aiReport"]

    user = get_current_user()
    user_id = user.id

    manager, _scan = ScanManager.resolve_owned_scan(scan_id, user_id)

    if not manager.is_scan_finished(scan_id):
        raise ValidationError(
            field="scan_id",
            message=f"El escaneo {scan_id} no esta finalizado aun",
            value=scan_id,
        )

    doc_mgr = ThemisReportManager()
    doc_id = doc_mgr.generate_report(
        scan_id=scan_id,
        ai_report=ai_report,
    )
    logger.info(f"Generacion de PDF solicitada para escaneo {scan_id} (documento {doc_id}) por usuario {user.username} con AI Report: {ai_report}")

    return {
        "message": "Generacion de PDF iniciada",
        "documentId": doc_id,
        "scanId": scan_id,
        "status": "pending",
        "aiReport": ai_report,
        "downloadUrl": f"/themis/document/{doc_id}/download",
    }


@themis_blp.get("/document-status")
@themis_blp.arguments(DocumentStatusQuerySchema, location="query")
@themis_blp.response(200, DocumentStatusResponseSchema, description="Document status")
@themis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@themis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@themis_blp.alt_response(404, schema=ErrorSchema, description="Document not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.THEMIS_READ])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(default_exception=ScanNotFoundError, logger=logger)
def get_document_status(args):
    """Consultar estado de generacion de un documento"""
    user = get_current_user()
    document_id = args.get("document_id")
    scan_id = args.get("scan_id")

    doc_mgr = ThemisReportManager()

    # N1/E4: lookup dual (por document_id o, si no, el último documento del
    # scan) + verificación de ownership viven en el manager, no aquí.
    # not_found_error=ScanNotFoundError preserva el 404 propio de este
    # endpoint (assert_document_ownership usa el DocumentError genérico de
    # 500, con otro propósito — ver el docstring de get_document_status).
    document = doc_mgr.get_document_status(document_id, scan_id, user.id, not_found_error=ScanNotFoundError)

    return {
        "documentId": document.id,
        "scanId": document.scan_id,
        "status": document.status,
        "aiReport": document.enrichment_json is not None,
        "createdAt": document.created_at if document.created_at else None,
        "generatedAt": document.generated_at if document.generated_at else None,
        "downloadUrl": _download_url_for(document),
    }


@themis_blp.get("/documents")
@themis_blp.arguments(DocumentsQuerySchema, location="query")
@themis_blp.response(200, DocumentListResponseSchema, description="All documents")
@themis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@themis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.THEMIS_READ])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(default_exception=DocumentError, logger=logger)
def get_all_documents(args):
    """Obtener todos los documentos del usuario"""
    user = get_current_user()
    scan_type_filter = args["scan_type"]

    doc_mgr = ThemisReportManager()
    documents = doc_mgr.get_documents_for_user(user.id)

    if scan_type_filter != "all":
        documents = [document for document in documents if document.scan_type == scan_type_filter]

    docs_list = [_serialize_document(document) for document in documents]

    return {
        "documents": docs_list,
        "total": len(docs_list),
        "filter": scan_type_filter,
    }


@themis_blp.get("/scan/<int:scan_id>/documents")
@themis_blp.response(200, ScanDocumentsResponseSchema, description="Scan documents")
@themis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@themis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@themis_blp.alt_response(404, schema=ErrorSchema, description="Scan not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.THEMIS_READ])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(default_exception=DocumentError, logger=logger)
def get_documents_by_scan(scan_id: int):
    """Obtener todos los documentos de un escaneo concreto"""
    user = get_current_user()

    # N1: verificar ownership del escaneo antes de listar sus documentos.
    # Sin esto, cualquier usuario con THEMIS_READ puede enumerar los
    # documentos (ids, fechas, estado, downloadUrl) de escaneos ajenos.
    ScanManager.resolve_owned_scan(scan_id, user.id) # type: ignore

    doc_mgr = ThemisReportManager()
    documents = doc_mgr.get_documents_by_parent(scan_id)

    docs_list = [_serialize_document(document) for document in documents]

    return {
        "scanId": scan_id,
        "documents": docs_list,
        "total": len(docs_list),
    }


@themis_blp.get("/document/<int:document_id>/download")
@themis_blp.response(200, description="PDF file download")
@themis_blp.alt_response(400, schema=ErrorSchema, description="Document not ready")
@themis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@themis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@themis_blp.alt_response(404, schema=ErrorSchema, description="Document not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.THEMIS_READ])
@handle_exceptions(default_exception=DocumentError, logger=logger)
def download_document(document_id: int):
    """Descargar un documento PDF generado"""
    user = get_current_user()
    user_id = user.id
    logger.info(f"Download request for document {document_id} by user {user_id}")

    doc_mgr = ThemisReportManager()
    doc_mgr.assert_document_ownership(document_id, user_id) # type: ignore

    document = doc_mgr.get_document_by_id(document_id)
    if not document:
        logger.warning(f"Document {document_id} not found or access denied for user {user_id}")
        raise DocumentNotFoundError(document_id)

    if document.status != "done" or not document.filename or not os.path.exists(document.filename):
        logger.warning(f"Document {document_id} not ready: status={document.status}, filename={document.filename}")
        raise DocumentNotReadyError(document_id, document.status)

    logger.info(f"Serving document {document_id}: {document.filename}")
    return send_file(
        document.filename,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"{document.scan_type}_scan_{document.scan_id}.pdf",
    )


@themis_blp.delete("/document/<int:document_id>")
@themis_blp.response(200, DocumentDeleteResponseSchema, description="Document deleted")
@themis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@themis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@themis_blp.alt_response(404, schema=ErrorSchema, description="Document not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.THEMIS_DELETE])
@limiter.limit("30 per hour; 100 per day")
@handle_exceptions(default_exception=DocumentError, logger=logger)
def delete_document(document_id: int):
    """Eliminar un documento"""
    user = get_current_user()
    user_id = user.id

    doc_mgr = ThemisReportManager()
    doc_mgr.assert_document_ownership(document_id, user_id) # type: ignore
    doc_mgr.delete_document(document_id)
    logger.info(f"Documento {document_id} eliminado por usuario {user_id}")
    return {"message": "Documento eliminado correctamente", "documentId": document_id}


@themis_blp.post("/scheduled-scans")
@themis_blp.arguments(ScheduledScanRequestSchema)
@themis_blp.response(201, ScheduledScanResponseSchema, description="Scheduled scan created")
@themis_blp.alt_response(400, schema=ErrorSchema, description="Validation error")
@themis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@themis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.THEMIS_SCHEDULE_CREATE])
@limiter.limit("30 per hour; 100 per day")
@handle_exceptions(default_exception=ProgramedScanError, logger=logger)
def schedule_scan(data):
    """Crear un escaneo programado"""
    scan_type_str = data["scan_type"].lower()
    valid_types = {scan_type.value for scan_type in ScanType}
    if scan_type_str not in valid_types:
        raise ValidationError(
            field="scan_type",
            message="Tipo de escaneo invalido",
            value=scan_type_str,
            expected=", ".join(sorted(valid_types)),
        )
    user = get_current_user()
    programed_scan = ProgramedScanManager.register(
        user_id=user.id,
        scan_type=ScanType(scan_type_str),
        arguments=data["arguments"],
        schedule_type=data["schedule_type"],
        schedule_config=data["schedule_config"],
    )
    logger.info(
        f"Escaneo programado {programed_scan.id} creado: tipo={scan_type_str} "
        f"programacion={data['schedule_type']} usuario={user.username}"
    )
    return {
        "message": "Escaneo programado creado correctamente",
        "programedScanId": programed_scan.id,
        "scanType": scan_type_str,
        "scheduleType": data["schedule_type"],
        "scheduleConfig": data["schedule_config"],
        "nextRunAt": programed_scan.next_run_at if programed_scan.next_run_at else None,
        "user": user.username,
    }


@themis_blp.delete("/scheduled-scans/<int:programed_scan_id>")
@themis_blp.response(200, ScheduledScanActionResponseSchema, description="Scheduled scan revoked")
@themis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@themis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@themis_blp.alt_response(404, schema=ErrorSchema, description="Not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.THEMIS_SCHEDULE_DELETE])
@limiter.limit("60 per hour; 200 per day")
@handle_exceptions(default_exception=ProgramedScanNotFoundError, logger=logger)
def revoke_scheduled_scan(programed_scan_id: int):
    """Revocar un escaneo programado (desactivar)"""
    user = get_current_user()
    programed_scan = ProgramedScanManager.assert_ownership(programed_scan_id, user.id) # type: ignore
    ProgramedScanManager.revoke(programed_scan_id, user.id) # type: ignore
    logger.info(f"Escaneo programado {programed_scan_id} revocado por {user.username}")
    return {
        "message": "Escaneo programado revocado correctamente",
        "programedScanId": programed_scan_id,
        "scanType": programed_scan.scan_type,
        "user": user.username,
    }


@themis_blp.delete("/scheduled-scans/<int:programed_scan_id>/permanent")
@themis_blp.response(200, ScheduledScanActionResponseSchema, description="Scheduled scan permanently deleted")
@themis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@themis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@themis_blp.alt_response(404, schema=ErrorSchema, description="Not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.THEMIS_SCHEDULE_DELETE])
@limiter.limit("30 per hour; 100 per day")
@handle_exceptions(default_exception=ProgramedScanNotFoundError, logger=logger)
def delete_scheduled_scan(programed_scan_id: int):
    """Eliminar permanentemente un escaneo programado de la BD"""
    user = get_current_user()
    programed_scan = ProgramedScanManager.assert_ownership(programed_scan_id, user.id) # type: ignore
    ProgramedScanManager.delete(programed_scan_id, user.id) # type: ignore
    logger.info(f"Escaneo programado {programed_scan_id} eliminado permanentemente por {user.username}")
    return {
        "message": "Escaneo programado eliminado permanentemente",
        "programedScanId": programed_scan_id,
        "scanType": programed_scan.scan_type,
        "user": user.username,
    }


@themis_blp.get("/scheduled-scans")
@themis_blp.response(200, ScheduledScanListResponseSchema, description="List of scheduled scans")
@themis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@themis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@limiter.limit("300 per hour; 2000 per day")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.THEMIS_SCHEDULE_READ])
@handle_exceptions(default_exception=ProgramedScanError, logger=logger)
def list_scheduled_scans():
    """Listar todos los escaneos programados del usuario"""
    user = get_current_user()
    scans = ProgramedScanManager.get_scans_for_user(user.id)
    results = [
        {
            "id": programed_scan.id,
            "scanType": programed_scan.scan_type,
            "arguments": programed_scan.arguments,
            "scheduleType": programed_scan.schedule_type,
            "scheduleConfig": programed_scan.schedule_config,
            "isActive": programed_scan.is_active,
            "lastRunAt": programed_scan.last_run_at if programed_scan.last_run_at else None,
            "nextRunAt": programed_scan.next_run_at if programed_scan.next_run_at else None,
            "createdAt": programed_scan.created_at if programed_scan.created_at else None,
        }
        for programed_scan in scans
    ]
    return {
        "message": "Escaneos programados obtenidos correctamente",
        "count": len(results),
        "scheduledScans": results,
        "user": user.username,
    }


# =========================================================================
# SCAN FOLDERS
# =========================================================================

@themis_blp.post("/folders")
@themis_blp.arguments(CreateFolderSchema)
@themis_blp.response(201, FolderActionResponseSchema, description="Folder created")
@themis_blp.alt_response(400, schema=ErrorSchema, description="Validation error")
@themis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@themis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.THEMIS_FOLDER_CREATE])
@limiter.limit("60 per hour; 200 per day")
@handle_exceptions(default_exception=FolderNameInvalidError, logger=logger)
def create_folder(data):
    """Crear una nueva carpeta de escaneos"""
    user = get_current_user()
    folder = ScanFolderManager().create_folder(user.id, data["name"])
    logger.info(f"Carpeta {folder.id} creada por {user.username}")
    return {
        "message": "Carpeta creada correctamente",
        "folderId": folder.id,
        "name": folder.name,
        "user": user.username,
    }


@themis_blp.get("/folders")
@themis_blp.response(200, FolderListResponseSchema, description="User folders with scans")
@themis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@themis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.THEMIS_FOLDER_READ])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(default_exception=FolderNotFoundError, logger=logger)
def list_folders():
    """Listar todas las carpetas del usuario con sus escaneos completos"""
    user = get_current_user()
    result = ScanFolderManager().get_folders_with_scans(user.id)
    logger.info(f"Carpetas obtenidas para usuario {user.username}")
    return {
        "message": "Carpetas obtenidas correctamente",
        "folders": result["folders"],
        "unfoldered": result["unfoldered"],
        "user": user.username,
    }


@themis_blp.put("/folders/<int:folder_id>")
@themis_blp.arguments(RenameFolderSchema)
@themis_blp.response(200, FolderActionResponseSchema, description="Folder renamed")
@themis_blp.alt_response(400, schema=ErrorSchema, description="Validation error")
@themis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@themis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@themis_blp.alt_response(404, schema=ErrorSchema, description="Folder not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.THEMIS_FOLDER_UPDATE])
@limiter.limit("60 per hour; 200 per day")
@handle_exceptions(default_exception=FolderNotFoundError, logger=logger)
def rename_folder(data, folder_id: int):
    """Renombrar una carpeta existente"""
    user = get_current_user()
    folder = ScanFolderManager().rename_folder(folder_id, user.id, data["name"])  # type: ignore
    logger.info(f"Carpeta {folder_id} renombrada por {user.username}")
    return {
        "message": "Carpeta renombrada correctamente",
        "folderId": folder.id,
        "name": folder.name,
        "user": user.username,
    }


@themis_blp.delete("/folders/<int:folder_id>")
@themis_blp.response(200, FolderActionResponseSchema, description="Folder deleted")
@themis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@themis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@themis_blp.alt_response(404, schema=ErrorSchema, description="Folder not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.THEMIS_FOLDER_DELETE])
@limiter.limit("60 per hour; 200 per day")
@handle_exceptions(default_exception=FolderNotFoundError, logger=logger)
def delete_folder(folder_id: int):
    """Eliminar una carpeta (los escaneos quedan sin carpeta)"""
    user = get_current_user()
    ScanFolderManager().delete_folder(folder_id, user.id)  # type: ignore
    logger.info(f"Carpeta {folder_id} eliminada por {user.username}")
    return {
        "message": "Carpeta eliminada correctamente",
        "folderId": folder_id,
        "user": user.username,
    }


@themis_blp.post("/folders/<int:folder_id>/scans")
@themis_blp.arguments(MoveScanToFolderSchema)
@themis_blp.response(200, ScanFolderActionResponseSchema, description="Scan moved to folder")
@themis_blp.alt_response(400, schema=ErrorSchema, description="Validation error")
@themis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@themis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@themis_blp.alt_response(404, schema=ErrorSchema, description="Folder or scan not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.THEMIS_FOLDER_UPDATE])
@limiter.limit("120 per hour; 400 per day")
@handle_exceptions(default_exception=ScanNotFoundError, logger=logger)
def move_scan_to_folder(data, folder_id: int):
    """Añadir o mover un escaneo a una carpeta"""
    user = get_current_user()
    scan = ScanFolderManager().move_scan_to_folder(data["scanId"], folder_id, user.id)  # type: ignore
    logger.info(f"Escaneo {scan.id} movido a carpeta {folder_id} por {user.username}")
    return {
        "message": "Escaneo añadido a la carpeta correctamente",
        "scanId": scan.id,
        "folderId": folder_id,
        "user": user.username,
    }


@themis_blp.post("/folders/<int:folder_id>/scans/batch")
@themis_blp.arguments(AddScansToFolderSchema)
@themis_blp.response(200, ScanFolderActionResponseSchema, description="Scans added to folder")
@themis_blp.alt_response(400, schema=ErrorSchema, description="Validation error")
@themis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@themis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@themis_blp.alt_response(404, schema=ErrorSchema, description="Folder or scan not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.THEMIS_FOLDER_UPDATE])
@limiter.limit("60 per hour; 200 per day")
@handle_exceptions(default_exception=ScanNotFoundError, logger=logger)
def add_scans_to_folder(data, folder_id: int):
    """Añadir varios escaneos a una carpeta de una sola vez"""
    user = get_current_user()
    scans = ScanFolderManager().add_scans_to_folder(data["scanIds"], folder_id, user.id)
    logger.info(f"{len(scans)} escaneos añadidos a carpeta {folder_id} por {user.username}")
    return {
        "message": f"{len(scans)} escaneo(s) añadido(s) a la carpeta correctamente",
        "scanId": scans[0].id if scans else None,
        "folderId": folder_id,
        "user": user.username,
    }


@themis_blp.delete("/folders/<int:folder_id>/scans/<int:scan_id>")
@themis_blp.response(200, ScanFolderActionResponseSchema, description="Scan removed from folder")
@themis_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@themis_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@themis_blp.alt_response(404, schema=ErrorSchema, description="Scan not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.THEMIS_FOLDER_UPDATE])
@limiter.limit("120 per hour; 400 per day")
@handle_exceptions(default_exception=ScanNotFoundError, logger=logger)
def remove_scan_from_folder(folder_id: int, scan_id: int):
    """Sacar un escaneo de una carpeta (lo deja sin carpeta)"""
    user = get_current_user()
    ScanFolderManager().remove_scan_from_folder(scan_id, user.id)  # type: ignore
    logger.info(f"Escaneo {scan_id} sacado de carpeta {folder_id} por {user.username}")
    return {
        "message": "Escaneo eliminado de la carpeta correctamente",
        "scanId": scan_id,
        "folderId": None,
        "user": user.username,
    }
