from __future__ import annotations

import logging
import os
import ipaddress

from flask import request, send_file
from flask_smorest import Blueprint as SmorestBlueprint

from src.modules.users import require_oauth_token, require_attributes, AttributeType, get_current_user
from src.modules.shared import (
    handle_exceptions,
    limiter,
)
from src.modules.shared._exceptions import (
    ValidationError,
    IllegalStateError,
    SecOpsException,
)
from src.modules.shared.schemas import ErrorSchema
from src.modules.aegis.exceptions import DocumentError, DocumentNotFoundError, DocumentNotReadyError

from .managers import (
    ScanManager,
    NmapScanManager,
    NiktoScanManager,
    OpenVASScanManager,
    EllysiaEngineManager,
    ProgramedScanManager,
    SentinelReportManager,
    ScanFolderManager,
    ScanHistoryManager,
    TracerouteManager,
)
from .model import ScanType
from .exceptions import (
    ScanError,
    ScanExecutionError,
    ScanNotFoundError,
    FindingNotFoundError,
    IPValidationError,
    MaxHostsExceededError,
    PortValidationError,
    PrivateIPRequested,
    ProgramedScanError,
    ProgramedScanNotFoundError,
    FolderNotFoundError,
    FolderNameInvalidError,
    ScanAlreadyInFolderError,
)
from .schemas import (
    ScanIdQuerySchema,
    NmapScanRequestSchema,
    NiktoScanRequestSchema,
    OpenVASScanRequestSchema,
    EllysiaScanRequestSchema,
    FindingStateRequestSchema,
    FindingStateResponseSchema,
    ResultsQuerySchema,
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


sentinel_blp = SmorestBlueprint(
    "sentinel", __name__,
    description="Escaneos de seguridad (Nmap, Nikto, OpenVAS) y PDFs"
)
logger = logging.getLogger(__name__)

CANCELLABLE_STATES = frozenset({"pending", "running"})
MAX_PDF_SIZE_BYTES = 50 * 1024 * 1024


def validate_targets(raw: str, max_hosts: int = 10) -> list[str]:
    """
    Validate ``raw`` as a target spec via ``ScanManager.validate_ip``,
    translating its domain exceptions into the HTTP-facing ones.
    """
    try:
        return ScanManager.validate_ip(raw, max_hosts=max_hosts)
    except IPValidationError as exc:
        raise ValidationError(field="target", message=str(exc), value=raw) from exc
    except MaxHostsExceededError as exc:
        raise ValidationError(str(exc.user_message or exc))
    except PrivateIPRequested as exc:
        raise SecOpsException(str(exc.user_message or exc), status_code=403)


@sentinel_blp.get("/scan-status")
@sentinel_blp.arguments(ScanIdQuerySchema, location="query")
@sentinel_blp.response(200, ScanStatusResponseSchema, description="Scan status")
@sentinel_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@sentinel_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@sentinel_blp.alt_response(404, schema=ErrorSchema, description="Scan not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_READ])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(default_exception=ScanNotFoundError, logger=logger)
def get_scan_status(args):
    """Estado y progreso de un escaneo"""
    scan_id = args["id"]
    user = get_current_user()
    manager, scan = ScanManager.resolve_owned_scan(scan_id, user.id) # type: ignore

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


@sentinel_blp.post("/scans/<int:scan_id>/cancel")
@sentinel_blp.response(200, ScanResponseSchema, description="Scan cancelled")
@sentinel_blp.alt_response(400, schema=ErrorSchema, description="Invalid state")
@sentinel_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@sentinel_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@sentinel_blp.alt_response(500, schema=ErrorSchema, description="Cancellation failed")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_UPDATE])
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

    scan = manager.get_scan_by_id(scan_id)
    if not scan:
        raise ScanNotFoundError(scan_id)

    logger.info(f"Escaneo {scan.scan_type} {scan_id} cancelado por {user.username}")
    return {
        "message": "Escaneo cancelado exitosamente",
        "scanId": scan_id,
        "scanType": scan.scan_type,
        "status": scan.status,
        "user": user.username,
    }


@sentinel_blp.post("/nmap")
@sentinel_blp.arguments(NmapScanRequestSchema)
@sentinel_blp.response(201, NmapScanResponseSchema, description="Nmap scan started")
@sentinel_blp.alt_response(400, schema=ErrorSchema, description="Validation error")
@sentinel_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@sentinel_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_CREATE])
@limiter.limit("20 per hour; 100 per day")
@handle_exceptions(default_exception=ScanExecutionError, logger=logger)
def start_nmap_scan(data: dict):
    """Lanzar uno o mas escaneos Nmap (soporta rangos CIDR)"""
    host = data["target"]
    ports = data["ports"]
    timeout = data["timeout"]
    user = get_current_user()

    nmap_manager = NmapScanManager()
    hosts = validate_targets(host)

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


@sentinel_blp.post("/nikto")
@sentinel_blp.arguments(NiktoScanRequestSchema)
@sentinel_blp.response(201, ScanResponseSchema, description="Nikto scan started")
@sentinel_blp.alt_response(400, schema=ErrorSchema, description="Validation error")
@sentinel_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@sentinel_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@limiter.limit("20 per hour; 100 per day")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_CREATE])
@handle_exceptions(default_exception=ScanExecutionError, logger=logger)
def start_nikto_scan(data):
    """Lanzar un escaneo Nikto"""
    target = data["target"]
    timeout = data["timeout"]
    user = get_current_user()

    nikto_manager = NiktoScanManager()
    scan_id = nikto_manager.run_scan(target, user_id=user.id, timeout=timeout) # type: ignore
    logger.info(f"Nikto lanzado: ID={scan_id} target={target} timeout={timeout} user={user.username}")
    return {
        "message": "Escaneo Nikto iniciado correctamente",
        "scanId": scan_id,
        "target": target,
        "timeout": timeout,
        "user": user.username,
    }


@sentinel_blp.post("/openvas")
@sentinel_blp.arguments(OpenVASScanRequestSchema)
@sentinel_blp.response(201, ScanResponseSchema, description="OpenVAS scan started")
@sentinel_blp.alt_response(400, schema=ErrorSchema, description="Validation error")
@sentinel_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@sentinel_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@limiter.limit("10 per hour; 50 per day")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_CREATE])
@handle_exceptions(default_exception=ScanExecutionError, logger=logger)
def start_openvas_scan(data):
    """Lanzar un escaneo OpenVAS para un unico host"""
    target = data["target"]
    scan_config = data["scanConfig"]
    user = get_current_user()
    if user is None:
        raise IllegalStateError("'user' detectado como None")

    hosts = validate_targets(target, max_hosts=1)

    openvas_manager = OpenVASScanManager()
    target_ip = hosts[0]
    ipaddress.ip_address(target_ip)

    scan_id = openvas_manager.run_scan(
        target=target_ip,
        scan_config=scan_config,
        user_id=user.id,
        skip_normalize=True,
    )
    logger.info(f"OpenVAS lanzado: ID={scan_id} target={target_ip} config={scan_config} user={user.username}")

    return {
        "message": "Escaneo OpenVAS iniciado correctamente",
        "scanId": scan_id,
        "target": target_ip,
        "scanConfig": scan_config,
        "user": user.username,
        "note": "Use /sentinel/scan-status para verificar el progreso.",
    }


@sentinel_blp.post("/ellysia")
@sentinel_blp.arguments(EllysiaScanRequestSchema)
@sentinel_blp.response(201, ScanResponseSchema, description="Ellysia engine scan started")
@sentinel_blp.alt_response(400, schema=ErrorSchema, description="Validation error")
@sentinel_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@sentinel_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@sentinel_blp.alt_response(404, schema=ErrorSchema, description="Source scan not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_CREATE])
@limiter.limit("20 per hour; 100 per day")
@handle_exceptions(default_exception=ScanExecutionError, logger=logger)
def start_ellysia_scan(data):
    """Lanzar un escaneo Ellysia sobre los servicios de un Nmap previo"""
    source_scan_id = data["sourceScanId"]
    timeout = data["timeout"]
    user = get_current_user()

    # El escaneo fuente debe existir, ser del usuario y ser un Nmap (la fase
    # actual de Ellysia analiza los servicios que Nmap ya descubrió).
    source_scan = ScanManager.assert_scan_ownership(source_scan_id, user.id)
    if source_scan.scan_type != ScanType.NMAP.value:
        raise ValidationError(
            field="sourceScanId",
            message="El escaneo fuente debe ser un escaneo Nmap",
            value=source_scan_id,
        )

    scan_id = EllysiaEngineManager().run_scan(
        source_scan_id=source_scan_id,
        user_id=user.id,
        timeout=timeout,
    )
    logger.info(f"Ellysia lanzado: ID={scan_id} fuente={source_scan_id} user={user.username}")
    return {
        "message": "Escaneo Ellysia iniciado correctamente",
        "scanId": scan_id,
        "scanType": "ellysia",
        "user": user.username,
    }


@sentinel_blp.patch("/findings/<int:finding_id>")
@sentinel_blp.arguments(FindingStateRequestSchema)
@sentinel_blp.response(200, FindingStateResponseSchema, description="Finding state updated")
@sentinel_blp.alt_response(400, schema=ErrorSchema, description="Validation error")
@sentinel_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@sentinel_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@sentinel_blp.alt_response(404, schema=ErrorSchema, description="Finding not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_UPDATE])
@limiter.limit("120 per hour; 400 per day")
@handle_exceptions(default_exception=FindingNotFoundError, logger=logger)
def update_finding_state(data, finding_id: int):
    """Marcar el estado de un hallazgo (p. ej. aceptar un riesgo)."""
    user = get_current_user()
    finding = EllysiaEngineManager().set_finding_state(finding_id, user.id, data["state"])
    logger.info(f"Hallazgo {finding_id} marcado como '{data['state']}' por {user.username}")
    return {
        "message": "Estado del hallazgo actualizado correctamente",
        "findingId": finding.id,
        "state": finding.state,
        "user": user.username,
    }


@sentinel_blp.get("/results")
@sentinel_blp.arguments(ResultsQuerySchema, location="query")
@sentinel_blp.response(200, ResultsResponseSchema, description="Scan results")
@sentinel_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@sentinel_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_READ])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(default_exception=ScanError, logger=logger)
def retrieve_all_scans(args):
    """Listar todos los escaneos del usuario con paginacion opcional"""
    scan_type = args["type"]
    page = args["page"]
    per_page = args["per_page"]

    user = get_current_user()
    uid = user.id

    TYPE_MGR_MAP = {
        "nmap": NmapScanManager(),
        "nikto": NiktoScanManager(),
        "openvas": OpenVASScanManager(),
        "ellysia": EllysiaEngineManager(),
    }

    if scan_type != "all":
        mgr = TYPE_MGR_MAP[scan_type]
        results, total_count = mgr.get_scans_paginated(uid, page, per_page)
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
    for mgr in TYPE_MGR_MAP.values():
        try:
            for scan in mgr.get_scans_for_user(uid):
                all_results.append(mgr.format_scan(scan.id))
        except (OSError, RuntimeError) as exc:
            logger.error(f"Error obteniendo scans: {exc}", exc_info=True)

    return {
        "message": "Escaneos obtenidos correctamente",
        "filter": scan_type,
        "count": len(all_results),
        "results": all_results,
        "user": user.username,
    }


@sentinel_blp.get("/stats")
@sentinel_blp.response(200, description="Scan statistics")
@sentinel_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@sentinel_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_READ])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(default_exception=ScanNotFoundError, logger=logger)
def get_scan_stats():
    """Contadores de escaneos por tipo"""
    from src.modules.infrastructure.session import get_db_session
    from .repositories import ScanRepository as _ScanRepo
    user = get_current_user()
    session = get_db_session()
    repo = _ScanRepo(session=session)
    stats = repo.get_stats(user.id)
    return stats


@sentinel_blp.get("/history/hosts")
@sentinel_blp.response(200, HistoryHostsResponseSchema, description="Scanned hosts")
@sentinel_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@sentinel_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_READ])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(default_exception=ScanNotFoundError, logger=logger)
def list_history_hosts():
    """Listar los hosts escaneados por el usuario (para el selector de estadísticas)"""
    user = get_current_user()
    hosts = ScanHistoryManager().list_scanned_hosts(user.id)  # type: ignore
    return {
        "message": "Hosts obtenidos correctamente",
        "hosts": hosts,
        "user": user.username,
    }


@sentinel_blp.get("/history/stats")
@sentinel_blp.arguments(HistoryStatsQuerySchema, location="query")
@sentinel_blp.response(200, HistoryStatsResponseSchema, description="Host historical statistics")
@sentinel_blp.alt_response(400, schema=ErrorSchema, description="Validation error")
@sentinel_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@sentinel_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_READ])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(default_exception=ScanNotFoundError, logger=logger)
def get_history_stats(args):
    """Estadísticas históricas de un host para los últimos escaneos del usuario"""
    target = args["target"]
    scan_type = ScanType(args["type"])

    user = get_current_user()
    payload = ScanHistoryManager().get_host_history(user.id, target, scan_type)  # type: ignore
    payload["message"] = "Estadísticas obtenidas correctamente"
    payload["user"] = user.username
    return payload


@sentinel_blp.get("/results/<int:scan_id>")
@sentinel_blp.response(200, ScanDetailResponseSchema, description="Scan detail")
@sentinel_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@sentinel_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@sentinel_blp.alt_response(404, schema=ErrorSchema, description="Scan not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_READ])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(default_exception=ScanNotFoundError, logger=logger)
def retrieve_scan_by_id(scan_id: int):
    """Detalle completo de un escaneo especifico"""
    user = get_current_user()

    manager, scan = ScanManager.resolve_owned_scan(scan_id, user.id) # type: ignore

    logger.info(f"Obteniendo detalles para escaneo {scan_id} de tipo {scan.scan_type} por usuario {user.username}")
    result = manager.format_scan(scan_id)
    if scan.scan_type == "nmap": # type: ignore
        result["openPorts"] = [{
            "port": f"{p.port_id}/{p.port.protocol}",
            "reason": p.reason,
            "product": p.product,
            "version": p.version,
        } for p in scan.open_ports_relation]
    elif scan.scan_type == "openvas": # type: ignore
        result["severityBreakdown"] = {
            "critical": sum(1 for r in scan.results if r.vulnerability.severity_class == "Critical"),
            "high": sum(1 for r in scan.results if r.vulnerability.severity_class == "High"),
            "medium": sum(1 for r in scan.results if r.vulnerability.severity_class == "Medium"),
            "low": sum(1 for r in scan.results if r.vulnerability.severity_class == "Low"),
            "info": sum(1 for r in scan.results if r.vulnerability.severity_class == "Log"),
        }

    return {
        "message": "Escaneo obtenido correctamente",
        "result": result,
        "user": user.username,
    }


@sentinel_blp.get("/scan/<int:scan_id>/traceroute")
@sentinel_blp.response(200, TracerouteResponseSchema, description="Cached traceroute to the scan target")
@sentinel_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@sentinel_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@sentinel_blp.alt_response(404, schema=ErrorSchema, description="Scan not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_READ])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(default_exception=ScanNotFoundError, logger=logger)
def get_scan_traceroute(scan_id: int):
    """Traceroute (cacheado) desde el servidor Ellysia hasta el objetivo del escaneo."""
    user = get_current_user()
    payload = TracerouteManager().get_for_scan(scan_id, user.id)  # type: ignore
    payload["message"] = "Traceroute obtenido correctamente"
    payload["user"] = user.username
    return payload


@sentinel_blp.post("/scan/<int:scan_id>/traceroute/refresh")
@sentinel_blp.response(200, TracerouteResponseSchema, description="Recomputed traceroute to the scan target")
@sentinel_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@sentinel_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@sentinel_blp.alt_response(404, schema=ErrorSchema, description="Scan not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_READ])
@limiter.limit("60 per hour; 300 per day")
@handle_exceptions(default_exception=ScanNotFoundError, logger=logger)
def refresh_scan_traceroute(scan_id: int):
    """Fuerza el recálculo del traceroute hasta el objetivo del escaneo."""
    user = get_current_user()
    payload = TracerouteManager().get_for_scan(scan_id, user.id, force_refresh=True)  # type: ignore
    payload["message"] = "Traceroute recalculado correctamente"
    payload["user"] = user.username
    return payload


@sentinel_blp.get("/is-finished")
@sentinel_blp.arguments(ScanIdQuerySchema, location="query")
@sentinel_blp.response(200, IsFinishedResponseSchema, description="Scan finished status")
@sentinel_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@sentinel_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@sentinel_blp.alt_response(404, schema=ErrorSchema, description="Scan not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_READ])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(default_exception=ScanNotFoundError, logger=logger)
def is_scan_finished(args):
    """Indicar si un escaneo ha finalizado"""
    user = get_current_user()
    scan_id = args["id"]
    manager, scan = ScanManager.resolve_owned_scan(scan_id, user.id) # type: ignore

    finished = manager.is_scan_finished(scan.id) # type: ignore

    return {
        "message": f"El escaneo {scan_id} {'esta' if finished else 'no esta'} terminado",
        "scanId": scan_id,
        "isFinished": finished,
        "scanType": scan.scan_type,
    }


@sentinel_blp.delete("/<int:scan_id>")
@sentinel_blp.response(200, ScanResponseSchema, description="Scan deleted")
@sentinel_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@sentinel_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@sentinel_blp.alt_response(404, schema=ErrorSchema, description="Scan not found")
@sentinel_blp.alt_response(500, schema=ErrorSchema, description="Deletion failed")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_DELETE])
@limiter.limit("60 per hour; 200 per day")
@handle_exceptions(default_exception=ScanNotFoundError, logger=logger)
def delete_scan(scan_id: int):
    """Eliminar un escaneo del sistema"""
    user = get_current_user()

    manager, scan = ScanManager.resolve_owned_scan(scan_id, user.id) # type: ignore

    if scan.status in CANCELLABLE_STATES:
        logger.info(f"Cancelando escaneo {scan_id} antes de eliminar")
        manager.cancel_scan(scan_id, user.id) # type: ignore

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


@sentinel_blp.delete("/scans")
@sentinel_blp.arguments(BulkDeleteScansSchema)
@sentinel_blp.response(200, BulkDeleteScansResponseSchema, description="Scans bulk deleted")
@sentinel_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@sentinel_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@sentinel_blp.alt_response(500, schema=ErrorSchema, description="Deletion failed")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_DELETE])
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


@sentinel_blp.post("/generate-pdf")
@sentinel_blp.arguments(GeneratePdfRequestSchema)
@sentinel_blp.response(202, PdfGenerateResponseSchema, description="PDF generation started")
@sentinel_blp.alt_response(400, schema=ErrorSchema, description="Scan not finished")
@sentinel_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@sentinel_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_CREATE])
@limiter.limit("30 per hour; 100 per day")
@handle_exceptions(default_exception=ScanNotFoundError, logger=logger)
def generate_pdf(args):
    """Solicitar generacion asincrona de un PDF"""
    scan_id = args["id"]
    ai_report = args["aiReport"]

    user = get_current_user()
    uid = user.id

    manager, _scan = ScanManager.resolve_owned_scan(scan_id, uid) # type: ignore

    if not manager.is_scan_finished(scan_id):
        raise ValidationError(
            field="scan_id",
            message=f"El escaneo {scan_id} no esta finalizado aun",
            value=scan_id,
        )

    doc_mgr = SentinelReportManager()
    doc_id = doc_mgr.generate_report(
        scan_id=scan_id,
        ai_report=ai_report,
        strategy_class=manager._strategy_class,
    )
    logger.info(f"Generacion de PDF solicitada para escaneo {scan_id} (documento {doc_id}) por usuario {user.username} con AI Report: {ai_report}")

    return {
        "message": "Generacion de PDF iniciada",
        "documentId": doc_id,
        "scanId": scan_id,
        "status": "pending",
        "aiReport": ai_report,
        "downloadUrl": f"/sentinel/document/{doc_id}/download",
    }


@sentinel_blp.get("/document-status")
@sentinel_blp.arguments(DocumentStatusQuerySchema, location="query")
@sentinel_blp.response(200, DocumentStatusResponseSchema, description="Document status")
@sentinel_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@sentinel_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@sentinel_blp.alt_response(404, schema=ErrorSchema, description="Document not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_READ])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(default_exception=ScanNotFoundError, logger=logger)
def get_document_status(args):
    """Consultar estado de generacion de un documento"""
    user = get_current_user()
    document_id = args.get("document_id")
    scan_id = args.get("scan_id")

    doc_mgr = SentinelReportManager()

    doc = doc_mgr.get_document_by_id(document_id) if document_id else (
        doc_mgr.get_latest_document_by_scan_id(scan_id) if scan_id else None
    )

    if not doc:
        raise ScanNotFoundError(document_id or scan_id)

    if document_id:
        doc_mgr.assert_document_ownership(document_id, user.id)

    download_url = None
    is_done = doc.status == "done"
    if is_done and doc.filename: # type: ignore
        download_url = f"/sentinel/document/{doc.id}/download"

    return {
        "documentId": doc.id,
        "scanId": doc.scan_id,
        "status": doc.status,
        "aiReport": doc.enrichment_json is not None,
        "createdAt": doc.created_at if doc.created_at else None, # type: ignore
        "generatedAt": doc.generated_at if doc.generated_at else None, # type: ignore
        "downloadUrl": download_url,
    }


@sentinel_blp.get("/documents")
@sentinel_blp.arguments(DocumentsQuerySchema, location="query")
@sentinel_blp.response(200, DocumentListResponseSchema, description="All documents")
@sentinel_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@sentinel_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_READ])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(default_exception=DocumentError, logger=logger)
def get_all_documents(args):
    """Obtener todos los documentos del usuario"""
    user = get_current_user()
    scan_type_filter = args["scan_type"]

    doc_mgr = SentinelReportManager()
    documents = doc_mgr.get_documents_for_user(user.id) # type: ignore

    if scan_type_filter != "all":
        documents = [d for d in documents if d.scan_type == scan_type_filter]

    docs_list = []
    for doc in documents:
        download_url = None
        is_done = doc.status == "done"
        if is_done and doc.filename: # type: ignore
            download_url = f"/sentinel/document/{doc.id}/download"

        docs_list.append({
            "documentId": doc.id,
            "scanId": doc.scan_id,
            "scanType": doc.scan_type,
            "status": doc.status,
            "isAiGenerated": doc.is_ai_generated == 1 if doc.is_ai_generated is not None else False,
            "createdAt": doc.created_at if doc.created_at else None, # type: ignore
            "generatedAt": doc.generated_at if doc.generated_at else None, # type: ignore
            "downloadUrl": download_url,
        })

    return {
        "documents": docs_list,
        "total": len(docs_list),
        "filter": scan_type_filter,
    }


@sentinel_blp.get("/scan/<int:scan_id>/documents")
@sentinel_blp.response(200, ScanDocumentsResponseSchema, description="Scan documents")
@sentinel_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@sentinel_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@sentinel_blp.alt_response(404, schema=ErrorSchema, description="Scan not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_READ])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(default_exception=DocumentError, logger=logger)
def get_documents_by_scan(scan_id: int):
    """Obtener todos los documentos de un escaneo concreto"""
    user = get_current_user()

    doc_mgr = SentinelReportManager()
    scan_mgr = ScanManager.resolve_manager(scan_id)

    scan = scan_mgr.get_scan_by_id(scan_id)
    if not scan:
        raise ScanNotFoundError(scan_id)

    documents = doc_mgr.get_documents_by_scan_id(scan_id)

    docs_list = []
    for doc in documents:
        download_url = None
        is_done = doc.status == "done"
        if is_done and doc.filename: # type: ignore
            download_url = f"/sentinel/document/{doc.id}/download"

        docs_list.append({
            "documentId": doc.id,
            "scanId": doc.scan_id,
            "scanType": doc.scan_type,
            "status": doc.status,
            "isAiGenerated": doc.is_ai_generated == 1 if doc.is_ai_generated is not None else False,
            "createdAt": doc.created_at if doc.created_at else None,
            "generatedAt": doc.generated_at if doc.generated_at else None,
            "downloadUrl": download_url,
        })

    return {
        "scanId": scan_id,
        "documents": docs_list,
        "total": len(docs_list),
    }


@sentinel_blp.get("/document/<int:document_id>/download")
@sentinel_blp.response(200, description="PDF file download")
@sentinel_blp.alt_response(400, schema=ErrorSchema, description="Document not ready")
@sentinel_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@sentinel_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@sentinel_blp.alt_response(404, schema=ErrorSchema, description="Document not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_READ])
@handle_exceptions(default_exception=DocumentError, logger=logger)
def download_document(document_id: int):
    """Descargar un documento PDF generado"""
    user = get_current_user()
    uid = user.id
    logger.info(f"Download request for document {document_id} by user {uid}")

    doc_mgr = SentinelReportManager()
    doc_mgr.assert_document_ownership(document_id, uid) # type: ignore

    doc = doc_mgr.get_document_by_id(document_id)
    if not doc:
        logger.warning(f"Document {document_id} not found or access denied for user {uid}")
        raise DocumentNotFoundError(document_id)

    if doc.status != "done" or not doc.filename or not os.path.exists(doc.filename): # type: ignore
        logger.warning(f"Document {document_id} not ready: status={doc.status}, filename={doc.filename}")
        raise DocumentNotReadyError(document_id, doc.status)

    logger.info(f"Serving document {document_id}: {doc.filename}")
    return send_file(
        doc.filename, # type: ignore
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"{doc.scan_type}_scan_{doc.scan_id}.pdf",
    )


@sentinel_blp.delete("/document/<int:document_id>")
@sentinel_blp.response(200, DocumentDeleteResponseSchema, description="Document deleted")
@sentinel_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@sentinel_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@sentinel_blp.alt_response(404, schema=ErrorSchema, description="Document not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_DELETE])
@limiter.limit("30 per hour; 100 per day")
@handle_exceptions(default_exception=DocumentError, logger=logger)
def delete_document(document_id: int):
    """Eliminar un documento"""
    user = get_current_user()
    uid = user.id

    doc_mgr = SentinelReportManager()
    doc_mgr.assert_document_ownership(document_id, uid) # type: ignore
    doc_mgr.delete_document(document_id)
    logger.info(f"Documento {document_id} eliminado por usuario {uid}")
    return {"message": "Documento eliminado correctamente", "documentId": document_id}


@sentinel_blp.post("/scheduled-scans")
@sentinel_blp.arguments(ScheduledScanRequestSchema)
@sentinel_blp.response(201, ScheduledScanResponseSchema, description="Scheduled scan created")
@sentinel_blp.alt_response(400, schema=ErrorSchema, description="Validation error")
@sentinel_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@sentinel_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_SCHEDULE_CREATE])
@limiter.limit("30 per hour; 100 per day")
@handle_exceptions(default_exception=ProgramedScanError, logger=logger)
def schedule_scan(data):
    """Crear un escaneo programado"""
    scan_type_str = data["scan_type"].lower()
    valid_types = {t.value for t in ScanType}
    if scan_type_str not in valid_types:
        raise ValidationError(
            field="scan_type",
            message="Tipo de escaneo invalido",
            value=scan_type_str,
            expected=", ".join(sorted(valid_types)),
        )
    user = get_current_user()
    ps = ProgramedScanManager.register(
        user_id=user.id, # type: ignore
        scan_type=ScanType(scan_type_str),
        arguments=data["arguments"],
        schedule_type=data["schedule_type"],
        schedule_config=data["schedule_config"],
    )
    logger.info(
        f"Escaneo programado {ps.id} creado: tipo={scan_type_str} "
        f"programacion={data['schedule_type']} usuario={user.username}"
    )
    return {
        "message": "Escaneo programado creado correctamente",
        "programedScanId": ps.id,
        "scanType": scan_type_str,
        "scheduleType": data["schedule_type"],
        "scheduleConfig": data["schedule_config"],
        "nextRunAt": ps.next_run_at if ps.next_run_at else None, # type: ignore
        "user": user.username,
    }


@sentinel_blp.delete("/scheduled-scans/<int:ps_id>")
@sentinel_blp.response(200, ScheduledScanActionResponseSchema, description="Scheduled scan revoked")
@sentinel_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@sentinel_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@sentinel_blp.alt_response(404, schema=ErrorSchema, description="Not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_SCHEDULE_DELETE])
@limiter.limit("60 per hour; 200 per day")
@handle_exceptions(default_exception=ProgramedScanNotFoundError, logger=logger)
def revoke_scheduled_scan(ps_id: int):
    """Revocar un escaneo programado (desactivar)"""
    user = get_current_user()
    ps = ProgramedScanManager.assert_ownership(ps_id, user.id) # type: ignore
    ProgramedScanManager.revoke(ps_id, user.id) # type: ignore
    logger.info(f"Escaneo programado {ps_id} revocado por {user.username}")
    return {
        "message": "Escaneo programado revocado correctamente",
        "programedScanId": ps_id,
        "scanType": ps.scan_type,
        "user": user.username,
    }


@sentinel_blp.delete("/scheduled-scans/<int:ps_id>/permanent")
@sentinel_blp.response(200, ScheduledScanActionResponseSchema, description="Scheduled scan permanently deleted")
@sentinel_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@sentinel_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@sentinel_blp.alt_response(404, schema=ErrorSchema, description="Not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_SCHEDULE_DELETE])
@limiter.limit("30 per hour; 100 per day")
@handle_exceptions(default_exception=ProgramedScanNotFoundError, logger=logger)
def delete_scheduled_scan(ps_id: int):
    """Eliminar permanentemente un escaneo programado de la BD"""
    user = get_current_user()
    ps = ProgramedScanManager.assert_ownership(ps_id, user.id) # type: ignore
    ProgramedScanManager.delete(ps_id, user.id) # type: ignore
    logger.info(f"Escaneo programado {ps_id} eliminado permanentemente por {user.username}")
    return {
        "message": "Escaneo programado eliminado permanentemente",
        "programedScanId": ps_id,
        "scanType": ps.scan_type,
        "user": user.username,
    }


@sentinel_blp.get("/scheduled-scans")
@sentinel_blp.response(200, ScheduledScanListResponseSchema, description="List of scheduled scans")
@sentinel_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@sentinel_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@limiter.limit("300 per hour; 2000 per day")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_SCHEDULE_READ])
@handle_exceptions(default_exception=ProgramedScanError, logger=logger)
def list_scheduled_scans():
    """Listar todos los escaneos programados del usuario"""
    user = get_current_user()
    scans = ProgramedScanManager.get_scans_for_user(user.id) # type: ignore
    results = [
        {
            "id": ps.id,
            "scanType": ps.scan_type,
            "arguments": ps.arguments,
            "scheduleType": ps.schedule_type,
            "scheduleConfig": ps.schedule_config,
            "isActive": ps.is_active,
            "lastRunAt": ps.last_run_at if ps.last_run_at else None, # type: ignore
            "nextRunAt": ps.next_run_at if ps.next_run_at else None, # type: ignore
            "createdAt": ps.created_at if ps.created_at else None, # type: ignore
        }
        for ps in scans
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

@sentinel_blp.post("/folders")
@sentinel_blp.arguments(CreateFolderSchema)
@sentinel_blp.response(201, FolderActionResponseSchema, description="Folder created")
@sentinel_blp.alt_response(400, schema=ErrorSchema, description="Validation error")
@sentinel_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@sentinel_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_FOLDER_CREATE])
@limiter.limit("60 per hour; 200 per day")
@handle_exceptions(default_exception=FolderNameInvalidError, logger=logger)
def create_folder(data):
    """Crear una nueva carpeta de escaneos"""
    user = get_current_user()
    folder = ScanFolderManager().create_folder(user.id, data["name"])  # type: ignore
    logger.info(f"Carpeta {folder.id} creada por {user.username}")
    return {
        "message": "Carpeta creada correctamente",
        "folderId": folder.id,
        "name": folder.name,
        "user": user.username,
    }


@sentinel_blp.get("/folders")
@sentinel_blp.response(200, FolderListResponseSchema, description="User folders with scans")
@sentinel_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@sentinel_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_FOLDER_READ])
@limiter.limit("300 per hour; 2000 per day")
@handle_exceptions(default_exception=FolderNotFoundError, logger=logger)
def list_folders():
    """Listar todas las carpetas del usuario con sus escaneos completos"""
    user = get_current_user()
    result = ScanFolderManager().get_folders_with_scans(user.id)  # type: ignore
    logger.info(f"Carpetas obtenidas para usuario {user.username}")
    return {
        "message": "Carpetas obtenidas correctamente",
        "folders": result["folders"],
        "unfoldered": result["unfoldered"],
        "user": user.username,
    }


@sentinel_blp.put("/folders/<int:folder_id>")
@sentinel_blp.arguments(RenameFolderSchema)
@sentinel_blp.response(200, FolderActionResponseSchema, description="Folder renamed")
@sentinel_blp.alt_response(400, schema=ErrorSchema, description="Validation error")
@sentinel_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@sentinel_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@sentinel_blp.alt_response(404, schema=ErrorSchema, description="Folder not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_FOLDER_UPDATE])
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


@sentinel_blp.delete("/folders/<int:folder_id>")
@sentinel_blp.response(200, FolderActionResponseSchema, description="Folder deleted")
@sentinel_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@sentinel_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@sentinel_blp.alt_response(404, schema=ErrorSchema, description="Folder not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_FOLDER_DELETE])
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


@sentinel_blp.post("/folders/<int:folder_id>/scans")
@sentinel_blp.arguments(MoveScanToFolderSchema)
@sentinel_blp.response(200, ScanFolderActionResponseSchema, description="Scan moved to folder")
@sentinel_blp.alt_response(400, schema=ErrorSchema, description="Validation error")
@sentinel_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@sentinel_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@sentinel_blp.alt_response(404, schema=ErrorSchema, description="Folder or scan not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_FOLDER_UPDATE])
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


@sentinel_blp.post("/folders/<int:folder_id>/scans/batch")
@sentinel_blp.arguments(AddScansToFolderSchema)
@sentinel_blp.response(200, ScanFolderActionResponseSchema, description="Scans added to folder")
@sentinel_blp.alt_response(400, schema=ErrorSchema, description="Validation error")
@sentinel_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@sentinel_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@sentinel_blp.alt_response(404, schema=ErrorSchema, description="Folder or scan not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_FOLDER_UPDATE])
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


@sentinel_blp.delete("/folders/<int:folder_id>/scans/<int:scan_id>")
@sentinel_blp.response(200, ScanFolderActionResponseSchema, description="Scan removed from folder")
@sentinel_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@sentinel_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@sentinel_blp.alt_response(404, schema=ErrorSchema, description="Scan not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.SENTINEL_FOLDER_UPDATE])
@limiter.limit("120 per hour; 400 per day")
@handle_exceptions(default_exception=ScanNotFoundError, logger=logger)
def remove_scan_from_folder(folder_id: int, scan_id: int):
    """Sacar un escaneo de una carpeta (lo deja sin carpeta)"""
    user = get_current_user()
    scan = ScanFolderManager().remove_scan_from_folder(scan_id, user.id)  # type: ignore
    logger.info(f"Escaneo {scan_id} sacado de carpeta {folder_id} por {user.username}")
    return {
        "message": "Escaneo eliminado de la carpeta correctamente",
        "scanId": scan_id,
        "folderId": None,
        "user": user.username,
    }
