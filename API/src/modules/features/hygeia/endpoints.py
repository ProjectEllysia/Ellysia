"""
Endpoints del módulo Hygeia.

Este fichero solo hace autenticación y validación de schema: toda la lógica
vive en ``managers.py``, y el acceso a datos, únicamente vía ``UnitOfWork`` +
repositorio (regla del repo).

Dos superficies separadas:
    - Usuario (``@require_oauth_token``): alta, listado, detalle, baja y
      rotación de clave de los activos monitorizados, más el catálogo de
      etiquetas con el que se agrupan.
    - Agente (``@require_agent_key``): la ruta caliente de ingesta de
      heartbeats (``POST /hygeia/ingest``).
"""

import io
import logging

from flask import request, send_file
from flask_smorest import Blueprint as SmorestBlueprint

from src.modules.shared import handle_exceptions, limiter, current_actor
from src.modules.shared.schemas import ErrorSchema
from src.modules.users import (
    require_oauth_token, require_attributes, AttributeType, get_current_user,
)

from .exceptions import (
    AnomalyNotFoundError,
    AssetNotFoundError,
    HygeiaError,
    TagNotFoundError,
)
from .managers import (
    HygeiaAlertManager, HygeiaAssetManager, HygeiaIngestManager, HygeiaReportManager,
    HygeiaTagManager,
)
from .schemas import (
    AnalyzeInventoryResponseSchema,
    AnomalyListResponseSchema,
    AnomalyQuerySchema,
    AnomalySchema,
    AssetCreateRequestSchema,
    AssetCreatedResponseSchema,
    AssetInventoryResponseSchema,
    AssetLatestResponseSchema,
    AssetListResponseSchema,
    AssetMetricsQuerySchema,
    AssetMetricsResponseSchema,
    AssetSchema,
    AssetTagsRequestSchema,
    AssetUpdateRequestSchema,
    IngestRequestSchema,
    InventoryReportRequestSchema,
    IngestResponseSchema,
    InventoryAnalysisSummarySchema,
    RotateKeyResponseSchema,
    TagCreateRequestSchema,
    TagListResponseSchema,
    TagSchema,
)
from .services import agent_key_id_from_request, enforce_ingest_limits, require_agent_key

hygeia_blp = SmorestBlueprint(
    "hygeia", __name__,
    description="Monitorización de activos: ingesta de telemetría, "
                "detección de anomalías y alertado (Hygeia)",
)
logger = logging.getLogger(__name__)


@hygeia_blp.post("/assets")
@hygeia_blp.arguments(AssetCreateRequestSchema)
@hygeia_blp.response(
    201, AssetCreatedResponseSchema, description="Asset created — agent key shown once",
)
@hygeia_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@hygeia_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@hygeia_blp.alt_response(409, schema=ErrorSchema, description="Asset quota exceeded")
@limiter.limit("30 per hour")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.HYGEIA_CREATE])
@handle_exceptions(default_exception=HygeiaError, logger=logger)
def create_asset(data):
    """Dar de alta un activo a monitorizar y emitir su clave de agente"""
    user = get_current_user()
    manager = HygeiaAssetManager(user)
    result = manager.create_asset(
        hostname=data["hostname"],
        os_name=data["os"],
        labels=data["labels"],
        is_persistent=data["isPersistent"],
    )
    logger.info(f"Activo Hygeia creado | user={current_actor()} hostname={data['hostname']}")
    return result


@hygeia_blp.get("/assets")
@hygeia_blp.response(200, AssetListResponseSchema, description="Assets del usuario")
@hygeia_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@hygeia_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@limiter.limit("600 per hour")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.HYGEIA_READ])
@handle_exceptions(default_exception=HygeiaError, logger=logger)
def list_assets():
    """Listar los activos monitorizados del usuario con su estado de presencia"""
    user = get_current_user()
    manager = HygeiaAssetManager(user)
    return {"assets": manager.list_assets()}


@hygeia_blp.get("/assets/<int:asset_id>")
@hygeia_blp.response(200, AssetSchema, description="Detalle del activo")
@hygeia_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@hygeia_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@hygeia_blp.alt_response(404, schema=ErrorSchema, description="Asset not found")
@limiter.limit("600 per hour")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.HYGEIA_READ])
@handle_exceptions(default_exception=AssetNotFoundError, logger=logger)
def get_asset(asset_id):
    """Obtener el detalle de un activo monitorizado"""
    user = get_current_user()
    manager = HygeiaAssetManager(user)
    return manager.get_asset(asset_id)


@hygeia_blp.get("/assets/<int:asset_id>/metrics")
@hygeia_blp.arguments(AssetMetricsQuerySchema, location="query")
@hygeia_blp.response(200, AssetMetricsResponseSchema, description="Serie temporal de métricas del activo")
@hygeia_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@hygeia_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@hygeia_blp.alt_response(404, schema=ErrorSchema, description="Asset not found")
@limiter.limit("600 per hour")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.HYGEIA_READ])
@handle_exceptions(default_exception=AssetNotFoundError, logger=logger)
def get_asset_metrics(args, asset_id):
    """Obtener la serie temporal de métricas escalares de un activo, para el gráfico de la SPA"""
    user = get_current_user()
    manager = HygeiaAssetManager(user)
    return manager.get_metrics(asset_id, since=args["since"], until=args["until"])


@hygeia_blp.get("/assets/<int:asset_id>/metrics/latest")
@hygeia_blp.response(200, AssetLatestResponseSchema, description="Últimas métricas completas del activo")
@hygeia_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@hygeia_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@hygeia_blp.alt_response(404, schema=ErrorSchema, description="Asset not found")
@limiter.limit("600 per hour")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.HYGEIA_READ])
@handle_exceptions(default_exception=AssetNotFoundError, logger=logger)
def get_asset_latest_metrics(asset_id):
    """Obtener el último heartbeat completo de un activo (disco, red, procesos y núcleos)"""
    user = get_current_user()
    manager = HygeiaAssetManager(user)
    return manager.get_latest_metrics(asset_id)


@hygeia_blp.get("/assets/<int:asset_id>/inventory")
@hygeia_blp.response(200, AssetInventoryResponseSchema, description="Último inventario de software del activo")
@hygeia_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@hygeia_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@hygeia_blp.alt_response(404, schema=ErrorSchema, description="Asset not found")
@limiter.limit("600 per hour")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.HYGEIA_READ])
@handle_exceptions(default_exception=AssetNotFoundError, logger=logger)
def get_asset_inventory(asset_id):
    """Obtener el último inventario de software conocido de un activo"""
    user = get_current_user()
    manager = HygeiaAssetManager(user)
    return manager.get_inventory(asset_id)


@hygeia_blp.post("/assets/<int:asset_id>/analyze")
@hygeia_blp.response(202, AnalyzeInventoryResponseSchema, description="Análisis de inventario encolado")
@hygeia_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@hygeia_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@hygeia_blp.alt_response(404, schema=ErrorSchema, description="Asset not found")
@hygeia_blp.alt_response(409, schema=ErrorSchema, description="Asset has no inventory to analyse")
@limiter.limit("20 per hour; 100 per day")
@require_oauth_token
# Exige AMBOS atributos a propósito: la acción vive en Hygeia pero lo que crea
# es un escaneo de Themis, así que quien no puede lanzar escaneos allí tampoco
# debe poder lanzarlos por esta puerta.
@require_attributes(all_required=[AttributeType.HYGEIA_UPDATE, AttributeType.THEMIS_CREATE])
@handle_exceptions(default_exception=HygeiaError, logger=logger)
def analyze_asset_inventory(asset_id):
    """Analizar el inventario de software de un activo con el motor Lybra"""
    user = get_current_user()
    manager = HygeiaAssetManager(user)
    result = manager.analyze_inventory(asset_id)
    logger.info(f"Análisis de inventario del activo {asset_id} lanzado por {user.username}")
    return result


@hygeia_blp.get("/assets/<int:asset_id>/analysis")
@hygeia_blp.response(200, InventoryAnalysisSummarySchema, description="Resumen del último análisis de inventario")
@hygeia_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@hygeia_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@hygeia_blp.alt_response(404, schema=ErrorSchema, description="Asset not found")
@limiter.limit("600 per hour")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.HYGEIA_READ])
@handle_exceptions(default_exception=AssetNotFoundError, logger=logger)
def get_asset_analysis(asset_id):
    """Obtener el resumen del último análisis de inventario de un activo"""
    user = get_current_user()
    manager = HygeiaAssetManager(user)
    return manager.get_analysis_summary(asset_id)


@hygeia_blp.patch("/assets/<int:asset_id>")
@hygeia_blp.arguments(AssetUpdateRequestSchema)
@hygeia_blp.response(200, AssetSchema, description="Activo actualizado")
@hygeia_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@hygeia_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@hygeia_blp.alt_response(404, schema=ErrorSchema, description="Asset not found")
@limiter.limit("30 per hour")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.HYGEIA_UPDATE])
@handle_exceptions(default_exception=AssetNotFoundError, logger=logger)
def update_asset(data, asset_id):
    """Marcar si un activo debería estar siempre encendido o se apaga a propósito"""
    user = get_current_user()
    manager = HygeiaAssetManager(user)
    result = manager.set_persistence(asset_id, data["isPersistent"])
    logger.info(
        f"Persistencia del activo {asset_id} = {data['isPersistent']} | user={current_actor()}"
    )
    return result


@hygeia_blp.delete("/assets/<int:asset_id>")
@hygeia_blp.response(200, description="Asset eliminado")
@hygeia_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@hygeia_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@hygeia_blp.alt_response(404, schema=ErrorSchema, description="Asset not found")
@limiter.limit("30 per hour")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.HYGEIA_DELETE])
@handle_exceptions(default_exception=AssetNotFoundError, logger=logger)
def delete_asset(asset_id):
    """Dar de baja un activo monitorizado, revocando su clave de agente"""
    user = get_current_user()
    manager = HygeiaAssetManager(user)
    manager.delete_asset(asset_id)
    logger.info(f"Activo Hygeia {asset_id} eliminado | user={current_actor()}")


@hygeia_blp.post("/inventory/report")
@hygeia_blp.arguments(InventoryReportRequestSchema)
@hygeia_blp.response(200, description="PDF del inventario de activos")
@hygeia_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@hygeia_blp.alt_response(403, schema=ErrorSchema, description="Organization scope requires ownership")
# 20 por hora, muy por debajo del resto de lecturas de Hygeia (600): construir
# el PDF es trabajo de CPU en el hilo de la petición, y ese es el precio de
# haberlo hecho síncrono.
@limiter.limit("20 per hour")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.HYGEIA_READ])
@handle_exceptions(default_exception=HygeiaError, logger=logger)
def download_inventory_report(data):
    """Descargar el inventario de activos en PDF, propio o de toda la organización"""
    user = get_current_user()
    manager = HygeiaReportManager(user)
    pdf, filename = manager.build_inventory_report(
        scope=data["scope"], include_software=data["includeSoftware"],
    )
    logger.info(
        f"Informe de inventario generado | user={current_actor()} "
        f"scope={data['scope']} software={data['includeSoftware']} bytes={len(pdf)}"
    )
    # POST y no GET aunque sea una lectura: `run.py` registra un GET
    # condicional (ETag/304) global, y un PDF que cambia cada vez que se da de
    # alta un activo no debe pasar por esa caché.
    return send_file(
        io.BytesIO(pdf),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=filename,
    )


# =============================================================================
# ETIQUETAS — catálogo común + repositorio personal, y su asignación a activos.
#
# No estrenan atributos propios: una etiqueta es una propiedad de los activos
# de Hygeia, no un recurso aparte, así que reutilizan los HYGEIA_* que ya
# gobiernan el módulo.
# =============================================================================


@hygeia_blp.get("/tags")
@hygeia_blp.response(200, TagListResponseSchema, description="Etiquetas visibles para el usuario")
@hygeia_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@hygeia_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@limiter.limit("600 per hour")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.HYGEIA_READ])
@handle_exceptions(default_exception=HygeiaError, logger=logger)
def list_tags():
    """Listar el catálogo de etiquetas del usuario con el recuento de activos de cada una"""
    user = get_current_user()
    manager = HygeiaTagManager(user)
    return {"tags": manager.list_tags()}


@hygeia_blp.post("/tags")
@hygeia_blp.arguments(TagCreateRequestSchema)
@hygeia_blp.response(201, TagSchema, description="Etiqueta personal creada")
@hygeia_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@hygeia_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@hygeia_blp.alt_response(409, schema=ErrorSchema, description="Tag name taken or quota exceeded")
@limiter.limit("60 per hour")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.HYGEIA_CREATE])
@handle_exceptions(default_exception=HygeiaError, logger=logger)
def create_tag(data):
    """Añadir una etiqueta al repositorio personal del usuario"""
    user = get_current_user()
    manager = HygeiaTagManager(user)
    result = manager.create_tag(name=data["name"], color=data["color"])
    logger.info(f"Etiqueta Hygeia creada | user={current_actor()} name={data['name']}")
    return result


@hygeia_blp.delete("/tags/<int:tag_id>")
@hygeia_blp.response(200, description="Etiqueta eliminada")
@hygeia_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@hygeia_blp.alt_response(403, schema=ErrorSchema, description="System tags cannot be deleted")
@hygeia_blp.alt_response(404, schema=ErrorSchema, description="Tag not found")
@limiter.limit("60 per hour")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.HYGEIA_DELETE])
@handle_exceptions(default_exception=TagNotFoundError, logger=logger)
def delete_tag(tag_id):
    """Borrar una etiqueta personal, quitándola de todos los activos que la llevaran"""
    user = get_current_user()
    manager = HygeiaTagManager(user)
    manager.delete_tag(tag_id)
    logger.info(f"Etiqueta Hygeia {tag_id} eliminada | user={current_actor()}")


@hygeia_blp.put("/assets/<int:asset_id>/tags")
@hygeia_blp.arguments(AssetTagsRequestSchema)
@hygeia_blp.response(200, AssetSchema, description="Activo con sus etiquetas actualizadas")
@hygeia_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@hygeia_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@hygeia_blp.alt_response(404, schema=ErrorSchema, description="Asset or tag not found")
@limiter.limit("120 per hour")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.HYGEIA_UPDATE])
@handle_exceptions(default_exception=AssetNotFoundError, logger=logger)
def set_asset_tags(data, asset_id):
    """Fijar el conjunto completo de etiquetas de un activo"""
    user = get_current_user()
    manager = HygeiaTagManager(user)
    result = manager.set_asset_tags(asset_id, data["tagIds"])
    logger.info(
        f"Etiquetas del activo {asset_id} = {data['tagIds']} | user={current_actor()}"
    )
    return result


@hygeia_blp.post("/assets/<int:asset_id>/rotate-key")
@hygeia_blp.response(200, RotateKeyResponseSchema, description="New agent key — shown once")
@hygeia_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@hygeia_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@hygeia_blp.alt_response(404, schema=ErrorSchema, description="Asset not found")
@limiter.limit("30 per hour")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.HYGEIA_UPDATE])
@handle_exceptions(default_exception=AssetNotFoundError, logger=logger)
def rotate_key(asset_id):
    """Regenerar la clave de agente de un activo, invalidando la anterior"""
    user = get_current_user()
    manager = HygeiaAssetManager(user)
    result = manager.rotate_key(asset_id)
    logger.info(f"Clave de agente rotada para activo {asset_id} | user={current_actor()}")
    return result


@hygeia_blp.get("/alerts")
@hygeia_blp.arguments(AnomalyQuerySchema, location="query")
@hygeia_blp.response(200, AnomalyListResponseSchema, description="Anomalías de los activos del usuario")
@hygeia_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@hygeia_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@limiter.limit("600 per hour")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.HYGEIA_READ])
@handle_exceptions(default_exception=HygeiaError, logger=logger)
def list_alerts(args):
    """Listar las anomalías de los activos del usuario, con filtros opcionales"""
    user = get_current_user()
    manager = HygeiaAlertManager(user)
    anomalies = manager.list_alerts(
        state=args["state"], severity=args["severity"], asset_id=args["assetId"],
    )
    return {"anomalies": anomalies}


@hygeia_blp.post("/alerts/<int:anomaly_id>/ack")
@hygeia_blp.response(200, AnomalySchema, description="Anomalía reconocida")
@hygeia_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@hygeia_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@hygeia_blp.alt_response(404, schema=ErrorSchema, description="Anomaly not found")
@limiter.limit("60 per hour")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.HYGEIA_UPDATE])
@handle_exceptions(default_exception=AnomalyNotFoundError, logger=logger)
def ack_alert(anomaly_id):
    """Reconocer una anomalía, sin darla por resuelta"""
    user = get_current_user()
    manager = HygeiaAlertManager(user)
    result = manager.ack_alert(anomaly_id)
    logger.info(f"Anomalía {anomaly_id} reconocida | user={current_actor()}")
    return result


@hygeia_blp.post("/alerts/<int:anomaly_id>/resolve")
@hygeia_blp.response(200, AnomalySchema, description="Anomalía resuelta")
@hygeia_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@hygeia_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@hygeia_blp.alt_response(404, schema=ErrorSchema, description="Anomaly not found")
@limiter.limit("60 per hour")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.HYGEIA_UPDATE])
@handle_exceptions(default_exception=AnomalyNotFoundError, logger=logger)
def resolve_alert(anomaly_id):
    """Resolver manualmente una anomalía"""
    user = get_current_user()
    manager = HygeiaAlertManager(user)
    result = manager.resolve_alert(anomaly_id)
    logger.info(f"Anomalía {anomaly_id} resuelta manualmente | user={current_actor()}")
    return result


@hygeia_blp.delete("/alerts/<int:anomaly_id>")
@hygeia_blp.response(200, description="Anomalía eliminada")
@hygeia_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@hygeia_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@hygeia_blp.alt_response(404, schema=ErrorSchema, description="Anomaly not found")
@hygeia_blp.alt_response(409, schema=ErrorSchema, description="Anomaly still open")
@limiter.limit("60 per hour")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.HYGEIA_DELETE])
@handle_exceptions(default_exception=AnomalyNotFoundError, logger=logger)
def delete_alert(anomaly_id):
    """Borrar una anomalía ya reconocida o resuelta"""
    user = get_current_user()
    manager = HygeiaAlertManager(user)
    manager.delete_alert(anomaly_id)
    logger.info(f"Anomalía {anomaly_id} eliminada | user={current_actor()}")
    return {"message": "Anomalía eliminada correctamente"}


# ============================================================================
# SUPERFICIE DE AGENTE — autenticada por clave de agente, no por OAuth
# ============================================================================

@hygeia_blp.post("/ingest")
@enforce_ingest_limits
@hygeia_blp.arguments(IngestRequestSchema)
@hygeia_blp.response(200, IngestResponseSchema, description="Heartbeat procesado")
@hygeia_blp.alt_response(401, schema=ErrorSchema, description="Invalid or missing agent key")
@hygeia_blp.alt_response(400, schema=ErrorSchema, description="Validation error or clock skew")
@hygeia_blp.alt_response(413, schema=ErrorSchema, description="Payload too large")
@hygeia_blp.alt_response(429, schema=ErrorSchema, description="Heartbeat too frequent")
@limiter.limit("20 per minute", key_func=agent_key_id_from_request)
@require_agent_key
@handle_exceptions(default_exception=HygeiaError, logger=logger)
def ingest(data):
    """Recibir un heartbeat de un agente Hygeia y actualizar la presencia del activo"""
    # Esta superficie se autentica por clave de agente (@require_agent_key
    # inyecta request.current_asset_id), no por OAuth de usuario — no hay
    # request.current_user_id aquí, así que get_current_user() no aplica.
    manager = HygeiaIngestManager(request.current_asset_id)
    return manager.ingest_heartbeat(data)
