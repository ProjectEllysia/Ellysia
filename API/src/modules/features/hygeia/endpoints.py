"""
Endpoints del módulo Hygeia.

Este fichero solo hace autenticación y validación de schema: toda la lógica
vive en ``managers.py``, y el acceso a datos, únicamente vía ``UnitOfWork`` +
repositorio (regla del repo).

Dos superficies separadas:
    - Usuario (``@require_oauth_token``): alta, listado, detalle, baja y
      rotación de clave de los activos monitorizados.
    - Agente (``@require_agent_key``): la ruta caliente de ingesta de
      heartbeats (``POST /hygeia/ingest``).
"""

import logging

from flask import request
from flask_smorest import Blueprint as SmorestBlueprint

from src.modules.shared import handle_exceptions, limiter, current_actor
from src.modules.shared.schemas import ErrorSchema
from src.modules.users import (
    require_oauth_token, require_attributes, AttributeType, get_current_user,
)

from .exceptions import AnomalyNotFoundError, AssetNotFoundError, HygeiaError
from .managers import HygeiaAlertManager, HygeiaAssetManager, HygeiaIngestManager
from .schemas import (
    AnomalyListResponseSchema,
    AnomalyQuerySchema,
    AnomalySchema,
    AssetCreateRequestSchema,
    AssetCreatedResponseSchema,
    AssetListResponseSchema,
    AssetMetricsQuerySchema,
    AssetMetricsResponseSchema,
    AssetSchema,
    IngestRequestSchema,
    IngestResponseSchema,
    RotateKeyResponseSchema,
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
    mgr = HygeiaAssetManager(user)
    result = mgr.create_asset(
        hostname=data["hostname"],
        os_name=data["os"],
        labels=data["labels"],
    )
    logger.info(f"Activo Hygeia creado | user={current_actor()} hostname={data['hostname']}")
    return result


@hygeia_blp.get("/assets")
@hygeia_blp.response(200, AssetListResponseSchema, description="Assets del usuario")
@hygeia_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@hygeia_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@limiter.limit("300 per hour")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.HYGEIA_READ])
@handle_exceptions(default_exception=HygeiaError, logger=logger)
def list_assets():
    """Listar los activos monitorizados del usuario con su estado de presencia"""
    user = get_current_user()
    mgr = HygeiaAssetManager(user)
    return {"assets": mgr.list_assets()}


@hygeia_blp.get("/assets/<int:asset_id>")
@hygeia_blp.response(200, AssetSchema, description="Detalle del activo")
@hygeia_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@hygeia_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@hygeia_blp.alt_response(404, schema=ErrorSchema, description="Asset not found")
@limiter.limit("300 per hour")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.HYGEIA_READ])
@handle_exceptions(default_exception=AssetNotFoundError, logger=logger)
def get_asset(asset_id):
    """Obtener el detalle de un activo monitorizado"""
    user = get_current_user()
    mgr = HygeiaAssetManager(user)
    return mgr.get_asset(asset_id)


@hygeia_blp.get("/assets/<int:asset_id>/metrics")
@hygeia_blp.arguments(AssetMetricsQuerySchema, location="query")
@hygeia_blp.response(200, AssetMetricsResponseSchema, description="Serie temporal de métricas del activo")
@hygeia_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@hygeia_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@hygeia_blp.alt_response(404, schema=ErrorSchema, description="Asset not found")
@limiter.limit("300 per hour")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.HYGEIA_READ])
@handle_exceptions(default_exception=AssetNotFoundError, logger=logger)
def get_asset_metrics(args, asset_id):
    """Obtener la serie temporal de métricas (CPU/memoria) de un activo, para el gráfico de la SPA"""
    user = get_current_user()
    mgr = HygeiaAssetManager(user)
    return {"snapshots": mgr.get_metrics(asset_id, since=args["since"], until=args["until"])}


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
    mgr = HygeiaAssetManager(user)
    mgr.delete_asset(asset_id)
    logger.info(f"Activo Hygeia {asset_id} eliminado | user={current_actor()}")
    return {"message": "Asset eliminado correctamente"}


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
    mgr = HygeiaAssetManager(user)
    result = mgr.rotate_key(asset_id)
    logger.info(f"Clave de agente rotada para activo {asset_id} | user={current_actor()}")
    return result


@hygeia_blp.get("/alerts")
@hygeia_blp.arguments(AnomalyQuerySchema, location="query")
@hygeia_blp.response(200, AnomalyListResponseSchema, description="Anomalías de los activos del usuario")
@hygeia_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@hygeia_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@limiter.limit("300 per hour")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.HYGEIA_READ])
@handle_exceptions(default_exception=HygeiaError, logger=logger)
def list_alerts(args):
    """Listar las anomalías de los activos del usuario, con filtros opcionales"""
    user = get_current_user()
    mgr = HygeiaAlertManager(user)
    anomalies = mgr.list_alerts(
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
    mgr = HygeiaAlertManager(user)
    result = mgr.ack_alert(anomaly_id)
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
    mgr = HygeiaAlertManager(user)
    result = mgr.resolve_alert(anomaly_id)
    logger.info(f"Anomalía {anomaly_id} resuelta manualmente | user={current_actor()}")
    return result


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
    mgr = HygeiaIngestManager(request.current_asset_id)
    return mgr.ingest_heartbeat(data)
