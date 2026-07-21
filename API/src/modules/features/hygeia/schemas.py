"""
Schemas Marshmallow del módulo Hygeia. Claves de respuesta en camelCase,
por convención del proyecto.
"""

from datetime import timezone

from marshmallow import EXCLUDE, Schema, ValidationError, fields, post_load, validate, validates_schema

import src.modules.system.config_reading as CR
from src.modules.shared.schemas import UTCDateTime


class AssetCreateRequestSchema(Schema):
    """Alta de un nuevo activo a monitorizar."""
    hostname = fields.String(required=True, validate=validate.Length(min=1, max=255))
    os = fields.String(load_default=None, validate=validate.Length(max=64))
    labels = fields.Dict(load_default=dict)


class AssetSchema(Schema):
    """Vista de un activo monitorizado (nunca incluye la clave de agente)."""
    id = fields.Integer()
    hostname = fields.String()
    os = fields.String(allow_none=True)
    labels = fields.Dict()
    status = fields.String()
    lastSeenAt = UTCDateTime(allow_none=True)
    agentVersion = fields.String(allow_none=True)
    createdAt = UTCDateTime()


class AssetCreatedResponseSchema(Schema):
    """Respuesta del alta: el activo más la clave de agente en claro, una sola vez."""
    asset = fields.Nested(AssetSchema)
    agentKey = fields.String()


class AssetListResponseSchema(Schema):
    """Listado de activos monitorizados del usuario."""
    assets = fields.List(fields.Nested(AssetSchema))


class RotateKeyResponseSchema(Schema):
    """Respuesta de la rotación de clave: la nueva clave en claro, una sola vez."""
    agentKey = fields.String()


# =============================================================================
# INGESTA (§11) — el schema valida y descarta lo desconocido: defensa en la
# frontera de confianza, no se relaja aunque el agente sea "de confianza".
# =============================================================================

class _IngestSchema(Schema):
    """Base común de los schemas de ingesta: descarta claves desconocidas."""
    class Meta:
        unknown = EXCLUDE


class HostInfoSchema(_IngestSchema):
    """Identificación del host que envía el heartbeat."""
    hostname = fields.String(required=True, validate=validate.Length(min=1, max=255))
    os = fields.String(load_default=None, validate=validate.Length(max=64))
    kernel = fields.String(load_default=None, validate=validate.Length(max=128))
    uptimeSec = fields.Integer(load_default=None, validate=validate.Range(min=0))


class CpuMetricsSchema(_IngestSchema):
    """Métricas de CPU de un heartbeat."""
    usagePct = fields.Float(required=True, validate=validate.Range(min=0, max=100))
    loadAvg = fields.List(fields.Float(), load_default=list, validate=validate.Length(max=8))
    ctxSwitches = fields.Integer(load_default=None)
    perCorePct = fields.List(fields.Float(), load_default=list, validate=validate.Length(max=1024))


class MemoryMetricsSchema(_IngestSchema):
    """Métricas de memoria de un heartbeat."""
    totalBytes = fields.Integer(load_default=None)
    usedBytes = fields.Integer(load_default=None)
    usagePct = fields.Float(required=True, validate=validate.Range(min=0, max=100))
    swapUsedPct = fields.Float(load_default=None, validate=validate.Range(min=0, max=100))


class DiskMountSchema(_IngestSchema):
    """Uso de un punto de montaje del host."""
    mount = fields.String(required=True, validate=validate.Length(min=1, max=256))
    usagePct = fields.Float(required=True, validate=validate.Range(min=0, max=100))
    freeBytes = fields.Integer(load_default=None)


class NetworkInterfaceSchema(_IngestSchema):
    """Tráfico de una interfaz de red del host."""
    iface = fields.String(required=True, validate=validate.Length(min=1, max=64))
    rxBytesPerSec = fields.Integer(load_default=None)
    txBytesPerSec = fields.Integer(load_default=None)
    errIn = fields.Integer(load_default=None)
    errOut = fields.Integer(load_default=None)


class ProcessInfoSchema(_IngestSchema):
    """
    Un proceso destacado por consumo de CPU o memoria.

    Se reutiliza tanto para ``topCpu`` como para ``topMem``: cada entrada
    solo rellena el campo (``cpuPct`` o ``memPct``) relevante a la lista en
    la que aparece; el otro queda a ``None``.
    """
    pid = fields.Integer(required=True)
    name = fields.String(required=True, validate=validate.Length(min=1, max=256))
    cpuPct = fields.Float(load_default=None, validate=validate.Range(min=0, max=100))
    memPct = fields.Float(load_default=None, validate=validate.Range(min=0, max=100))


class ProcessesMetricsSchema(_IngestSchema):
    """Resumen de procesos del host en el momento del heartbeat."""
    total = fields.Integer(load_default=None)
    zombie = fields.Integer(load_default=None)
    topCpu = fields.List(fields.Nested(ProcessInfoSchema), load_default=list)
    topMem = fields.List(fields.Nested(ProcessInfoSchema), load_default=list)


class MetricsSchema(_IngestSchema):
    """Payload completo de métricas de un heartbeat (§11)."""
    cpu = fields.Nested(CpuMetricsSchema, required=True)
    memory = fields.Nested(MemoryMetricsSchema, required=True)
    disk = fields.List(fields.Nested(DiskMountSchema), load_default=list)
    network = fields.List(fields.Nested(NetworkInterfaceSchema), load_default=list)
    processes = fields.Nested(ProcessesMetricsSchema, load_default=dict)

    @validates_schema
    def validate_array_limits(self, data, **kwargs):
        """
        Acota disk/network/topCpu/topMem contra los límites configurables de
        ``hygeia.limits`` (§16.1).

        Se leen con ``CR`` en cada validación (no se hornean al importar el
        módulo) para que un cambio vía ``PUT /system`` surta efecto sin
        reiniciar la API, igual que el resto de la configuración.
        """
        max_disk = CR.get_hygeia_max_disk_mounts()
        if len(data.get("disk", [])) > max_disk:
            raise ValidationError(
                f"disk excede el máximo de {max_disk} puntos de montaje", field_name="disk",
            )

        max_net = CR.get_hygeia_max_net_interfaces()
        if len(data.get("network", [])) > max_net:
            raise ValidationError(
                f"network excede el máximo de {max_net} interfaces", field_name="network",
            )

        max_procs = CR.get_hygeia_max_processes()
        processes = data.get("processes") or {}
        if len(processes.get("topCpu", [])) > max_procs:
            raise ValidationError(
                f"topCpu excede el máximo de {max_procs} procesos", field_name="processes",
            )
        if len(processes.get("topMem", [])) > max_procs:
            raise ValidationError(
                f"topMem excede el máximo de {max_procs} procesos", field_name="processes",
            )


class IngestRequestSchema(_IngestSchema):
    """Heartbeat completo enviado por un agente Hygeia (§11)."""
    agentVersion = fields.String(required=True, validate=validate.Length(min=1, max=32))
    collectedAt = fields.DateTime(required=True, format="iso")
    host = fields.Nested(HostInfoSchema, required=True)
    metrics = fields.Nested(MetricsSchema, required=True)
    localAlerts = fields.List(fields.Raw(), load_default=list)

    @post_load
    def normalize_collected_at(self, data, **kwargs):
        """Normaliza ``collectedAt`` a naive-UTC, como el resto de datetimes del esquema.

        Si el agente manda un ISO-8601 con sufijo de zona (el contrato pide
        ``Z``), se convierte a UTC y se descarta el tzinfo. Si llega naive
        (sin zona), se asume ya en UTC — nunca se aplica la zona local del
        servidor, que sería silenciosamente incorrecto.
        """
        collected_at = data["collectedAt"]
        if collected_at.tzinfo is not None:
            collected_at = collected_at.astimezone(timezone.utc).replace(tzinfo=None)
        data["collectedAt"] = collected_at
        return data


class IngestResponseSchema(Schema):
    """Respuesta a un heartbeat: permite al agente auto-ajustarse sin redeploy (§11)."""
    ok = fields.Boolean()
    nextIntervalSec = fields.Integer()
    serverTime = UTCDateTime()


# =============================================================================
# ANOMALÍAS (§6) — alertas abiertas por la evaluación de umbrales
# =============================================================================

class AnomalySchema(Schema):
    """Vista de una anomalía detectada, con su ciclo de vida."""
    id = fields.Integer()
    assetId = fields.Integer()
    kind = fields.String()
    severity = fields.String()
    metric = fields.String(allow_none=True)
    value = fields.Float(allow_none=True)
    threshold = fields.Float(allow_none=True)
    details = fields.Dict()
    state = fields.String()
    openedAt = UTCDateTime()
    resolvedAt = UTCDateTime(allow_none=True)


class AnomalyQuerySchema(Schema):
    """Filtros opcionales para listar anomalías."""
    state = fields.String(
        load_default=None, validate=validate.OneOf(["open", "acknowledged", "resolved"]),
    )
    severity = fields.String(
        load_default=None, validate=validate.OneOf(["info", "warning", "critical"]),
    )
    assetId = fields.Integer(load_default=None)


class AnomalyListResponseSchema(Schema):
    """Listado de anomalías de los activos del usuario."""
    anomalies = fields.List(fields.Nested(AnomalySchema))


# =============================================================================
# SERIE TEMPORAL DE MÉTRICAS (§5, Fase 5) — para el gráfico de la SPA
# =============================================================================

class AssetMetricsQuerySchema(Schema):
    """Filtros opcionales de rango temporal (``?from=&to=``, §5)."""
    since = fields.DateTime(data_key="from", load_default=None, format="iso")
    until = fields.DateTime(data_key="to", load_default=None, format="iso")

    @post_load
    def normalize_range(self, data, **kwargs):
        """Normaliza ``since``/``until`` a naive-UTC, igual que ``collectedAt`` en la ingesta."""
        for key in ("since", "until"):
            value = data.get(key)
            if value is not None and value.tzinfo is not None:
                data[key] = value.astimezone(timezone.utc).replace(tzinfo=None)
        return data


class AssetSnapshotPointSchema(Schema):
    """Un punto de la serie temporal: solo lo desnormalizado, sin el JSONB completo."""
    collectedAt = UTCDateTime()
    cpuPct = fields.Float(allow_none=True)
    memPct = fields.Float(allow_none=True)


class AssetMetricsResponseSchema(Schema):
    """Serie temporal de métricas de un activo, para el gráfico de la SPA."""
    snapshots = fields.List(fields.Nested(AssetSnapshotPointSchema))
