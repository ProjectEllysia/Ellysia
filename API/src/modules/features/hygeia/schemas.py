"""
Schemas Marshmallow del módulo Hygeia. Claves de respuesta en camelCase,
por convención del proyecto.
"""

from datetime import timezone

from marshmallow import EXCLUDE, Schema, ValidationError, fields, post_load, validate, validates_schema

import src.modules.system.config_reading as CR
from src.modules.shared.schemas import UTCDateTime


TAG_COLORS = ("slate", "green", "teal", "blue", "violet", "amber", "red", "pink")
"""Paleta cerrada de colores de etiqueta.

Se guarda el **nombre** del color, no un valor CSS: el frontend lo traduce a
la variable que toque, así que cambiar el tema (o el matiz exacto de "amber")
no obliga a reescribir ninguna fila. Cerrada, además, porque una paleta libre
acaba siendo diez tonos de gris indistinguibles en un badge de 11px.
"""


class TagSchema(Schema):
    """Vista de una etiqueta.

    ``assetCount`` solo lo rellena el listado del catálogo; las etiquetas
    anidadas dentro de un activo lo omiten (allí no significaría nada).
    """
    id = fields.Integer()
    name = fields.String()
    color = fields.String()
    tagType = fields.String()
    assetCount = fields.Integer()


class TagCreateRequestSchema(Schema):
    """Alta de una etiqueta personal."""
    name = fields.String(required=True, validate=validate.Length(min=1, max=48))
    color = fields.String(load_default="slate", validate=validate.OneOf(TAG_COLORS))


class TagListResponseSchema(Schema):
    """Catálogo visible para el usuario: las de sistema más las suyas."""
    tags = fields.List(fields.Nested(TagSchema))


class AssetTagsRequestSchema(Schema):
    """Conjunto completo de etiquetas de un activo.

    Es un reemplazo, no un añadido: lo que llega es la lista definitiva, y
    las que no aparezcan se quitan. Una sola operación cubre poner, quitar y
    reordenar sin que el cliente tenga que calcular diferencias.
    """
    tagIds = fields.List(fields.Integer(), required=True)


class InventoryReportRequestSchema(Schema):
    """Petición del informe PDF del inventario de activos.

    ``scope`` distingue "mis activos" de "los de toda mi organización"; el
    segundo solo lo puede pedir el dueño, y de eso se encarga el manager, no
    este schema. ``includeSoftware`` viene desactivado porque el anexo de
    software puede multiplicar por veinte el tamaño del documento.
    """
    scope = fields.String(
        load_default="user", validate=validate.OneOf(("user", "organization")),
    )
    includeSoftware = fields.Boolean(load_default=False)


class AssetCreateRequestSchema(Schema):
    """Alta de un nuevo activo a monitorizar."""
    hostname = fields.String(required=True, validate=validate.Length(min=1, max=255))
    os = fields.String(load_default=None, validate=validate.Length(max=64))
    labels = fields.Dict(load_default=dict)
    # Por defecto se espera un host siempre encendido: es el comportamiento
    # que tenía todo activo antes de que existiera esta propiedad.
    isPersistent = fields.Boolean(load_default=True)


class AssetUpdateRequestSchema(Schema):
    """Modificación de un activo. Solo la expectativa de encendido es editable."""
    isPersistent = fields.Boolean(required=True)


class AssetSchema(Schema):
    """Vista de un activo monitorizado (nunca incluye la clave de agente)."""
    id = fields.Integer()
    hostname = fields.String()
    os = fields.String(allow_none=True)
    kernel = fields.String(allow_none=True)
    # Identidad del host, no una métrica (§P29): null significa "el agente
    # nunca lo ha reportado" (agente anterior a esta necesidad, o su
    # `gopsutil` no supo detectarlo), no "no es una máquina virtual".
    virtualizationSystem = fields.String(allow_none=True)
    virtualizationRole = fields.String(allow_none=True)
    labels = fields.Dict()
    tags = fields.List(fields.Nested(TagSchema))
    status = fields.String()
    isPersistent = fields.Boolean()
    # Hallazgos del último análisis Lybra del activo, o null si nunca se
    # analizó: lo que la rejilla de agentes de Themis pinta en cada tarjeta.
    totalFindings = fields.Integer(allow_none=True, load_default=None)
    lastSeenAt = UTCDateTime(allow_none=True)
    uptimeSec = fields.Integer(allow_none=True)
    agentVersion = fields.String(allow_none=True)
    # Aviso, no validación: null significa "no se puede saber" (nunca ha
    # reportado versión, o su versión / el suelo configurado no encajan en
    # el formato X.Y.Z...), y no se pinta como si fuera un "no" (services/agent_freshness.py).
    agentOutdated = fields.Boolean(allow_none=True, load_default=None)
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
    # Texto libre en vez de un OneOf (§P29): gopsutil puede devolver valores
    # nuevos que el servidor todavía no conoce, y un agente con una versión
    # de gopsutil distinta no debe ver su heartbeat rechazado por eso. Solo
    # el literal "guest" dispara el mensaje de máquina virtual; cualquier
    # otro valor (incluido uno que no se reconozca) se trata como "host o
    # desconocido" — la misma doctrina de "ante la duda, no se sabe" que ya
    # sigue el comparador de versiones de agente.
    virtualizationSystem = fields.String(load_default=None, validate=validate.Length(max=32))
    virtualizationRole = fields.String(load_default=None, validate=validate.Length(max=32))


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


class PowerMetricsSchema(_IngestSchema):
    """Consumo eléctrico del host, tal como lo reporta el agente.

    Los tres campos son ``required`` dentro del bloque, mientras que el
    bloque entero es opcional en ``MetricsSchema``: no saber la potencia es
    legítimo y se expresa omitiendo ``power``; mandar unos vatios sin decir
    de dónde salieron no lo es.
    """
    watts = fields.Float(required=True, validate=validate.Range(min=0))
    estimated = fields.Boolean(required=True)
    source = fields.String(required=True, validate=validate.Length(min=1, max=64))


class MetricsSchema(_IngestSchema):
    """Payload completo de métricas de un heartbeat (§11)."""
    cpu = fields.Nested(CpuMetricsSchema, required=True)
    memory = fields.Nested(MemoryMetricsSchema, required=True)
    disk = fields.List(fields.Nested(DiskMountSchema), load_default=list)
    network = fields.List(fields.Nested(NetworkInterfaceSchema), load_default=list)
    processes = fields.Nested(ProcessesMetricsSchema, load_default=dict)
    # Opcional: un agente sin ninguna fuente de potencia compatible (o más
    # viejo que el contrato) simplemente no lo manda, y eso no rompe nada.
    power = fields.Nested(PowerMetricsSchema, load_default=None, allow_none=True)

    @validates_schema
    def validate_array_limits(self, data, **kwargs):
        """
        Acota disk/network/topCpu/topMem contra los límites configurables de
        ``features.hygeia.limits`` (§16.1).

        Se leen con ``CR`` en cada validación (no se hornean al importar el
        módulo) para que un cambio vía ``PUT /system`` surta efecto sin
        reiniciar la API, igual que el resto de la configuración.
        """
        max_disk = CR.hygeia_limits().max_disk_mounts
        if len(data.get("disk", [])) > max_disk:
            raise ValidationError(
                f"disk excede el máximo de {max_disk} puntos de montaje", field_name="disk",
            )

        max_net = CR.hygeia_limits().max_net_interfaces
        if len(data.get("network", [])) > max_net:
            raise ValidationError(
                f"network excede el máximo de {max_net} interfaces", field_name="network",
            )

        max_procs = CR.hygeia_limits().max_processes
        processes = data.get("processes") or {}
        if len(processes.get("topCpu", [])) > max_procs:
            raise ValidationError(
                f"topCpu excede el máximo de {max_procs} procesos", field_name="processes",
            )
        if len(processes.get("topMem", [])) > max_procs:
            raise ValidationError(
                f"topMem excede el máximo de {max_procs} procesos", field_name="processes",
            )


class SoftwareSchema(_IngestSchema):
    """Una aplicación instalada, tal como la reporta el escaneo de inventario del agente."""
    name = fields.String(required=True, validate=validate.Length(min=1, max=512))
    type = fields.String(load_default=None, validate=validate.Length(max=32))
    vendor = fields.String(load_default=None, validate=validate.Length(max=256))
    version = fields.String(load_default=None, validate=validate.Length(max=128))
    guid = fields.String(load_default=None, validate=validate.Length(max=128))
    # String, no DateTime: viaja tal cual dentro del JSONB `inventory` (nunca
    # se computa contra ella, a diferencia de `collectedAt`), y un `datetime`
    # ahí dentro no sería serializable a JSON al guardar la fila.
    installedAt = fields.String(load_default=None, allow_none=True, validate=validate.Length(max=32))
    installPath = fields.String(load_default=None, validate=validate.Length(max=1024))
    architecture = fields.String(load_default=None, validate=validate.Length(max=16))
    sizeBytes = fields.Integer(load_default=None, validate=validate.Range(min=0))
    status = fields.String(load_default=None, validate=validate.Length(max=32))
    source = fields.String(load_default=None, validate=validate.Length(max=32))


class InventorySchema(_IngestSchema):
    """Inventario de software de un escaneo (§ contrato de ingesta v1.0).

    Sin "delta": cada escaneo trae el estado completo de software instalado,
    nunca un diff — el backend reemplaza por completo el inventario anterior.
    """
    software = fields.List(fields.Nested(SoftwareSchema), required=True)

    @validates_schema
    def validate_max_items(self, data, **kwargs):
        """Acota ``software`` contra ``features.hygeia.limits.maxInventoryItems`` (§16.1)."""
        max_items = CR.hygeia_limits().max_inventory_items
        if len(data.get("software", [])) > max_items:
            raise ValidationError(
                f"software excede el máximo de {max_items} elementos", field_name="software",
            )


class IngestRequestSchema(_IngestSchema):
    """Heartbeat completo enviado por un agente Hygeia (§11)."""
    agentVersion = fields.String(required=True, validate=validate.Length(min=1, max=32))
    collectedAt = fields.DateTime(required=True, format="iso")
    host = fields.Nested(HostInfoSchema, required=True)
    metrics = fields.Nested(MetricsSchema, required=True)
    localAlerts = fields.List(fields.Raw(), load_default=list)
    # Opcional (omitempty en el agente): solo presente tras un escaneo de
    # software reciente, no en cada heartbeat (§ contrato de ingesta v1.0).
    inventory = fields.Nested(InventorySchema, load_default=None, allow_none=True)

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
    """Filtros opcionales de rango temporal (``?from=&to=``, §5).

    El rango se aplica sobre ``receivedAt`` (reloj del servidor), no sobre
    ``collectedAt`` (reloj del agente): es el mismo eje por el que se ordena
    y se poda la serie, así que ventana y orden no pueden discrepar por una
    deriva de reloj del agente.
    """
    since = fields.DateTime(data_key="from", load_default=None, format="iso")
    until = fields.DateTime(data_key="to", load_default=None, format="iso")
    # Tamaño del cubo de agregación en segundos. Sin él la serie viaja cruda
    # (un punto por heartbeat); con él, un punto por cubo con el máximo de
    # cada métrica, para que ventanas largas (24 h/7 d) no se recorten contra
    # el tope de puntos y los spikes sigan siendo visibles.
    bucket = fields.Integer(load_default=None, validate=validate.Range(min=1))

    @post_load
    def normalize_range(self, data, **kwargs):
        """Normaliza ``since``/``until`` a naive-UTC, igual que ``collectedAt`` en la ingesta."""
        for key in ("since", "until"):
            value = data.get(key)
            if value is not None and value.tzinfo is not None:
                data[key] = value.astimezone(timezone.utc).replace(tzinfo=None)
        return data


class AssetSnapshotPointSchema(Schema):
    """
    Un punto de la serie temporal: solo lo desnormalizado, sin el JSONB completo.

    Todo lo que no sea el instante es nullable: ``NULL`` significa "el agente
    no reportó esto" (Windows no manda ``load1``, un host sin interfaces
    visibles no manda red), y las filas anteriores a la instrumentación de
    cada columna también llegan vacías. El consumidor debe tratar cada campo
    como opcional y omitir la traza en lugar de dibujar un cero.
    """
    collectedAt = UTCDateTime()
    receivedAt = UTCDateTime()
    cpuPct = fields.Float(allow_none=True)
    memPct = fields.Float(allow_none=True)
    swapPct = fields.Float(allow_none=True)
    load1 = fields.Float(allow_none=True)
    diskMaxPct = fields.Float(allow_none=True)
    diskMaxMount = fields.String(allow_none=True)
    netRxBps = fields.Integer(allow_none=True)
    netTxBps = fields.Integer(allow_none=True)
    powerWatts = fields.Float(allow_none=True)
    # En la serie por cubos estos dos siempre llegan a null (P18): no son
    # magnitudes que se puedan promediar ni maximizar dentro de un cubo. En
    # la serie cruda sí viajan, uno por snapshot.
    powerEstimated = fields.Boolean(allow_none=True)
    powerSource = fields.String(allow_none=True)


class AssetMetricsResponseSchema(Schema):
    """Serie temporal de métricas de un activo, para el gráfico de la SPA.

    ``bucket`` ecoa el cubo de agregación usado: ``null`` = serie cruda (un
    punto por heartbeat), un entero = un punto por cubo con el máximo de cada
    métrica. Así el consumidor rotula la ventana con honestidad sin adivinar.
    """
    snapshots = fields.List(fields.Nested(AssetSnapshotPointSchema))
    truncated = fields.Boolean(
        metadata={"description": "La serie se recortó al máximo de puntos: "
                                 "hay más histórico del que se devuelve."},
    )
    bucket = fields.Integer(allow_none=True, load_default=None)


class AssetLatestResponseSchema(Schema):
    """
    Últimas métricas completas de un activo — lo que la serie temporal no cabe.

    Aquí viaja el payload íntegro del último heartbeat: uso por punto de
    montaje, tráfico por interfaz, procesos top y uso por núcleo. Reutiliza
    ``MetricsSchema``, el mismo schema con el que se validó al entrar, en
    dirección de volcado: un solo contrato, documentado una vez.

    Los tres campos son nullable porque un activo recién dado de alta existe
    pero aún no ha reportado — un estado legítimo, no un error.
    """
    collectedAt = UTCDateTime(allow_none=True)
    receivedAt = UTCDateTime(allow_none=True)
    metrics = fields.Nested(MetricsSchema, allow_none=True)


# =============================================================================
# ENERGÍA Y COSTE (Fase 3, §hygeia-power) — resumen de consumo de un activo
# =============================================================================

class CurrentPowerSchema(Schema):
    """Última lectura de potencia conocida, tal como la deja el propio heartbeat.

    ``watts`` nulo es "este activo no expone ninguna fuente de potencia
    compatible", no un error; los otros dos campos solo tienen sentido junto
    a una lectura real, así que viajan nulos en el mismo caso.
    """
    watts = fields.Float(allow_none=True)
    estimated = fields.Boolean(allow_none=True)
    source = fields.String(allow_none=True)


class PowerPeriodSchema(Schema):
    """
    Energía y coste de un periodo, con su procedencia (P24).

    ``classification`` distingue tres casos: ``"observed"`` (el periodo cabe
    en la retención y la cobertura de datos es alta), ``"observed_partial"``
    (cabe pero con cobertura baja — se da la cifra igual, marcada) y
    ``"projected"`` (el periodo excede la retención configurada y la cifra
    se extrapola desde la media observada). Un activo sin ni un intervalo
    válido en el periodo devuelve ``averageWatts``/``kwh``/``cost`` a
    ``None`` — no hay cifra que dar, y no es cero.
    """
    averageWatts = fields.Float(allow_none=True)
    kwh = fields.Float(allow_none=True)
    cost = fields.Float(allow_none=True)
    currency = fields.String()
    classification = fields.String()
    coverageFraction = fields.Float(allow_none=True)
    periodFrom = UTCDateTime()
    periodTo = UTCDateTime()


class PowerSummaryResponseSchema(Schema):
    """
    Resumen de consumo de un activo para la ficha (P25): la lectura actual
    más energía y coste de 24 h, 7 d y 30 d, y una proyección mensual.

    ``day``/``week``/``month`` cubren como mucho la ventana de retención
    configurada (30 días por defecto): más allá de ahí no hay histórico que
    observar. ``monthProjected`` sí extrapola siempre, y por eso se marca
    ``"projected"`` sin excepción: contra treinta días de retención, un mes
    natural nunca es dato observado completo.
    """
    current = fields.Nested(CurrentPowerSchema)
    day = fields.Nested(PowerPeriodSchema)
    week = fields.Nested(PowerPeriodSchema)
    month = fields.Nested(PowerPeriodSchema)
    monthProjected = fields.Nested(PowerPeriodSchema)


# =============================================================================
# INVENTARIO DE SOFTWARE — reemplaza por completo en cada escaneo, sin delta
# =============================================================================

class SoftwareViewSchema(Schema):
    """Vista de una aplicación instalada (respuesta, no ingesta)."""
    name = fields.String()
    type = fields.String(allow_none=True)
    vendor = fields.String(allow_none=True)
    version = fields.String(allow_none=True)
    guid = fields.String(allow_none=True)
    installedAt = fields.String(allow_none=True)
    installPath = fields.String(allow_none=True)
    architecture = fields.String(allow_none=True)
    sizeBytes = fields.Integer(allow_none=True)
    status = fields.String(allow_none=True)
    source = fields.String(allow_none=True)


class AssetInventoryResponseSchema(Schema):
    """Último inventario de software conocido de un activo.

    ``collectedAt`` y ``software`` son nulos/vacíos si el activo nunca ha
    mandado un escaneo de inventario (agente antiguo, o aún no le tocó el
    primer escaneo) — no es un error, es un estado legítimo.
    """
    collectedAt = UTCDateTime(allow_none=True)
    software = fields.List(fields.Nested(SoftwareViewSchema))


# =============================================================================
# ANÁLISIS DEL INVENTARIO CON LYBRA (Fase I) — el resumen; el desglose vive
# en Themis, que ya tiene la interfaz para presentarlo
# =============================================================================

class AnalyzeInventoryResponseSchema(Schema):
    """Confirmación de que el análisis se ha encolado."""
    scanId = fields.Integer()


class InventoryAnalysisSummarySchema(Schema):
    """Resumen del último análisis de inventario de un activo.

    ``scanId`` nulo significa "nunca se ha analizado" — estado inicial de
    todo activo, no un error. Con un escaneo en curso (``status`` a
    ``pending``/``running``) los recuentos llegan a cero hasta que termina.
    """
    scanId          = fields.Integer(allow_none=True)
    status          = fields.String(allow_none=True)
    startedAt       = fields.String(allow_none=True)
    finishedAt      = fields.String(allow_none=True)
    totalFindings   = fields.Integer(load_default=0)
    # {"CRITICAL": 2, "HIGH": 5, ...} — solo los niveles con al menos un
    # hallazgo, para no obligar al cliente a filtrar ceros.
    byPriority      = fields.Dict(keys=fields.String(), values=fields.Integer())
    confirmedCount  = fields.Integer(load_default=0)
    vulnerableCount = fields.Integer(load_default=0)
    # Paquetes inventariados analizados (uno por entrada del inventario, se le
    # haya resuelto un CPE o no). Con `vulnerableCount` a cero permite avisar
    # de que "sin detecciones" no equivale a "verificado limpio".
    packageCount    = fields.Integer(load_default=0)
    # De esos, cuántos el matcher no pudo ni identificar (Fase I-b,
    # `Finding.cpe_resolved=False`) — el número real detrás del aviso, en vez
    # de "puede que alguno no se haya reconocido".
    unresolvedCount = fields.Integer(load_default=0)
