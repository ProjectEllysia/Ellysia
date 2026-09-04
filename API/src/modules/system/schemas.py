from marshmallow import Schema, fields, validate


class HelloResponseSchema(Schema):
    message = fields.String()
    status = fields.String()
    version = fields.String()


class SystemInfoSchema(Schema):
    name = fields.String()
    version = fields.String()
    environment = fields.String()
    pythonVersion = fields.String()


class CpuInfoSchema(Schema):
    percent = fields.Float()


class MemoryInfoSchema(Schema):
    total = fields.Integer()
    available = fields.Integer()
    percent = fields.Float()
    used = fields.Integer()
    free = fields.Integer()


class DiskInfoSchema(Schema):
    total = fields.Integer()
    used = fields.Integer()
    free = fields.Integer()
    percent = fields.Float()


class SystemStatusSchema(Schema):
    cpu = fields.Nested(CpuInfoSchema)
    memory = fields.Nested(MemoryInfoSchema)
    disk = fields.Nested(DiskInfoSchema)
    status = fields.String()


class ConfigUpdateSchema(Schema):
    new_config = fields.Dict(required=True)


class TaskSchema(Schema):
    id = fields.String()
    name = fields.String()
    category = fields.String()
    externalId = fields.String(allow_none=True)
    status = fields.String()
    progress = fields.Integer()
    createdAt = fields.String(allow_none=True)
    startedAt = fields.String(allow_none=True)
    finishedAt = fields.String(allow_none=True)
    error = fields.String(allow_none=True)


class TaskQueueStatusSchema(Schema):
    maxWorkers = fields.Integer()
    aliveWorkers = fields.Integer()
    runningCount = fields.Integer()
    pendingCount = fields.Integer()
    historyCount = fields.Integer()


class TaskQueueConfigSchema(Schema):
    max_workers = fields.Integer(required=True)


class TaskListResponseSchema(Schema):
    tasks = fields.List(fields.Nested(TaskSchema))
    totalCount = fields.Integer()


class TaskPaginationQuerySchema(Schema):
    page = fields.Integer(load_default=1, validate=lambda n: n >= 1)
    per_page = fields.Integer(load_default=20, validate=lambda n: 1 <= n <= 100)
    category = fields.String(load_default=None)
    status = fields.String(load_default=None)


class LogQuerySchema(Schema):
    """Filtros de lectura del log del sistema.

    Las fechas del fichero actual no incluyen zona horaria; el servicio las
    interpreta en la zona horaria local de la API y la devuelve en la respuesta.
    """

    page = fields.Integer(load_default=1, validate=validate.Range(min=1))
    per_page = fields.Integer(load_default=100, validate=validate.Range(min=1, max=500))
    position = fields.String(
        load_default="tail",
        validate=validate.OneOf(["head", "tail"]),
    )
    from_ = fields.DateTime(data_key="from", load_default=None, allow_none=True)
    to = fields.DateTime(load_default=None, allow_none=True)
    last_minutes = fields.Integer(
        data_key="lastMinutes",
        load_default=None,
        allow_none=True,
        validate=validate.Range(min=1, max=525_600),
    )
    """Ventana relativa al reloj del servidor: ``lastMinutes=30`` es la media
    hora anterior. Es incompatible con ``from``, y existe porque las marcas del
    log son hora local de la API: si la calculara el navegador, un
    administrador conectado desde otro huso pediría una ventana desplazada.
    """

    level = fields.String(
        load_default=None,
        allow_none=True,
        validate=validate.OneOf(["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]),
    )
    min_level = fields.String(
        data_key="minLevel",
        load_default=None,
        allow_none=True,
        validate=validate.OneOf(["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]),
    )
    """Severidad mínima: ``minLevel=WARNING`` trae WARNING, ERROR y CRITICAL.

    Complementa a ``level``, que sigue siendo de valor exacto. Si se envían
    los dos, se aplican ambos.
    """

    contains = fields.String(
        load_default=None,
        allow_none=True,
        validate=validate.Length(max=200),
    )
    snapshot = fields.String(
        load_default=None,
        allow_none=True,
        validate=validate.Length(max=512),
    )


class SystemLogsResponseSchema(Schema):
    compression = fields.String(required=True)
    encoding = fields.String(required=True)
    content = fields.String(required=True)
    totalBytes = fields.Integer(required=True)
    returnedBytes = fields.Integer(required=True)
    compressedBytes = fields.Integer(required=True)
    truncated = fields.Boolean(required=True)
    totalLines = fields.Integer(required=True)
    returnedLines = fields.Integer(required=True)
    levelCounts = fields.Dict(
        keys=fields.String(),
        values=fields.Integer(),
        required=True,
    )
    page = fields.Integer(required=True)
    perPage = fields.Integer(required=True)
    totalPages = fields.Integer(required=True)
    position = fields.String(required=True)
    hasPrevious = fields.Boolean(required=True)
    hasNext = fields.Boolean(required=True)
    snapshot = fields.String(required=True)
    snapshotBytes = fields.Integer(required=True)
    currentBytes = fields.Integer(required=True)
    lastModified = fields.String(required=True)
    windowStart = fields.String(required=True)
    timeZone = fields.String(required=True)
    firstLine = fields.Integer(allow_none=True)
    lastLine = fields.Integer(allow_none=True)


class AIStrategyModelsSchema(Schema):
    """Una estrategia de scribe y los modelos que su proveedor sirve ahora.

    ``isReachable`` en false no es un error de la petición: significa que a
    ese proveedor concreto no se le pudo preguntar (sin credenciales, servidor
    apagado, red cortada) y que ``error`` dice por qué. El resto de filas
    siguen siendo válidas — tener OpenAI caído no impide elegir modelo de
    Ollama.
    """

    strategy = fields.String(required=True)
    configuredModel = fields.String(required=True)
    models = fields.List(fields.String(), required=True)
    isReachable = fields.Boolean(required=True)
    error = fields.String(required=True)


class AIModelsResponseSchema(Schema):
    strategies = fields.List(fields.Nested(AIStrategyModelsSchema), required=True)
