from marshmallow import Schema, ValidationError, fields, validate, validates_schema

import src.modules.system.config_reading as CR


class TrackedProductSchema(Schema):
    """Coordenadas CPE de un producto vigilado.

    Salen del espejo local de NVD (``GET /aegis/products``), no de una lista
    fija: son el ``vendor``/``product`` de un CPE tal cual los indexa la base
    de conocimiento de Themis.
    """
    vendor  = fields.String(required=True, validate=validate.Length(min=1, max=128))
    product = fields.String(required=True, validate=validate.Length(min=1, max=128))


class AegisTweaksSchema(Schema):
    """
    Parámetros opcionales que ajustan la generación de una píldora.

    Todos los campos son opcionales; cuando faltan, ``_build_user_prompt``
    aplica un texto de fallback razonable (ver services/pills.py).
    """
    company           = fields.String(load_default="", validate=validate.Length(max=128))
    sector            = fields.String(load_default="", validate=validate.Length(max=128))
    audienceLevel     = fields.String(
        load_default="mixed",
        validate=validate.OneOf(["technical", "mixed", "non-technical"]),
    )
    trackedProducts   = fields.List(fields.Nested(TrackedProductSchema), load_default=list)
    # Si va a true (por defecto), los productos se deducen del inventario de
    # los agentes de Hygeia y ``trackedProducts`` queda como alternativa.
    useHygeiaInventory = fields.Boolean(load_default=True)
    mentionContact    = fields.String(load_default="", validate=validate.Length(max=128))
    language          = fields.String(load_default="es", validate=validate.Length(max=8))
    tone              = fields.String(load_default="profesional", validate=validate.Length(max=64))
    topicFocus        = fields.String(load_default="", validate=validate.Length(max=256))
    # Tamaño de la empresa: bucket categórico y/o conteo exacto de empleados.
    companySize       = fields.String(
        load_default="", validate=validate.OneOf(["", "micro", "pequeña", "mediana"]),
    )
    employeeCount     = fields.Integer(load_default=None, allow_none=True, validate=validate.Range(min=1))
    # Región y marco legal aplicable (RGPD, ENS, NIS2, ...).
    jurisdiction      = fields.String(load_default="", validate=validate.Length(max=256))
    # Modelo de trabajo predominante, cambia la superficie de amenaza enfatizada.
    workModel         = fields.String(
        load_default="", validate=validate.OneOf(["", "remoto", "híbrido", "presencial"]),
    )
    # Descripción breve de un incidente reciente sufrido por la empresa (opcional).
    recentIncident    = fields.String(load_default="", validate=validate.Length(max=500))


class AegisOrgProfileSchema(Schema):
    """
    Perfil de organización de Aegis: valores estables que casi nunca cambian
    entre generaciones (empresa, contacto, tono, tamaño, jurisdicción, marcas
    habituales). Comparte nombres de campo con AegisTweaksSchema para que el
    frontend pueda precargar el formulario de generación sin traducirlos.
    """
    company           = fields.String(load_default="", validate=validate.Length(max=128))
    mentionContact    = fields.String(load_default="", validate=validate.Length(max=128))
    tone              = fields.String(load_default="profesional", validate=validate.Length(max=64))
    companySize       = fields.String(
        load_default="", validate=validate.OneOf(["", "micro", "pequeña", "mediana"]),
    )
    jurisdiction      = fields.String(load_default="", validate=validate.Length(max=256))
    language          = fields.String(load_default="es", validate=validate.Length(max=8))
    sector            = fields.String(load_default="", validate=validate.Length(max=128))
    workModel         = fields.String(
        load_default="", validate=validate.OneOf(["", "remoto", "híbrido", "presencial"]),
    )
    employeeCount     = fields.Integer(load_default=None, allow_none=True, validate=validate.Range(min=1))
    trackedProducts   = fields.List(fields.Nested(TrackedProductSchema), load_default=list)
    useHygeiaInventory = fields.Boolean(load_default=True)
    # Solo de salida: no es un campo del perfil sino del entorno (si el usuario
    # tiene algún agente de Hygeia que haya reportado inventario). El frontend
    # lo usa para decidir si pinta el interruptor de arriba. Sin ``dump_only``
    # el mismo esquema, que también valida el PUT, lo descartaría al serializar.
    hygeiaInventoryAvailable = fields.Boolean(dump_only=True)


class ProductSearchQuerySchema(Schema):
    """Búsqueda en el índice CPE que alimenta el selector de productos."""
    q     = fields.String(required=True, validate=validate.Length(min=2, max=64))
    limit = fields.Integer(load_default=20, validate=validate.Range(min=1, max=50))


class AegisGenerateRequestSchema(Schema):
    topicId = fields.Integer(required=True)
    tweaks = fields.Nested(AegisTweaksSchema, load_default=dict)


class DocumentIdQuerySchema(Schema):
    id = fields.Integer(required=True)


class AegisLinkSchema(Schema):
    text = fields.String(required=True, validate=validate.Length(min=1, max=200))
    url = fields.Url(required=True, schemes={"http", "https"})


class AegisTipUpdateSchema(Schema):
    headline = fields.String(required=True, validate=validate.Length(min=1, max=150))
    body = fields.String(required=True, validate=validate.Length(min=1))
    links = fields.List(fields.Nested(AegisLinkSchema), load_default=[])


class AegisQuizQuestionUpdateSchema(Schema):
    prompt = fields.String(required=True, validate=validate.Length(min=1, max=300))
    # El tope de opciones sale de features.aegis.optionsAmount, no de un
    # validate.Length: ese se evalúa al importar el módulo y congelaría el
    # valor hasta el siguiente reinicio, que es justo lo que se quiere evitar.
    options = fields.List(
        fields.String(validate=validate.Length(min=1, max=200)),
        required=True,
        validate=validate.Length(min=2),
    )
    correctIndex = fields.Integer(required=True, validate=validate.Range(min=0))

    @validates_schema
    def validate_options_and_correct_index(self, data, **kwargs):
        options = data.get("options") or []
        max_options = CR.aegis_config().options_amount
        if len(options) > max_options:
            raise ValidationError(
                f"una pregunta admite como mucho {max_options} opciones", field_name="options"
            )

        correct_index = data.get("correctIndex")
        if correct_index is not None and correct_index >= len(options):
            raise ValidationError(
                "correctIndex debe apuntar a una opción existente", field_name="correctIndex"
            )


class AegisPillUpdateSchema(Schema):
    subtitle = fields.String(required=True, validate=validate.Length(min=1, max=256))
    intro = fields.String(load_default="")
    closing = fields.String(load_default="")
    contactEmail = fields.String(load_default="", validate=validate.Length(max=128))
    company = fields.String(load_default="", validate=validate.Length(max=128))
    tips = fields.List(fields.Nested(AegisTipUpdateSchema), load_default=[])
    questions = fields.List(fields.Nested(AegisQuizQuestionUpdateSchema), load_default=[])

    @validates_schema
    def validate_question_count(self, data, **kwargs):
        """Mismo motivo que en las opciones: el tope se lee en tiempo de validación."""
        max_questions = CR.aegis_config().questions_amount
        if len(data.get("questions") or []) > max_questions:
            raise ValidationError(
                f"una píldora admite como mucho {max_questions} preguntas",
                field_name="questions",
            )


class ExportRequestBodySchema(Schema):
    format = fields.String(load_default="md", validate=validate.OneOf(["md", "json", "html"]))
    options = fields.Dict(load_default={})


class ExportDownloadQuerySchema(Schema):
    format = fields.String(load_default="md", validate=validate.OneOf(["md", "json", "html"]))
    inline = fields.Boolean(load_default=False)


class MarkdownExportQuerySchema(Schema):
    inline = fields.Boolean(load_default=False)
    noAlerts = fields.Boolean(load_default=False)


class GenerateResponseSchema(Schema):
    message = fields.String()
    documentId = fields.Integer()
    status = fields.String()


class DeleteDocumentResponseSchema(Schema):
    message = fields.String()
    documentId = fields.Integer()


class DocumentListResponseSchema(Schema):
    count = fields.Integer()
    documents = fields.List(fields.Dict())


class ProductItemSchema(Schema):
    """Un producto del índice CPE, tal como lo devuelve GET /aegis/products."""
    vendor      = fields.String()
    product     = fields.String()
    displayName = fields.String()


class ProductSearchResponseSchema(Schema):
    count    = fields.Integer()
    products = fields.List(fields.Nested(ProductItemSchema))


class FormatItemSchema(Schema):
    id = fields.String()
    name = fields.String()
    description = fields.String()
    mimetype = fields.String()
    extension = fields.String()
    features = fields.List(fields.String())
    coming_soon = fields.Boolean(load_default=False)


class ExportFormatsResponseSchema(Schema):
    default = fields.String()
    formats = fields.List(fields.Nested(FormatItemSchema))


class ExportResultResponseSchema(Schema):
    success = fields.Boolean()
    export = fields.Dict()
    document = fields.Dict()
    downloadUrl = fields.String()


# ============================================================================
# CAMPAÑAS DE CONCIENCIACIÓN
# ============================================================================

class DistributionListCreateSchema(Schema):
    name = fields.String(required=True, validate=validate.Length(min=1, max=128))


class RecipientInputSchema(Schema):
    email = fields.Email(required=True)
    name = fields.String(load_default="", validate=validate.Length(max=128))


class RecipientsAddSchema(Schema):
    recipients = fields.List(
        fields.Nested(RecipientInputSchema), required=True, validate=validate.Length(min=1, max=1000),
    )


class CampaignCreateSchema(Schema):
    documentId = fields.Integer(required=True)
    listId = fields.Integer(required=True)
    name = fields.String(required=True, validate=validate.Length(min=1, max=128))


class QuizTokenQuerySchema(Schema):
    t = fields.String(required=True, validate=validate.Length(min=1, max=128))


class QuizAnswerInputSchema(Schema):
    questionPosition = fields.Integer(required=True, validate=validate.Range(min=1))
    selectedIndex = fields.Integer(required=True, validate=validate.Range(min=0))


class QuizSubmitSchema(Schema):
    answers = fields.List(
        fields.Nested(QuizAnswerInputSchema), required=True, validate=validate.Length(min=1),
    )
