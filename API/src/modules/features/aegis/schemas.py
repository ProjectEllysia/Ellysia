from marshmallow import Schema, ValidationError, fields, validate, validates_schema


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
    associatedBrands  = fields.List(fields.String(), load_default=list)
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
    associatedBrands  = fields.List(fields.String(), load_default=list)


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
    options = fields.List(
        fields.String(validate=validate.Length(min=1, max=200)),
        required=True,
        validate=validate.Length(min=2, max=4),
    )
    correctIndex = fields.Integer(required=True, validate=validate.Range(min=0))

    @validates_schema
    def validate_correct_index_in_range(self, data, **kwargs):
        options = data.get("options") or []
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


class BrandsResponseSchema(Schema):
    count = fields.Integer()
    brands = fields.List(fields.Dict())


class BrandItemSchema(Schema):
    label = fields.String()
    circl_vendor = fields.String()
    circl_product = fields.String()
    aliases = fields.List(fields.String())


class BrandsCatalogResponseSchema(Schema):
    count = fields.Integer()
    brands = fields.List(fields.Nested(BrandItemSchema))


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
