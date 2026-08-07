"""
Schemas Marshmallow del módulo accounts. Claves JSON en camelCase.

Los nombres llevan prefijo ``Account``/``Plan`` para no chocar en el
``components/schemas`` del OpenAPI con los de otros módulos.
"""

from marshmallow import Schema, fields, validate

from src.modules.shared.schemas import UTCDateTime


class PlanLimitValueSchema(Schema):
    """Un tope: cuánto y con qué periodicidad.

    ``value`` puede ser ``null``, y no es lo mismo que cero: ``null`` significa
    ilimitado y ``0`` significa que el plan no incluye la característica.
    """

    value = fields.Integer(allow_none=True)
    period = fields.String()


class PlanScopedLimitsSchema(Schema):
    """Topes agrupados por ámbito.

    ``holder`` es lo que se lleva quien contrata el plan; ``member``, lo que se
    lleva por herencia cada miembro de su organización.
    """

    holder = fields.Dict(keys=fields.String(), values=fields.Nested(PlanLimitValueSchema))
    member = fields.Dict(keys=fields.String(), values=fields.Nested(PlanLimitValueSchema))


class PlanCatalogItemSchema(Schema):
    """Un plan en el catálogo público."""

    id = fields.Integer()
    code = fields.String()
    name = fields.String()
    tagline = fields.String(allow_none=True)
    rank = fields.Integer()
    monthlyPriceCents = fields.Integer()
    orgAddonPriceCents = fields.Integer()
    currency = fields.String()
    isPublic = fields.Boolean()
    isDefault = fields.Boolean()
    limits = fields.Nested(PlanScopedLimitsSchema)


class PlanCatalogResponseSchema(Schema):
    plans = fields.List(fields.Nested(PlanCatalogItemSchema))


class PlanSummarySchema(Schema):
    """El plan aplicado, sin sus topes (van aparte, ya resueltos)."""

    id = fields.Integer()
    code = fields.String()
    name = fields.String()
    tagline = fields.String(allow_none=True)
    rank = fields.Integer()
    monthlyPriceCents = fields.Integer()
    orgAddonPriceCents = fields.Integer()
    currency = fields.String()
    isPublic = fields.Boolean()
    isDefault = fields.Boolean()


class OrganizationCreateRequestSchema(Schema):
    name = fields.String(required=True, validate=validate.Length(min=2, max=128))


class OrganizationSchema(Schema):
    id = fields.Integer()
    name = fields.String()
    slug = fields.String()
    ownerUserId = fields.Integer()
    memberCount = fields.Integer()
    createdAt = UTCDateTime()
    myRole = fields.String()
    isOwner = fields.Boolean()


class OrganizationMemberSchema(Schema):
    """Identidad y nada más.

    Ni escaneos, ni análisis, ni bóvedas: el dueño de una organización no ve
    los datos de su gente, y eso se vende como garantía.
    """

    userId = fields.Integer()
    username = fields.String()
    email = fields.String()
    fullName = fields.String()
    role = fields.String()
    joinedAt = UTCDateTime()


class OrganizationMemberListSchema(Schema):
    members = fields.List(fields.Nested(OrganizationMemberSchema))


class MyOrganizationResponseSchema(Schema):
    """Estado de pertenencia del usuario. ``null`` = no está en ninguna.

    Va envuelto y con 200 en vez de responder 404 cuando no hay ninguna: "no
    perteneces a ninguna organización" es un **estado normal**, no un recurso
    que falte. Con el 404, la mayoría de las cuentas veían un error rojo en la
    consola del navegador en cada carga — y una consola llena de rojos de
    mentira es una consola en la que ya no se ve el rojo de verdad.
    """

    organization = fields.Nested(OrganizationSchema, allow_none=True)


class UsageEntrySchema(Schema):
    """Consumo de una clave.

    ``used`` puede ser ``null``: significa "todavía no sabemos medir esto", que
    no es lo mismo que cero.
    """

    value = fields.Integer(allow_none=True)
    period = fields.String()
    used = fields.Integer(allow_none=True)
    resetsAt = fields.Date(allow_none=True)
    exceeded = fields.Boolean()


class UsageResponseSchema(Schema):
    planCode = fields.String()
    usage = fields.Dict(keys=fields.String(), values=fields.Nested(UsageEntrySchema))


class EffectivePlanResponseSchema(Schema):
    """Plan efectivo de quien pregunta, más el estado de su suscripción.

    ``plan`` y ``status`` pueden no casar, y es intencionado: un Gold caducado
    devuelve el plan Freemium con ``status="active"`` y un ``currentPeriodEnd``
    en el pasado. Con eso el cliente escribe "tu plan terminó el 1 de
    septiembre" en vez de degradar en silencio.
    """

    plan = fields.Nested(PlanSummarySchema)
    source = fields.String()
    status = fields.String(allow_none=True)
    isEffective = fields.Boolean()
    currentPeriodEnd = UTCDateTime(allow_none=True)
    cancelAtPeriodEnd = fields.Boolean()
    graceUntil = UTCDateTime(allow_none=True)
    organizationEnabled = fields.Boolean()
    limits = fields.Dict(keys=fields.String(), values=fields.Nested(PlanLimitValueSchema))


class InvitationCreateRequestSchema(Schema):
    email = fields.Email(required=True, validate=validate.Length(max=128))


class InvitationSchema(Schema):
    id = fields.Integer()
    email = fields.String()
    status = fields.String()
    createdAt = UTCDateTime()
    expiresAt = UTCDateTime()
    acceptedAt = UTCDateTime(allow_none=True)
    createdUserId = fields.Integer(allow_none=True)


class InvitationListSchema(Schema):
    invitations = fields.List(fields.Nested(InvitationSchema))


class InvitationAcceptRequestSchema(Schema):
    token = fields.String(required=True)


class InvitationAcceptResponseSchema(Schema):
    message = fields.String()
    organizationId = fields.Integer()


class SubscriptionSchema(Schema):
    id = fields.Integer()
    userId = fields.Integer()
    planId = fields.Integer()
    status = fields.String()
    organizationEnabled = fields.Boolean()
    startedAt = UTCDateTime()
    currentPeriodStart = UTCDateTime(allow_none=True)
    currentPeriodEnd = UTCDateTime(allow_none=True)
    cancelAtPeriodEnd = fields.Boolean()
    graceUntil = UTCDateTime(allow_none=True)


class SubscriptionStateSchema(Schema):
    """Suscripción de una cuenta. ``null`` = no tiene, luego está en el plan
    por defecto — mismo criterio que ``MyOrganizationResponseSchema``."""

    subscription = fields.Nested(SubscriptionSchema, allow_none=True)


class SubscriptionOperationSchema(Schema):
    """Una de las seis operaciones del ciclo de vida, y sus argumentos.

    El cuerpo nombra la INTENCIÓN, no el estado final. Aceptar un ``status``
    a pelo dejaría escribir combinaciones imposibles (``canceled`` con
    ``graceUntil``) y perdería el sentido de lo que se hizo.
    """

    operation = fields.String(
        required=True,
        validate=validate.OneOf(
            ["activate", "start_trial", "mark_past_due", "cancel", "resume", "expire"]
        ),
    )
    planCode = fields.String(load_default=None)
    organizationEnabled = fields.Boolean(load_default=False)
    periodEnd = fields.DateTime(load_default=None)
    graceUntil = fields.DateTime(load_default=None)
    immediate = fields.Boolean(load_default=False)


# =========================================================================
# GESTOR DEL CATÁLOGO (root)
# =========================================================================


class PlanWriteSchema(Schema):
    """Alta de un plan."""

    code = fields.String(required=True, validate=validate.Length(min=2, max=32))
    name = fields.String(required=True, validate=validate.Length(min=2, max=64))
    tagline = fields.String(load_default=None, allow_none=True,
                            validate=validate.Length(max=160))
    rank = fields.Integer(load_default=0)
    monthly_price_cents = fields.Integer(data_key="monthlyPriceCents", load_default=0,
                                         validate=validate.Range(min=0))
    org_addon_price_cents = fields.Integer(data_key="orgAddonPriceCents", load_default=0,
                                           validate=validate.Range(min=0))
    currency = fields.String(load_default="EUR", validate=validate.Length(equal=3))
    is_public = fields.Boolean(data_key="isPublic", load_default=True)


class PlanUpdateSchema(Schema):
    """Edición de un plan. **Sin `code`**: cambiarlo rompería las asignaciones
    que lo nombran y, el día de la pasarela, su correspondencia con ella. Si
    hace falta otro código, es otro plan."""

    name = fields.String(validate=validate.Length(min=2, max=64))
    tagline = fields.String(allow_none=True, validate=validate.Length(max=160))
    rank = fields.Integer()
    monthly_price_cents = fields.Integer(data_key="monthlyPriceCents",
                                         validate=validate.Range(min=0))
    org_addon_price_cents = fields.Integer(data_key="orgAddonPriceCents",
                                           validate=validate.Range(min=0))
    currency = fields.String(validate=validate.Length(equal=3))
    is_public = fields.Boolean(data_key="isPublic")


class PlanLimitWriteSchema(Schema):
    """Un tope. ``period`` no se acepta: lo dicta el catálogo de claves, no el
    formulario — si lo eligiera quien rellena, un contador mensual podría
    acabar declarado como existencias."""

    limitKey = fields.String(required=True)
    scope = fields.String(load_default="holder", validate=validate.OneOf(["holder", "member"]))
    value = fields.Integer(allow_none=True, load_default=None, validate=validate.Range(min=0))


class PlanLimitsWriteSchema(Schema):
    limits = fields.List(fields.Nested(PlanLimitWriteSchema), required=True)


class PlanLimitsResponseSchema(Schema):
    planCode = fields.String()
    limits = fields.Nested(PlanScopedLimitsSchema)


class LimitCatalogEntrySchema(Schema):
    key = fields.String()
    period = fields.String()


class LimitCatalogResponseSchema(Schema):
    """Las claves que existen, para que el panel las ofrezca en un desplegable
    en vez de dejar escribirlas a mano."""

    keys = fields.List(fields.Nested(LimitCatalogEntrySchema))
