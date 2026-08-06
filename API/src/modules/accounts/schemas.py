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
