"""
Schemas Marshmallow del módulo accounts. Claves JSON en camelCase.

Los nombres llevan prefijo ``Account``/``Plan`` para no chocar en el
``components/schemas`` del OpenAPI con los de otros módulos.
"""

from marshmallow import Schema, fields

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
