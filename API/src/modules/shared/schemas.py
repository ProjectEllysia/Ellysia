from datetime import timezone

from marshmallow import Schema, ValidationError, fields, validate

from ._white_label import WhiteLabelLevel, validate_brand_color, validate_logo_data_uri


class UTCDateTime(fields.DateTime):
    """``fields.DateTime`` que asume naive-UTC y serializa con sufijo de zona horaria.

    ``fields.DateTime`` serializa vía ``datetime.isoformat()``, que no añade
    sufijo de zona horaria a un ``datetime`` naive. Todas las columnas
    ``DateTime`` del esquema son naive-UTC (ver ``utcnow_naive``), así que sin
    este field el frontend (``new Date(iso)``) interpreta la cadena como hora
    local en vez de UTC. Adjunta ``tzinfo=UTC`` antes de serializar para que
    el resultado quede sin ambigüedad (p. ej. ``"...T09:34:05+00:00"``).
    """

    def _serialize(self, value, attr, obj, **kwargs):
        if value is not None and value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return super()._serialize(value, attr, obj, **kwargs)


class ErrorSchema(Schema):
    error = fields.String()
    error_description = fields.String()
    code = fields.Integer(dump_default=None)


class SuccessMessageSchema(Schema):
    message = fields.String()


class PaginationQuerySchema(Schema):
    page = fields.Integer(load_default=1, validate=validate.Range(min=1))
    per_page = fields.Integer(load_default=10, validate=validate.Range(min=1, max=100))


def _validate_brand_logo(value: str) -> None:
    """Adapta la validación compartida del logo al contrato de marshmallow."""
    if not value:
        return
    try:
        validate_logo_data_uri(value)
    except ValueError as exc:
        raise ValidationError(str(exc)) from exc


def _validate_brand_color_field(value: str) -> None:
    """Adapta la validación compartida del color al contrato de marshmallow."""
    if not value:
        return
    try:
        validate_brand_color(value)
    except ValueError as exc:
        raise ValidationError(str(exc)) from exc


class WhiteLabelSchemaMixin:
    """
    Campos de white-labeling para el esquema de cualquier módulo que lo ofrezca.

    Se hereda junto a ``Schema`` (``class MiSchema(WhiteLabelSchemaMixin, Schema)``)
    y aporta los campos ya validados — el logo y el color llegan del navegador,
    así que su forma se comprueba aquí, en el borde de confianza, y no en el
    manager ni en la plantilla (donde el color acaba dentro de un ``style``).
    """

    whiteLabelLevel = fields.String(
        load_default=WhiteLabelLevel.NONE.value,
        validate=validate.OneOf([level.value for level in WhiteLabelLevel]),
    )
    brandLogo = fields.String(load_default="", allow_none=True, validate=_validate_brand_logo)
    brandColor = fields.String(load_default="", allow_none=True, validate=_validate_brand_color_field)
    #: Solo de salida: no es un ajuste sino el techo que concede el plan. El
    #: frontend lo usa para no ofrecer niveles que se van a rechazar. Sin
    #: ``dump_only`` el mismo esquema, que también valida la escritura, lo
    #: descartaría al serializar.
    maxWhiteLabelLevel = fields.String(dump_only=True)
