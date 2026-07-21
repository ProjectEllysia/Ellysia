from datetime import timezone

from marshmallow import Schema, fields, validate


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
