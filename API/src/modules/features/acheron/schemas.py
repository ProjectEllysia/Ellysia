from marshmallow import Schema, fields, validate, validates_schema, ValidationError


class StorableCreateSchema(Schema):
    kind = fields.String(
        required=True,
        validate=validate.OneOf([
            "account",
            "creditcard",
            "securenote",
            "identity",
            "bankaccount",
            "wifi",
            "license",
        ]),
    )
    title = fields.String(allow_none=True)
    internalId = fields.String(allow_none=True)
    createdAt = fields.String(allow_none=True)
    updatedAt = fields.String(allow_none=True)
    username = fields.String(allow_none=True)
    domain = fields.String(allow_none=True)
    password = fields.String(allow_none=True)
    cardHolderName = fields.String(allow_none=True)
    cardNumber = fields.String(allow_none=True)
    expirationDate = fields.String(allow_none=True)
    postalCode = fields.String(allow_none=True)
    cvv = fields.String(allow_none=True)
    content = fields.String(allow_none=True)
    fullName = fields.String(allow_none=True)
    email = fields.String(allow_none=True)
    phone = fields.String(allow_none=True)
    address = fields.String(allow_none=True)
    city = fields.String(allow_none=True)
    country = fields.String(allow_none=True)
    documentId = fields.String(allow_none=True)
    bankName = fields.String(allow_none=True)
    holder = fields.String(allow_none=True)
    iban = fields.String(allow_none=True)
    swiftBic = fields.String(allow_none=True)
    accountNumber = fields.String(allow_none=True)
    ssid = fields.String(allow_none=True)
    securityType = fields.String(allow_none=True)
    product = fields.String(allow_none=True)
    licenseKey = fields.String(allow_none=True)
    licensedTo = fields.String(allow_none=True)
    version = fields.String(allow_none=True)

    @validates_schema
    def validate_kind_fields(self, data, **kwargs):
        required_by_kind = {
            "account": ("username", "domain", "password"),
            "creditcard": ("cardHolderName", "cardNumber", "expirationDate", "postalCode", "cvv"),
            "securenote": ("content",),
            "identity": ("fullName", "email", "phone", "address", "city", "country", "documentId"),
            "bankaccount": ("bankName", "holder", "iban", "swiftBic", "accountNumber"),
            "wifi": ("ssid", "password", "securityType"),
            "license": ("product", "licenseKey", "licensedTo", "version"),
        }
        for f in required_by_kind.get(data["kind"], ()):
            if not data.get(f):
                raise ValidationError(f"{f} is required for {data['kind']} storables")


class StorableDeleteSchema(Schema):
    internalId = fields.String(required=True)


class BulkOperationSchema(Schema):
    internalId = fields.String(required=True)
    changes = fields.Dict(keys=fields.String(), required=True)


class VaultPasswordChangeSchema(Schema):
    """Metadatos a refrescar tras un cambio de contraseña maestra.

    El cambio de contraseña es, criptográficamente, solo metadatos: la vaultKey
    (que cifra los storables) no cambia, así que NO se envían storables.
    """
    checker = fields.String(required=True)
    vaultKey = fields.String(required=True)
    algorithm = fields.Dict(required=True)


class VaultUpsertResponseSchema(Schema):
    message = fields.String()
    vaultId = fields.Integer()


class StorableResponseSchema(Schema):
    message = fields.String()
    storableId = fields.Integer()
    internalId = fields.String()
    vaultId = fields.Integer()
    kind = fields.String()


class BulkUpdateResponseSchema(Schema):
    message = fields.String()
    results = fields.List(fields.Raw())


class GeneratePasswordQuerySchema(Schema):
    length = fields.Integer(load_default=20, validate=validate.Range(min=6, max=128))
    uppercase = fields.Boolean(load_default=True)
    lowercase = fields.Boolean(load_default=True)
    digits = fields.Boolean(load_default=True)
    symbols = fields.Boolean(load_default=True)
    excludeAmbiguous = fields.Boolean(load_default=False)

    @validates_schema
    def validate_at_least_one_set(self, data, **kwargs):
        if not any([data["uppercase"], data["lowercase"], data["digits"], data["symbols"]]):
            raise ValidationError("At least one character set must be enabled")


class GeneratePasswordResponseSchema(Schema):
    password = fields.String()
