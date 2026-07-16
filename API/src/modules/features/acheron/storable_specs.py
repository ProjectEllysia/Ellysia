"""
acheron.storable_specs
───────────────────────
Registro único de los 7 tipos de Storable soportados por Acheron: qué modelo
usa cada uno, bajo qué clave de lista vive en el JSON del vault, y el mapeo
entre atributo Python (snake_case) y clave JSON (camelCase) de sus campos
propios (además de title/internalId/createdAt/updatedAt, comunes a todos).

managers.py y endpoints.py iteran este registro en vez de repetir un
dispatch por kind; añadir un tipo nuevo de Storable solo requiere una
entrada aquí.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Type

from .model import (
    Account,
    BankAccount,
    CreditCard,
    Identity,
    SecureNote,
    SoftwareLicense,
    Storable,
    WifiNetwork,
)


@dataclass(frozen=True)
class StorableSpec:
    model: Type[Storable]
    json_list_key: str
    fields: tuple[tuple[str, str], ...]  # (atributo_python, clave_json)


STORABLE_SPECS: dict[str, StorableSpec] = {
    "account": StorableSpec(Account, "accounts", (
        ("username", "username"),
        ("domain", "domain"),
        ("password", "password"),
    )),
    "creditcard": StorableSpec(CreditCard, "creditcards", (
        ("cardholder_name", "cardHolderName"),
        ("card_number", "cardNumber"),
        ("expiration_date", "expirationDate"),
        ("postal_code", "postalCode"),
        ("cvv", "cvv"),
    )),
    "securenote": StorableSpec(SecureNote, "securenotes", (
        ("content", "content"),
    )),
    "identity": StorableSpec(Identity, "identities", (
        ("full_name", "fullName"),
        ("email", "email"),
        ("phone", "phone"),
        ("address", "address"),
        ("city", "city"),
        ("country", "country"),
        ("document_id", "documentId"),
    )),
    "bankaccount": StorableSpec(BankAccount, "bankaccounts", (
        ("bank_name", "bankName"),
        ("holder", "holder"),
        ("iban", "iban"),
        ("swift_bic", "swiftBic"),
        ("account_number", "accountNumber"),
    )),
    "wifi": StorableSpec(WifiNetwork, "wifinetworks", (
        ("ssid", "ssid"),
        ("password", "password"),
        ("security_type", "securityType"),
    )),
    "license": StorableSpec(SoftwareLicense, "licenses", (
        ("product", "product"),
        ("license_key", "licenseKey"),
        ("licensed_to", "licensedTo"),
        ("version", "version"),
    )),
}

SPEC_BY_MODEL: dict[Type[Storable], StorableSpec] = {
    spec.model: spec for spec in STORABLE_SPECS.values()
}

# Clave JSON (camelCase) -> atributo Python (snake_case), para todos los tipos
# combinados. Usado por bulk_update_storables para traducir un payload
# {"cardHolderName": "..."} a kwargs de update_storable.
JSON_TO_ATTR: dict[str, str] = {"title": "title", "internalId": "internal_id"}
for _spec in STORABLE_SPECS.values():
    for _attr, _json_key in _spec.fields:
        JSON_TO_ATTR[_json_key] = _attr
