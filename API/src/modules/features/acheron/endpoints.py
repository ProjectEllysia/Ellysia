from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from flask import jsonify, request
from flask_smorest import Blueprint as SmorestBlueprint
from contextlib import contextmanager

from src.modules.shared._exceptions import (
    handle_exceptions,
    ValidationError,
)
from src.modules.shared._endpoints import limiter, current_actor
from src.modules.shared.schemas import ErrorSchema
from src.modules.shared import utcnow_naive
from src.modules.features.acheron.exceptions import (
    VaultError,
    VaultNotFoundError,
    StorableNotFoundError,
    StorableConflictError,
    VaultRevisionMismatchError,
)
from src.modules.users import require_oauth_token, require_attributes, AttributeType, get_current_user
from .managers import VaultManager
from .password_generator import generate_password as generate_password_util
from .storable_specs import STORABLE_SPECS
from .schemas import (
    StorableCreateSchema,
    StorableDeleteSchema,
    BulkOperationSchema,
    VaultUpsertResponseSchema,
    VaultPasswordChangeSchema,
    VaultRevisionSchema,
    StorableResponseSchema,
    BulkUpdateResponseSchema,
    GeneratePasswordQuerySchema,
    GeneratePasswordResponseSchema,
)


acheron_blp = SmorestBlueprint(
    "acheron", __name__,
    description="Gestion de vaults y secretos (Acheron)"
)
logger = logging.getLogger(__name__)


@contextmanager
def get_vault_manager():
    yield VaultManager(get_current_user())


def _client_revision() -> Optional[int]:
    """Revisión que el cliente cree tener, leída de la cabecera ``If-Match``.

    Devuelve ``None`` si no viene la cabecera: las operaciones granulares lo
    aceptan (compatibilidad con apps ya desplegadas) y el upsert completo lo
    rechaza. Se admite el formato de ETag débil (``W/"3"``) además del literal.
    """
    raw = request.headers.get("If-Match")
    if raw is None:
        return None

    token = raw.strip()
    if token.startswith("W/"):
        token = token[2:]
    token = token.strip('"')

    if not token.isdigit():
        raise ValidationError(
            "If-Match debe ser la revisión del vault (p. ej. If-Match: \"3\")",
            field="If-Match",
            value=raw,
        )
    return int(token)


def _etag(revision: int) -> dict:
    return {"ETag": f'"{revision}"'}


@acheron_blp.errorhandler(VaultRevisionMismatchError)
def handle_vault_revision_mismatch(error: VaultRevisionMismatchError):
    """Cuerpo estructurado del 409 para que el cliente pueda reintentar solo.

    El handler global de ``EllysiaException`` solo expone ``details`` en
    desarrollo, y la revisión actual hace falta siempre: con ella el cliente
    re-lee, reaplica su cambio sobre el estado fresco y reintenta.
    """
    logger.warning("Conflicto de revision de vault: %s", error.message)
    return jsonify({
        "error": "vault_revision_mismatch",
        "error_description": error.user_message,
        "code": error.code.value,
        "currentRevision": error.current_revision,
        "yourRevision": error.provided_revision,
    }), 409, _etag(error.current_revision)


@acheron_blp.get("/vault")
@acheron_blp.response(200, description="Vault del usuario en formato JSON")
@acheron_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@acheron_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@acheron_blp.alt_response(404, schema=ErrorSchema, description="Vault not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.ACHERON_READ])
@limiter.limit("120 per hour; 500 per day")
@handle_exceptions(default_exception=VaultNotFoundError, logger=logger)
def get_vault():
    """Obtener el vault del usuario en formato JSON"""
    with get_vault_manager() as manager:
        vault = manager.get_vault_for_user()

        if not vault:
            raise VaultNotFoundError()

        payload = manager.export_vault_to_json(vault.id)
    logger.info("Vault %s devuelto | user=%s", vault.id, current_actor())
    return payload, 200, _etag(payload["revision"])


@acheron_blp.get("/vault/revision")
@acheron_blp.response(200, VaultRevisionSchema, description="Revision actual del vault")
@acheron_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@acheron_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@acheron_blp.alt_response(404, schema=ErrorSchema, description="Vault not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.ACHERON_READ])
@limiter.limit("600 per hour; 5000 per day")
@handle_exceptions(default_exception=VaultNotFoundError, logger=logger)
def get_vault_revision():
    """Sonda barata: responde solo la revision, sin storables ni ciphertext.

    Permite a un cliente preguntar "¿ha cambiado algo?" sin descargar ni
    descifrar el vault entero, de ahi que tenga su propio limite de peticiones,
    mas generoso que el del GET completo.
    """
    with get_vault_manager() as manager:
        vault = manager.get_vault_for_user()

        if not vault:
            raise VaultNotFoundError()

        revision = vault.revision or 1
    return {"revision": revision}, 200, _etag(revision)


@acheron_blp.post("/vault")
@acheron_blp.response(201, VaultUpsertResponseSchema, description="Vault created")
@acheron_blp.alt_response(200, schema=VaultUpsertResponseSchema, description="Vault updated")
@acheron_blp.alt_response(400, schema=ErrorSchema, description="Invalid body")
@acheron_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@acheron_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@acheron_blp.alt_response(409, schema=ErrorSchema, description="Stale or missing vault revision")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.ACHERON_CREATE])
@limiter.limit("60 per hour; 300 per day")
@handle_exceptions(default_exception=VaultError, logger=logger)
def upsert_vault():
    """Crear el vault del usuario, o reemplazarlo por completo.

    Reemplazar es destructivo (borra todos los storables y los reinserta desde
    el payload), asi que sobre un vault ya existente exige las dos cosas:
    ``If-Match`` con la revision actual e intencion explicita ``?mode=replace``.
    La creacion inicial no lleva ninguna de las dos: no hay nada que pisar.
    """
    if not request.is_json:
        raise ValidationError("Content-Type must be application/json")

    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        raise ValidationError("Request body must be a JSON object")

    expected_revision = _client_revision()

    with get_vault_manager() as manager:
        existing = manager.get_vault_for_user()
        if existing is not None:
            if request.args.get("mode") != "replace":
                raise ValidationError(
                    "El vault ya existe: el reemplazo completo exige ?mode=replace. "
                    "Para editar contenido usa los endpoints de /acheron/storables",
                    field="mode",
                )
            if expected_revision is None:
                raise VaultRevisionMismatchError(current=existing.revision or 1)

        vault, created = manager.upsert_vault_from_json(
            data, expected_revision=expected_revision
        )
        logger.info("Vault %s (ID=%s) | user=%s", "creado" if created else "actualizado", vault.id, current_actor())
    result = {
        "message": "Vault created" if created else "Vault updated",
        "vaultId": vault.id,
        "revision": vault.revision or 1,
    }
    return result, 201 if created else 200, _etag(result["revision"])


@acheron_blp.patch("/vault")
@acheron_blp.arguments(VaultPasswordChangeSchema)
@acheron_blp.response(200, VaultUpsertResponseSchema, description="Vault metadata updated")
@acheron_blp.alt_response(400, schema=ErrorSchema, description="Invalid body")
@acheron_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@acheron_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@acheron_blp.alt_response(404, schema=ErrorSchema, description="Vault not found")
@acheron_blp.alt_response(409, schema=ErrorSchema, description="Stale vault revision")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.ACHERON_UPDATE])
@limiter.limit("60 per hour; 300 per day")
@handle_exceptions(default_exception=VaultError, logger=logger)
def change_vault_metadata(data):
    """Refrescar los metadatos cripto del vault tras un cambio de contraseña maestra.

    Actualiza unicamente checker, vaultKey y algorithm; los storables (cifrados con
    la misma vaultKey) permanecen intactos.
    """
    with get_vault_manager() as manager:
        vault = manager.update_vault_metadata(data, expected_revision=_client_revision())
        if not vault:
            raise VaultNotFoundError()
        logger.info("Metadatos del vault %s refrescados | user=%s", vault.id, current_actor())
    result = {
        "message": "Vault metadata updated",
        "vaultId": vault.id,
        "revision": vault.revision or 1,
    }
    return result, 200, _etag(result["revision"])


@acheron_blp.get("/generate-password")
@acheron_blp.arguments(GeneratePasswordQuerySchema, location="query")
@acheron_blp.response(200, GeneratePasswordResponseSchema, description="Contrasena generada")
@acheron_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@acheron_blp.alt_response(422, schema=ErrorSchema, description="Invalid parameters")
@limiter.limit("30 per minute; 300 per hour")
@require_oauth_token
@handle_exceptions(default_exception=VaultError, logger=logger)
def generate_password(query):
    """Generar una contrasena aleatoria segura."""
    password = generate_password_util(
        length=query["length"],
        use_uppercase=query["uppercase"],
        use_lowercase=query["lowercase"],
        use_digits=query["digits"],
        use_symbols=query["symbols"],
        exclude_ambiguous=query["excludeAmbiguous"],
    )
    logger.info("Password generado (length=%s) | ip=%s", query["length"], request.remote_addr)
    return {"password": password}


@acheron_blp.patch("/storables")
@acheron_blp.arguments(BulkOperationSchema(many=True))
@acheron_blp.response(200, BulkUpdateResponseSchema, description="Bulk update completed")
@acheron_blp.alt_response(400, schema=ErrorSchema, description="Invalid body")
@acheron_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@acheron_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@acheron_blp.alt_response(409, schema=ErrorSchema, description="Stale vault revision")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.ACHERON_UPDATE])
@limiter.limit("60 per hour; 300 per day")
@handle_exceptions(default_exception=VaultError, logger=logger)
def patch_vault_storables(data):
    """Actualizar en bulk uno o varios Storables del usuario (array de operaciones)"""
    with get_vault_manager() as manager:
        results = manager.bulk_update_storables(
            operations=data, expected_revision=_client_revision()
        )
        logger.info("Bulk update: %s operaciones | user=%s", len(data), current_actor())
        vault = manager.get_vault_for_user()
        revision = (vault.revision or 1) if vault else 1
    return (
        {"message": "Bulk storable update completed", "results": results, "revision": revision},
        200,
        _etag(revision),
    )


@acheron_blp.post("/storables")
@acheron_blp.arguments(StorableCreateSchema)
@acheron_blp.response(201, StorableResponseSchema, description="Storable created")
@acheron_blp.alt_response(400, schema=ErrorSchema, description="Validation error")
@acheron_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@acheron_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@acheron_blp.alt_response(404, schema=ErrorSchema, description="Vault not found")
@acheron_blp.alt_response(409, schema=ErrorSchema, description="internalId exists / stale revision")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.ACHERON_CREATE])
@limiter.limit("60 per hour; 300 per day")
@handle_exceptions(default_exception=VaultError, logger=logger)
def add_vault_storable(data):
    """Anadir un nuevo Storable (de cualquier kind soportado) al vault del usuario"""
    kind = data["kind"]

    internal_id = data.get("internalId")
    title = data.get("title")
    created_at = _parse_dt(data.get("createdAt"))
    updated_at = _parse_dt(data.get("updatedAt"))

    spec = STORABLE_SPECS.get(kind)
    payload = {attr: data.get(json_key, "") for attr, json_key in spec.fields} if spec else {}

    with get_vault_manager() as manager:
        vault = manager.get_vault_for_user()
        if not vault:
            raise VaultNotFoundError()

        if internal_id and manager.get_storable_by(vault_id=vault.id, internal_id=internal_id):
            raise StorableConflictError(internal_id)

        storable = manager.add_storable_to_vault(
            vault_id=vault.id, kind=kind, internal_id=internal_id,
            title=title, created_at=created_at, updated_at=updated_at,
            expected_revision=_client_revision(),
            **payload,
        )
    logger.info("Storable %s anadido al vault %s | user=%s", storable.id, vault.id, current_actor())
    return {
        "message": "Storable created",
        "storableId": storable.id,
        "internalId": storable.internal_id,
        "vaultId": storable.vault_id,
        "kind": kind,
        "revision": vault.revision or 1,
    }, 201, _etag(vault.revision or 1)


@acheron_blp.delete("/storables")
@acheron_blp.arguments(StorableDeleteSchema)
@acheron_blp.response(200, StorableResponseSchema, description="Storable deleted")
@acheron_blp.alt_response(400, schema=ErrorSchema, description="Missing internalId")
@acheron_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@acheron_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@acheron_blp.alt_response(404, schema=ErrorSchema, description="Storable not found")
@acheron_blp.alt_response(409, schema=ErrorSchema, description="Stale vault revision")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.ACHERON_DELETE])
@limiter.limit("60 per hour; 200 per day")
@handle_exceptions(default_exception=VaultError, logger=logger)
def delete_vault_storable(data):
    """Eliminar un Storable del vault por su internalId"""
    internal_id = data["internalId"]

    with get_vault_manager() as manager:
        vault = manager.get_vault_for_user()

        if not vault:
            raise VaultNotFoundError()

        storable = manager.get_storable_by(vault_id=vault.id, internal_id=internal_id)
        if not storable:
            raise StorableNotFoundError(internal_id)

        storable_id = storable.id
        if not manager.delete_storable(storable_id, expected_revision=_client_revision()):
            raise VaultError("Could not delete storable")

        logger.info("Storable %s (internalId=%s) eliminado | user=%s", storable_id, internal_id, current_actor())
    return {
        "message": "Storable deleted",
        "storableId": storable_id,
        "internalId": internal_id,
        "vaultId": vault.id,
        "revision": vault.revision or 1,
    }, 200, _etag(vault.revision or 1)


def _parse_dt(value):
    if not value:
        return utcnow_naive()
    try:
        parsed_datetime = datetime.fromisoformat(value)
        if parsed_datetime.tzinfo is not None:
            parsed_datetime = parsed_datetime.astimezone(timezone.utc).replace(tzinfo=None)
        return parsed_datetime
    except Exception:
        logger.warning("Failed to parse datetime value %r, defaulting to utcnow", value, exc_info=True)
        return utcnow_naive()
