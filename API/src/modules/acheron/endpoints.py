from __future__ import annotations

import logging
from datetime import datetime, timezone
from flask import request
from flask_smorest import Blueprint as SmorestBlueprint
from contextlib import contextmanager

from src.modules.shared._exceptions import (
    handle_exceptions,
    ValidationError,
)
from src.modules.shared._endpoints import limiter, current_actor
from src.modules.shared.schemas import ErrorSchema
from src.modules.acheron.exceptions import VaultError, VaultNotFoundError, StorableNotFoundError, StorableConflictError
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
    with get_vault_manager() as mgr:
        vault = mgr.get_vault_for_user()

        if not vault:
            raise VaultNotFoundError()

        payload = mgr.export_vault_to_json(vault.id)
    logger.info("Vault %s devuelto | user=%s", vault.id, current_actor())
    return payload


@acheron_blp.post("/vault")
@acheron_blp.response(201, VaultUpsertResponseSchema, description="Vault created")
@acheron_blp.alt_response(200, schema=VaultUpsertResponseSchema, description="Vault updated")
@acheron_blp.alt_response(400, schema=ErrorSchema, description="Invalid body")
@acheron_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@acheron_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.ACHERON_CREATE])
@limiter.limit("60 per hour; 300 per day")
@handle_exceptions(default_exception=VaultError, logger=logger)
def upsert_vault():
    """Crear o reemplazar completamente el vault del usuario"""
    if not request.is_json:
        raise ValidationError("Content-Type must be application/json")

    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        raise ValidationError("Request body must be a JSON object")

    with get_vault_manager() as mgr:
        vault, created = mgr.upsert_vault_from_json(data)
        logger.info("Vault %s (ID=%s) | user=%s", "creado" if created else "actualizado", vault.id, current_actor())
    result = {
        "message": "Vault created" if created else "Vault updated",
        "vaultId": vault.id,
    }
    if created:
        return result
    return result, 200


@acheron_blp.patch("/vault")
@acheron_blp.arguments(VaultPasswordChangeSchema)
@acheron_blp.response(200, VaultUpsertResponseSchema, description="Vault metadata updated")
@acheron_blp.alt_response(400, schema=ErrorSchema, description="Invalid body")
@acheron_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@acheron_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@acheron_blp.alt_response(404, schema=ErrorSchema, description="Vault not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.ACHERON_UPDATE])
@limiter.limit("60 per hour; 300 per day")
@handle_exceptions(default_exception=VaultError, logger=logger)
def change_vault_metadata(data):
    """Refrescar los metadatos cripto del vault tras un cambio de contraseña maestra.

    Actualiza unicamente checker, vaultKey y algorithm; los storables (cifrados con
    la misma vaultKey) permanecen intactos.
    """
    with get_vault_manager() as mgr:
        vault = mgr.update_vault_metadata(data)
        if not vault:
            raise VaultNotFoundError()
        logger.info("Metadatos del vault %s refrescados | user=%s", vault.id, current_actor())
    return {
        "message": "Vault metadata updated",
        "vaultId": vault.id,
    }


@acheron_blp.get("/generate-password")
@acheron_blp.arguments(GeneratePasswordQuerySchema, location="query")
@acheron_blp.response(200, GeneratePasswordResponseSchema, description="Contrasena generada")
@acheron_blp.alt_response(422, schema=ErrorSchema, description="Invalid parameters")
@limiter.limit("30 per minute; 300 per hour")
@handle_exceptions(default_exception=VaultError, logger=logger)
def generate_password(query):
    """Generar una contrasena aleatoria segura. Endpoint publico, no requiere autenticacion."""
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
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.ACHERON_UPDATE])
@limiter.limit("60 per hour; 300 per day")
@handle_exceptions(default_exception=VaultError, logger=logger)
def patch_vault_storables(data):
    """Actualizar en bulk uno o varios Storables del usuario (array de operaciones)"""
    with get_vault_manager() as mgr:
        results = mgr.bulk_update_storables(operations=data)
        logger.info("Bulk update: %s operaciones | user=%s", len(data), current_actor())
    return {"message": "Bulk storable update completed", "results": results}


@acheron_blp.post("/storables")
@acheron_blp.arguments(StorableCreateSchema)
@acheron_blp.response(201, StorableResponseSchema, description="Storable created")
@acheron_blp.alt_response(400, schema=ErrorSchema, description="Validation error")
@acheron_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@acheron_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@acheron_blp.alt_response(404, schema=ErrorSchema, description="Vault not found")
@acheron_blp.alt_response(409, schema=ErrorSchema, description="internalId already exists")
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

    with get_vault_manager() as mgr:
        vault = mgr.get_vault_for_user()
        if not vault:
            raise VaultNotFoundError()

        if internal_id and mgr.get_storable_by(vault_id=vault.id, internal_id=internal_id):
            raise StorableConflictError(internal_id)

        st = mgr.add_storable_to_vault(
            vault_id=vault.id, kind=kind, internal_id=internal_id,
            title=title, created_at=created_at, updated_at=updated_at,
            **payload,
        )
    logger.info("Storable %s anadido al vault %s | user=%s", st.id, vault.id, current_actor())
    return {
        "message": "Storable created",
        "storableId": st.id,
        "internalId": st.internal_id,
        "vaultId": st.vault_id,
        "kind": kind,
    }


@acheron_blp.delete("/storables")
@acheron_blp.arguments(StorableDeleteSchema)
@acheron_blp.response(200, StorableResponseSchema, description="Storable deleted")
@acheron_blp.alt_response(400, schema=ErrorSchema, description="Missing internalId")
@acheron_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@acheron_blp.alt_response(403, schema=ErrorSchema, description="Insufficient permissions")
@acheron_blp.alt_response(404, schema=ErrorSchema, description="Storable not found")
@require_oauth_token
@require_attributes(at_least_one=[AttributeType.ACHERON_DELETE])
@limiter.limit("60 per hour; 200 per day")
@handle_exceptions(default_exception=VaultError, logger=logger)
def delete_vault_storable(data):
    """Eliminar un Storable del vault por su internalId"""
    internal_id = data["internalId"]

    with get_vault_manager() as mgr:
        vault = mgr.get_vault_for_user()

        if not vault:
            raise VaultNotFoundError()

        st = mgr.get_storable_by(vault_id=vault.id, internal_id=internal_id)
        if not st:
            raise StorableNotFoundError(internal_id)

        if not mgr.delete_storable(st.id):
            raise VaultError("Could not delete storable")

        logger.info("Storable %s (internalId=%s) eliminado | user=%s", st.id, internal_id, current_actor())
    return {
        "message": "Storable deleted",
        "storableId": st.id,
        "internalId": internal_id,
        "vaultId": vault.id,
    }


def _parse_dt(value):
    if not value:
        return datetime.now(timezone.utc).replace(tzinfo=None)
    try:
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt
    except Exception:
        logger.warning("Failed to parse datetime value %r, defaulting to utcnow", value, exc_info=True)
        return datetime.now(timezone.utc).replace(tzinfo=None)
