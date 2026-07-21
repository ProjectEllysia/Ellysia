"""
hygeia.services.enrollment
───────────────────────────
Emisión y verificación de la clave de agente: la identidad de un
MonitoredAsset frente a la superficie de ingesta.

La clave tiene dos partes, ``<keyId>.<secreto>`` (estilo token de GitHub o
Stripe):

    - ``keyId``: prefijo corto y público, indexado en claro. No es secreto;
      su único trabajo es localizar por índice qué activo intenta
      autenticarse, en O(1), sin tener que verificar el Argon2 de todos los
      activos uno a uno.
    - ``secreto``: la parte de alta entropía. De esto se guarda solo el hash
      Argon2id — nunca se persiste en claro. Se devuelve al operador una
      única vez, en el momento del alta o de la rotación.
"""

from __future__ import annotations

import logging
import secrets
from functools import wraps
from typing import Optional, Tuple

from flask import jsonify, request
from flask_limiter.util import get_remote_address

from src.modules.infrastructure.session import build_repository
from src.modules.users.services.secrets import hash_password, verify_password

from ..repositories import MonitoredAssetRepository

logger = logging.getLogger(__name__)

# Longitud del prefijo público. No necesita alta entropía (esa la aporta el
# secreto); solo debe ser suficientemente largo para que colisiones entre
# activos distintos sean estadísticamente irrelevantes.
_KEY_ID_LENGTH = 16

# Hash Argon2id fijo, calculado una sola vez, contra el que se verifica un
# secreto arbitrario cuando el keyId recibido no corresponde a ningún activo
# (ver require_agent_key). Sin este trabajo simulado, un keyId inexistente
# respondería casi instantáneamente mientras que un secreto incorrecto para
# un keyId real tardaría lo que tarda un Argon2 completo — esa diferencia de
# tiempo es un oráculo que permitiría enumerar keyId válidos por timing.
_DUMMY_HASH = hash_password(secrets.token_urlsafe(32))


def generate_agent_key() -> Tuple[str, str, str]:
    """
    Genera una nueva clave de agente para un activo.

    Returns:
        Tupla ``(key_id, secret_hash, full_key)`` donde:
            - ``key_id``: prefijo público a guardar en ``agent_key_id``.
            - ``secret_hash``: hash Argon2id a guardar en ``agent_key_hash``.
            - ``full_key``: la clave completa ``<keyId>.<secreto>`` en claro,
              para devolver al operador una única vez. No se persiste.
    """
    key_id = secrets.token_hex(_KEY_ID_LENGTH // 2)
    secret = secrets.token_urlsafe(32)
    secret_hash = hash_password(secret)
    full_key = f"{key_id}.{secret}"
    return key_id, secret_hash, full_key


def _extract_key_from_request() -> Optional[str]:
    """Extrae la clave de agente de la cabecera Authorization o X-Agent-Key."""
    auth_header = request.headers.get("Authorization")
    if auth_header:
        parts = auth_header.split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            return parts[1]

    return request.headers.get("X-Agent-Key")


def agent_key_id_from_request() -> str:
    """
    Extrae el ``keyId`` (sin el secreto) de la clave de agente de la request,
    para usarlo como clave de rate-limit en la ruta de ingesta.

    No valida el secreto — solo separa el prefijo público, así que puede
    llamarse antes de cualquier autenticación real. Acotar por ``keyId`` en
    vez de por IP importa aquí: varios agentes detrás del mismo NAT no deben
    compartir cupo, y una clave robada no debe poder martillear la ingesta
    aunque cambie de IP.

    Returns:
        El ``keyId``, o la IP remota como clave de repuesto si la cabecera
        falta o está mal formada — el rate-limit sigue aplicando (más
        grueso) en vez de que una petición malformada rompa el limiter.
    """
    full_key = _extract_key_from_request()
    if full_key and "." in full_key:
        return full_key.split(".", 1)[0]
    return get_remote_address()


def require_agent_key(f):
    """
    Autentica un agente Hygeia por su clave bearer ``<keyId>.<secreto>``.

    Inyecta en el request:
        - request.current_asset_id  (int)

    Responde con un único 401 genérico e indistinguible tanto si el keyId no
    existe como si el secreto es incorrecto — nunca reveles en el cuerpo ni
    en el código cuál de los dos casos ocurrió, o un atacante podría usar la
    respuesta para enumerar keyId válidos.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        full_key = _extract_key_from_request()
        if not full_key or "." not in full_key:
            return jsonify({
                "error": "unauthorized",
                "error_description": "Missing or malformed agent key",
            }), 401

        key_id, _, secret = full_key.partition(".")
        repo    = build_repository(MonitoredAssetRepository)
        asset   = repo.get_by_agent_key_id(key_id)

        if asset is None:
            # keyId desconocido: se ejecuta igualmente una verificación Argon2
            # contra un hash fijo para que el coste temporal sea indistinguible
            # del de un secreto incorrecto sobre un keyId real (§16.6).
            verify_password(_DUMMY_HASH, secret)
            return jsonify({
                "error": "unauthorized",
                "error_description": "Invalid agent key",
            }), 401

        is_valid, _ = verify_password(asset.agent_key_hash, secret)
        if not is_valid:
            return jsonify({
                "error": "unauthorized",
                "error_description": "Invalid agent key",
            }), 401

        request.current_asset_id = asset.id  # type: ignore[attr-defined]
        return f(*args, **kwargs)

    return decorated
