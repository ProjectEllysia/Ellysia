"""
Shared utilities for all API endpoints.

This module provides:
- limiter: global rate limiter instance (lazy initialization).
- current_actor(): readable user identity for endpoint context logs.
- normalize_target(): normalize a user-supplied target to (ip, hostname).

Module Variables:
    limiter: Global rate limiter instance (lazy initialization).
"""

from __future__ import annotations

import ipaddress
import socket
from functools import wraps
from urllib.parse import urlparse
from typing import Tuple, Optional

from flask import request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from ._exceptions import MissingParameterError, MissingJsonBodyError


# =========================================================================
# RATE LIMITING
# =========================================================================
# S4: el storage_uri por defecto es 'memory://' (por-proceso) — con varios
# workers/gunicorn cada uno lleva su propio contador, multiplicando el
# límite real (p. ej. fuerza bruta en /oauth/token) y reseteándolo en cada
# reinicio. create_app() (run.py) sobreescribe esto a Redis-backed vía
# app.config["RATELIMIT_STORAGE_URI"] antes de limiter.init_app(app) —
# no se resuelve aquí porque importar config_reading en tiempo de carga de
# este módulo crea un import circular (shared -> system -> users -> shared).
# in_memory_fallback_enabled evita que un Redis caído tumbe el rate limiting.

limiter = Limiter(
    get_remote_address,
    default_limits=[],
    storage_uri="memory://",
    in_memory_fallback_enabled=True,
)


# =========================================================================
# HELPERS
# =========================================================================

def current_actor() -> str:
    """
    Devuelve una representación legible del usuario que realiza la petición
    para usar en los logs de contexto de los endpoints.

    Lee los atributos inyectados por ``@require_oauth_token``
    (``request.current_username`` / ``request.current_user_id``) sin tocar la
    base de datos. Si la petición es anónima devuelve ``"anonymous"``.

    Formato: ``"<username>(id=<id>)"`` o ``"anonymous"``.
    """
    username = getattr(request, "current_username", None)
    if not username:
        return "anonymous"
    uid = getattr(request, "current_user_id", None)
    return f"{username}(id={uid})"


def normalize_target(
    user_input: str,
    resolve_hostname: bool = False
) -> Tuple[str, str]:
    """
    Normaliza el target del usuario a IP + hostname.
    Acepta IPs, dominios o URLs completas (http://, https://).

    Args:
        user_input:         IP, dominio o URL completa.
        resolve_hostname:   Si es True y el input es una IP, intenta resolver
                            el hostname vía reverse DNS (con timeout acotado).
                            Si es False, el hostname se omite (se devuelve la IP
                            también en esa posición). Por defecto False.
        dns_timeout:        Segundos máximos para la resolución DNS inversa.

    Returns:
        (ip, hostname): hostname == ip cuando no se resuelve o resolve_hostname=False.
        Nunca None en un retorno normal — toda rama que no logra resolver ``ip``
        lanza ``ValueError`` antes de llegar al return (Q3: el tipo antes decía
        Optional[str] para ambos, forzando un `# type: ignore` en cada caller que
        desempaqueta el resultado y lo usa como str sin comprobar None).

    Raises:
        ValueError: Si ``user_input`` no es una IP válida ni un hostname resoluble.
    """

    def _gethostbyaddr_with_timeout(ip: str) -> Optional[str]:
        """
        Wrapper de socket.gethostbyaddr para resolución DNS inversa.
        Devuelve el hostname o None si falla.
        """
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror, OSError):
            return None
    cleaned_input = user_input.strip()

    if "://" in cleaned_input:
        parsed = urlparse(cleaned_input)
        if not parsed.netloc and parsed.path:
            cleaned_input = parsed.path.split('/')[0]
        else:
            cleaned_input = parsed.netloc.split(':')[0]
    else:
        cleaned_input = cleaned_input.split(':')[0].split('/')[0]

    ip: str
    hostname: str

    try:
        ip_obj = ipaddress.ip_address(cleaned_input)
        ip = str(ip_obj)

        if resolve_hostname:
            hostname = _gethostbyaddr_with_timeout(ip) or ip
        else:
            hostname = ip

    except ValueError:
        hostname = cleaned_input
        try:
            ip = socket.gethostbyname(hostname)
        except socket.gaierror as e:
            raise ValueError(f"No se pudo resolver '{user_input}': {e}") from e

    return ip, hostname





