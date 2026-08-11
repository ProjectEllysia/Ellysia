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

def rate_limit_key() -> str:
    """
    Clave de cubo del rate limiter: la identidad de quien llama, no su IP.

    Con ``get_remote_address`` a secas, una oficina entera detrás de un NAT
    comparte un solo cubo: todos los empleados suman al mismo contador y el
    primero que trabaja deja sin cupo a los demás. Con ``/oauth/token`` a
    20/hora eso significa que el vigesimoprimer inicio de sesión —o refresco de
    token— de esa oficina en una hora falla, y en el front un refresco fallido
    cierra la sesión directamente.

    Se usa el ``sub`` del JWT cuando la petición trae uno con **firma válida**.
    Se verifica la firma a propósito: sin verificar, cualquiera se fabricaría un
    ``sub`` distinto por petición y el límite dejaría de existir. No se
    comprueba la caducidad ni la revocación en base de datos:

    - La caducidad haría que el cubo saltara de identidad a IP justo mientras el
      cliente refresca, que es cuando menos falta hace.
    - La revocación exige una consulta a base de datos en CADA petición, incluidas
      las que el limitador va a rechazar — justo lo que se intenta evitar. Un
      token revocado sigue identificando a su dueño, que es lo único que se
      necesita para contar.

    Las peticiones anónimas (``/oauth/token``, el quiz público) caen a la IP, que
    es lo correcto: ahí la identidad todavía no existe y lo que se protege es
    precisamente el intento de adivinarla.
    """
    header = request.headers.get("Authorization", "")
    if header.startswith("Bearer "):
        try:
            # Import diferido: hacerlo arriba crea el ciclo
            # shared -> system -> users -> shared que documenta el bloque de abajo.
            import jwt
            from src.modules.system import config_reading as CR

            jwt_cfg = CR.jwt_config()
            payload = jwt.decode(
                header[7:],
                jwt_cfg.secret,
                algorithms=[jwt_cfg.algorithm],
                options={"verify_exp": False},
            )
            subject = payload.get("sub")
            if subject:
                return f"user:{subject}"
        except Exception:
            # Token ilegible, mal firmado o configuración incompleta: se cuenta
            # por IP. Nunca se deja pasar sin contar.
            pass
    return get_remote_address()


limiter = Limiter(
    rate_limit_key,
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
    user_id = getattr(request, "current_user_id", None)
    return f"{username}(id={user_id})"


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





