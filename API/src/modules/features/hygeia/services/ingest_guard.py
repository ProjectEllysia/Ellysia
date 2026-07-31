"""
hygeia.services.ingest_guard
─────────────────────────────
Guardas de la ruta caliente de ingesta (§16): frontera de confianza dura
sobre el tamaño del payload y la cordura de su reloj, aplicadas **antes**
de que Marshmallow intente siquiera parsear el cuerpo o de tocar la DB.
Un agente comprometido no debe poder tumbar la DB ni el worker con
payloads gigantes, un gzip-bomb, o fechas manipuladas.
"""

from __future__ import annotations

import gzip
import io
from datetime import datetime
from functools import wraps
from typing import Optional

from flask import request

import src.modules.system.config_reading as CR
from src.modules.shared import utcnow_naive

from ..exceptions import IngestClockSkewError, IngestPayloadTooLargeError

# Tamaño de bloque de descompresión: lo bastante pequeño para poder abortar
# pronto tras superar el límite, sin tantas iteraciones que penalicen el
# caso honesto (un heartbeat real descomprime a pocos KB).
_DECOMPRESS_CHUNK_BYTES = 65536


def enforce_body_size(content_length: Optional[int]) -> None:
    """
    Rechaza un cuerpo cuyo ``Content-Length`` supere ``maxBodyBytes``.

    Se comprueba por cabecera, antes de leer un solo byte del cuerpo: un
    heartbeat honesto pesa unos pocos KB, así que el límite nunca estorba
    al caso normal. Un ``Content-Length`` ausente también se rechaza —
    rechazar, no intentar adivinar cuánto habría que leer.

    Args:
        content_length: Valor de la cabecera ``Content-Length``, o ``None``
            si el cliente no la envió.

    Raises:
        IngestPayloadTooLargeError: Si falta la cabecera o supera el máximo.
    """
    max_bytes = CR.hygeia_limits().max_body_bytes
    if content_length is None:
        raise IngestPayloadTooLargeError("falta la cabecera Content-Length")
    if content_length > max_bytes:
        raise IngestPayloadTooLargeError(
            f"cuerpo de {content_length} bytes supera el máximo de {max_bytes}"
        )


def decompress_gzip_capped(compressed: bytes) -> bytes:
    """
    Descomprime un cuerpo gzip con un tope duro de tamaño descomprimido.

    Descomprime por bloques y aborta en cuanto se supera
    ``maxDecompressedBytes`` — nunca se vuelca a un búfer sin límite, que es
    precisamente cómo un gzip-bomb de pocos KB se convierte en varios GB en
    memoria.

    Args:
        compressed: Cuerpo crudo recibido, ya comprimido con gzip.

    Returns:
        El cuerpo descomprimido.

    Raises:
        IngestPayloadTooLargeError: Si el resultado descomprimido supera
            ``maxDecompressedBytes``, o si el cuerpo no es gzip válido.
    """
    max_bytes = CR.hygeia_limits().max_decompressed_bytes
    chunks: list[bytes] = []
    total = 0
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as decompressor:
            while True:
                chunk = decompressor.read(_DECOMPRESS_CHUNK_BYTES)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise IngestPayloadTooLargeError(
                        f"cuerpo descomprimido supera el máximo de {max_bytes} bytes"
                    )
                chunks.append(chunk)
    except OSError as exc:
        raise IngestPayloadTooLargeError("cuerpo declarado gzip no es válido") from exc

    return b"".join(chunks)


def check_clock_skew(collected_at: datetime) -> None:
    """
    Rechaza un heartbeat cuyo ``collectedAt`` se sale de la ventana de
    cordura respecto al reloj del servidor.

    El reloj del agente no es de fiar (§16.3): una clave robada no debe
    poder inyectar snapshots fechados en el pasado o futuro lejano, que
    envenenarían el orden de la serie temporal o taparían un hueco de
    presencia. El histórico y la detección siempre se ordenan por
    ``received_at`` (reloj del servidor), nunca por ``collected_at``; esta
    comprobación solo acota cuánto puede desviarse uno del otro.

    Args:
        collected_at: Marca de tiempo que trae el payload del agente.

    Raises:
        IngestClockSkewError: Si la desviación supera ``clockSkewSec``.
    """
    max_skew = CR.hygeia_limits().clock_skew_sec
    skew_seconds = abs((utcnow_naive() - collected_at).total_seconds())
    if skew_seconds > max_skew:
        raise IngestClockSkewError(collected_at.isoformat())


def enforce_ingest_limits(f):
    """
    Decorador que aplica los límites de tamaño del payload de ingesta antes
    de que Marshmallow intente parsear el cuerpo como JSON.

    Si el cuerpo viene comprimido con gzip, lo descomprime aquí (con tope
    duro) y lo deja en la caché interna de Werkzeug (``request._cached_data``)
    para que el resto del pipeline (webargs, vía ``request.get_data(cache=True)``)
    lo consuma ya en plano, sin volver a tocar el stream original.

    Reescribir ``request.environ["wsgi.input"]`` no basta: el objeto
    ``Request`` de Werkzeug ya fija su stream de lectura al construirse,
    antes de que este decorador llegue a ejecutarse, así que una
    sustitución posterior del WSGI environ pasa desapercibida. En cambio,
    ``get_data(cache=True)`` mira primero ``self._cached_data`` y solo lee
    el stream si está vacío — poblarla aquí es lo que sí surte efecto.

    Debe colocarse inmediatamente después de ``@blp.post(...)``, por encima
    de ``@blp.arguments(...)``: los decoradores se ejecutan de fuera hacia
    dentro, así que solo estando por encima se garantiza que esta
    comprobación corre antes de que webargs intente parsear un cuerpo que
    podría no ser JSON válido todavía (por estar comprimido).
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        enforce_body_size(request.content_length)

        if request.headers.get("Content-Encoding", "").lower() == "gzip":
            decompressed = decompress_gzip_capped(request.get_data(cache=False))
            request._cached_data = decompressed  # type: ignore[attr-defined]

        return f(*args, **kwargs)

    return decorated
