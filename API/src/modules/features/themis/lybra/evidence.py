"""La evidencia cruda de un hallazgo — capturada, redactada y con hash (Fase E).

Este módulo vive en la capa pura ``lybra/``: **no toca el ORM**. El motor
recoge la evidencia en una lista en memoria a través de un *recorder*
inyectable —igual que ``cve_lookup``—, y es el manager quien la vuelca a la
base de datos en la fase de persistencia. Aquí sólo están las dos operaciones
que no dependen de nada externo: **redactar** y **hashear**.

**Por qué la redacción es requisito y no mejora.** Una respuesta cruda puede
traer cookies de sesión, cabeceras ``Authorization``, tokens en el cuerpo o
datos personales del objetivo. Guardar evidencia sin redactar convertiría la
base de datos de Ellysia en un depósito de secretos ajenos. Filtrar las
cabeceras sensibles y truncar el cuerpo es la línea que separa «guardo lo que
vi» de «me quedo con las llaves de casa del cliente».
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

# Cabeceras que nunca se persisten: llevan credenciales o material de sesión.
# Se comparan en minúsculas, así que la lista va en minúsculas.
_SENSITIVE_HEADERS = frozenset({
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "www-authenticate",
    "proxy-authenticate",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-xsrf-token",
    "api-key",
    "authentication-info",
})

# Lo que se pone en lugar de una cabecera redactada, para que la evidencia diga
# «aquí había algo y lo quitamos» en vez de esconder que existía.
_REDACTED = "[redacted]"

# Las clases de evidencia que el modelo reconoce (MS-Fase E). Una entrada con
# otro ``kind`` no se descarta, pero conviene que la lista viva en un sitio.
EVIDENCE_KINDS = ("http_response", "ssh_banner", "tls_cert", "probe_output")


@dataclass
class EvidenceRecord:
    """Una evidencia recogida por el motor, aún sin persistir.

    El ``dedup_key`` es lo que ata la evidencia a su hallazgo cuando el manager
    la vuelca: el hallazgo se identifica por esa clave, no por la identidad de
    un objeto Python que ``merge_findings`` podría haber recreado.

    Attributes:
        dedup_key: La clave del hallazgo que esta evidencia respalda.
        kind: La clase de evidencia (:data:`EVIDENCE_KINDS`).
        payload: El contenido observado, **sin** redactar todavía.
    """
    dedup_key: str
    kind: str
    payload: Dict[str, Any]


@dataclass
class EvidenceRecorder:
    """Un recorder inyectable que acumula evidencia en memoria.

    El motor recibe uno de éstos y llama :meth:`record` cuando un hallazgo trae
    la respuesta que lo provocó. No sabe nada de la base de datos; el manager
    lee :attr:`records` al final y los persiste.
    """
    records: List[EvidenceRecord] = field(default_factory=list)

    def record(self, dedup_key: str, kind: str, payload: Dict[str, Any]) -> None:
        """Apunta una evidencia para un hallazgo.

        Args:
            dedup_key: La clave del hallazgo que respalda.
            kind: La clase de evidencia.
            payload: El contenido observado, sin redactar.
        """
        self.records.append(EvidenceRecord(dedup_key=dedup_key, kind=kind, payload=payload))


def redact_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Sustituye el valor de las cabeceras sensibles por un marcador.

    Se conserva el **nombre** de la cabecera —que dice que estaba— y se borra
    sólo el valor. Un informe que dice «había un ``Set-Cookie`` y lo redactamos»
    es más honesto que uno que finge que no existía.

    Args:
        headers: Las cabeceras de la respuesta.

    Returns:
        Una copia con los valores sensibles redactados.
    """
    return {
        name: (_REDACTED if name.lower() in _SENSITIVE_HEADERS else value)
        for name, value in headers.items()
    }


def redact_evidence(payload: Dict[str, Any], max_body_bytes: int = 8192) -> Dict[str, Any]:
    """Redacta y trunca una evidencia antes de persistirla.

    Args:
        payload: El contenido observado. Puede traer ``headers`` (un dict) y
            ``body`` (texto); cualquier otra clave se conserva tal cual.
        max_body_bytes: El tope del cuerpo, en bytes de su codificación UTF-8.

    Returns:
        Una copia redactada: cabeceras sensibles sin valor, cuerpo truncado con
        una marca de cuántos bytes se recortaron.
    """
    redacted = dict(payload)
    if isinstance(redacted.get("headers"), dict):
        redacted["headers"] = redact_headers(redacted["headers"])
    body = redacted.get("body")
    if isinstance(body, str):
        encoded = body.encode("utf-8", "ignore")
        if len(encoded) > max_body_bytes:
            redacted["body"] = encoded[:max_body_bytes].decode("utf-8", "ignore")
            redacted["body_truncated_bytes"] = len(encoded) - max_body_bytes
    return redacted


def evidence_hash(payload: Dict[str, Any]) -> str:
    """Calcula el SHA-256 de una evidencia redactada, de forma estable.

    Se serializa con las claves ordenadas para que el mismo contenido produzca
    siempre el mismo hash, que es lo que permite afirmar después que la
    evidencia no se ha tocado.

    Args:
        payload: La evidencia ya redactada.

    Returns:
        El digest hexadecimal.
    """
    serialized = json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def prepare_evidence(
    payload: Dict[str, Any],
    max_body_bytes: int = 8192,
) -> Dict[str, Any]:
    """Redacta, trunca y hashea una evidencia en un solo paso.

    Args:
        payload: El contenido observado, sin redactar.
        max_body_bytes: El tope del cuerpo.

    Returns:
        Un dict ``{"payload": <redactado>, "content_hash": <sha256>}`` listo
        para el modelo.
    """
    redacted = redact_evidence(payload, max_body_bytes)
    return {"payload": redacted, "content_hash": evidence_hash(redacted)}


def build_recorder(enabled: bool) -> Optional[EvidenceRecorder]:
    """Devuelve un recorder si la captura está activada, o ``None``.

    Un ``None`` es la señal de «no captures nada», que el motor propaga sin
    ramas especiales: donde llamaría a ``recorder.record`` simplemente no hay
    recorder.

    Args:
        enabled: Si la captura de evidencia está activada.

    Returns:
        Un :class:`EvidenceRecorder` nuevo, o ``None``.
    """
    return EvidenceRecorder() if enabled else None


# Tipo del recorder que el motor recibe: una función que apunta una evidencia,
# o ``None``. Se declara para que las firmas lo nombren sin importar la clase.
RecorderFn = Optional[Callable[[str, str, Dict[str, Any]], None]]
