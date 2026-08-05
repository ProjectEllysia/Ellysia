"""
Clasificador de plantillas de Nuclei por lo que exigen del runtime propio.

Esta es la pieza que responde a la pregunta de la Fase U4 —*¿qué fracción del
feed de Nuclei podríamos ingerir?*— y, más adelante, la que la Fase R usará para
decidir plantilla a plantilla si se traduce o se descarta.

**Se escribe una sola vez a propósito.** El censo (U4) y la ingesta (R) tienen
que estar de acuerdo sobre qué es ingerible, o el número medido no describe lo
que la ingesta acabará haciendo. Compartiendo este módulo no pueden discrepar:
si divergen, es un bug en un único sitio.

El criterio no es "¿entiende Nuclei esto?" sino "¿lo entiende
:class:`~..checks.CheckRuntime`?". Hoy el runtime soporta un subconjunto
pequeño y bien delimitado: peticiones HTTP con matchers ``status``/``word``/
``regex``, combinables con ``and``/``or`` y negables, más sondas de red que
comparan texto decodificado. Todo lo demás —extractors e interpolación
``{{var}}``, payloads y sus estrategias de ataque, matchers ``binary``/``dsl``/
``size``, condiciones dentro de un matcher— cae fuera, cada cosa por su propia
razón y a distinta distancia de poder soportarse.

De ahí que la clasificación no sea binaria sino por **cubos ordenados por
esfuerzo**: la decisión que el roadmap quiere tomar no es "¿se puede?" sino
"¿cuánto habría que construir, y a cambio de cuántas plantillas?".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set

# Claves de protocolo que una plantilla puede declarar en su raíz. Nuclei
# acepta ``http`` y su alias histórico ``requests`` para lo mismo, igual que
# ``network``/``tcp``.
_HTTP_KEYS = ("http", "requests")
_NETWORK_KEYS = ("network", "tcp")
# Protocolos que el motor no habla y no va a hablar por esta vía: o necesitan
# una infraestructura entera (``headless`` es un navegador; ``interactsh`` es un
# servidor fuera de banda), o son un lenguaje de scripting (``code``, ``flow``,
# ``javascript``), que el roadmap descarta explícitamente por no poder aislarse.
_SCRIPTING_KEYS = ("code", "flow", "javascript")
_OUT_OF_SCOPE_KEYS = ("dns", "file", "headless", "whois", "ssl", "websocket")

# Matchers que el runtime evalúa hoy (``CheckRuntime``/``Matcher._raw_match``).
# Cualquier otro (``binary``, ``size``, ``dsl``, ``favicon``) es un obstáculo, y
# se registra con su propio nombre (``matcher:dsl``) en vez de agruparse: el
# coste de soportarlos es muy distinto —``binary`` y ``size`` son pequeños y
# acotados, ``dsl`` es un lenguaje de expresiones entero— así que el histograma
# tiene que poder distinguirlos para que la decisión sea informada.
_SUPPORTED_MATCHERS = frozenset({"status", "word", "regex"})


class Bucket(Enum):
    """Cubos de ingestibilidad, ordenados por esfuerzo creciente.

    El orden importa: una plantilla cae en el cubo del *mayor* obstáculo que
    presenta, no en el primero que se detecta.
    """

    INGESTIBLE_NOW = "ingestible_now"
    NEEDS_EXTRACTORS = "needs_extractors"
    NEEDS_PAYLOADS_OR_BINARY = "needs_payloads_or_binary"
    REJECTED_BY_DESIGN = "rejected_by_design"
    OUT_OF_SCOPE = "out_of_scope"


@dataclass(frozen=True)
class TemplateProfile:
    """Qué exige una plantilla del runtime, y en qué cubo la deja.

    Attributes:
        template_id: El ``id`` declarado por la plantilla, o cadena vacía.
        protocol: El protocolo detectado (``"http"``, ``"network"``, ...), o
            cadena vacía si no se reconoció ninguno.
        severity: La severidad declarada en ``info.severity``, en minúsculas.
        bucket: El cubo de ingestibilidad resultante.
        matcher_types: Los tipos de matcher que la plantilla usa.
        blockers: Las razones concretas por las que no es ingerible tal cual.
            Vacío para :attr:`Bucket.INGESTIBLE_NOW`. Es lo que convierte el
            histograma en accionable: no solo cuántas fallan, sino por qué.
        request_count: Cuántas peticiones declara.
    """

    template_id: str
    protocol: str
    severity: str
    bucket: Bucket
    matcher_types: Set[str] = field(default_factory=set)
    blockers: Set[str] = field(default_factory=set)
    request_count: int = 0


def _first_present(document: dict, keys) -> Optional[str]:
    """Devuelve la primera de ``keys`` presente en el documento, o ``None``."""
    return next((key for key in keys if key in document), None)


def _iter_matchers(requests: List[dict]):
    """Itera todos los matchers de todas las peticiones de una plantilla."""
    for request in requests:
        if not isinstance(request, dict):
            continue
        for matcher in request.get("matchers") or []:
            if isinstance(matcher, dict):
                yield request, matcher


def _has_interpolation(value) -> bool:
    """Detecta la interpolación ``{{...}}`` de Nuclei en cualquier valor anidado.

    ``{{BaseURL}}`` es la excepción que no cuenta: aparece en casi toda
    plantilla HTTP y el runtime ya lo resuelve implícitamente (construye la URL
    a partir del host y el puerto del servicio). Contarlo como obstáculo
    marcaría el feed entero como no ingerible por algo que en realidad ya
    funciona.
    """
    if isinstance(value, str):
        stripped = value.replace("{{BaseURL}}", "").replace("{{Hostname}}", "")
        return "{{" in stripped
    if isinstance(value, dict):
        return any(_has_interpolation(nested_value) for nested_value in value.values())
    if isinstance(value, list):
        return any(_has_interpolation(nested_value) for nested_value in value)
    return False


def _inspect_matchers(requests: List[dict]):
    """Recorre los matchers y devuelve ``(tipos_usados, obstáculos)``."""
    matcher_types: Set[str] = set()
    blockers: Set[str] = set()

    for request, matcher in _iter_matchers(requests):
        matcher_type = str(matcher.get("type") or "")
        matcher_types.add(matcher_type)
        if matcher_type not in _SUPPORTED_MATCHERS:
            blockers.add(f"matcher:{matcher_type or 'sin-tipo'}")
        # ``condition`` DENTRO de un matcher (no el ``matchers-condition`` entre
        # matchers, que sí se soporta): ``Matcher._raw_match`` fija ``any()``
        # sobre la lista de palabras, así que un "and" interno cambiaría el
        # resultado en silencio en vez de fallar. Se cuenta como obstáculo.
        if matcher.get("condition") == "and":
            blockers.add("matcher-condition-interna")
        if request.get("req-condition") or request.get("stop-at-first-match"):
            blockers.add("condicion-entre-peticiones")

    return matcher_types, blockers


def _inspect_requests(requests: List[dict]) -> Set[str]:
    """Recorre las peticiones y devuelve los obstáculos de nivel de petición."""
    blockers: Set[str] = set()
    for request in requests:
        if not isinstance(request, dict):
            continue
        if request.get("payloads") or request.get("attack") or request.get("fuzzing"):
            blockers.add("payloads")
        if request.get("extractors"):
            blockers.add("extractors")
        # El esquema binario de una sonda de red: ``inputs`` con ``type: hex``.
        # Es justo lo que desbloquearía los checks de SMB que la Fase N no pudo
        # construir, así que interesa contarlo por separado.
        for entry in request.get("inputs") or []:
            if isinstance(entry, dict) and entry.get("type") == "hex":
                blockers.add("input-hex")
    return blockers


def classify_template(document: dict) -> TemplateProfile:
    """Clasifica una plantilla de Nuclei por lo que exigiría del runtime propio.

    Args:
        document: La plantilla ya parseada (ver
            ``NucleiTemplateStore.load_template``).

    Returns:
        Su :class:`TemplateProfile`, con el cubo y los obstáculos concretos.
    """
    template_id = str(document.get("id") or "")
    info = document.get("info") if isinstance(document.get("info"), dict) else {}
    severity = str(info.get("severity") or "").lower()

    scripting_key = _first_present(document, _SCRIPTING_KEYS)
    if scripting_key:
        return TemplateProfile(
            template_id=template_id,
            protocol=scripting_key,
            severity=severity,
            bucket=Bucket.REJECTED_BY_DESIGN,
            blockers={f"protocolo:{scripting_key}"},
        )

    protocol_key = _first_present(document, _HTTP_KEYS) or _first_present(document, _NETWORK_KEYS)
    if protocol_key is None:
        out_of_scope_key = _first_present(document, _OUT_OF_SCOPE_KEYS)
        return TemplateProfile(
            template_id=template_id,
            protocol=out_of_scope_key or "",
            severity=severity,
            bucket=Bucket.OUT_OF_SCOPE,
            blockers={f"protocolo:{out_of_scope_key or 'desconocido'}"},
        )

    protocol = "http" if protocol_key in _HTTP_KEYS else "network"
    requests = document.get(protocol_key) or []
    if not isinstance(requests, list):
        requests = []

    matcher_types, blockers = _inspect_matchers(requests)
    blockers |= _inspect_requests(requests)
    if _has_interpolation(requests):
        blockers.add("interpolacion")

    return TemplateProfile(
        template_id=template_id,
        protocol=protocol,
        severity=severity,
        bucket=_bucket_for(blockers),
        matcher_types=matcher_types,
        blockers=blockers,
        request_count=len(requests),
    )


# Obstáculos que solo exigen extractors + interpolación: la capa más barata de
# construir de todas las que faltan, y por eso su propio cubo.
_EXTRACTOR_BLOCKERS = frozenset({"extractors", "interpolacion"})


def _bucket_for(blockers: Set[str]) -> Bucket:
    """Decide el cubo a partir de los obstáculos hallados.

    Una plantilla cae en el cubo del *mayor* obstáculo que presenta: si necesita
    extractors y además payloads, cuenta como payloads.
    """
    if not blockers:
        return Bucket.INGESTIBLE_NOW
    if blockers <= _EXTRACTOR_BLOCKERS:
        return Bucket.NEEDS_EXTRACTORS
    return Bucket.NEEDS_PAYLOADS_OR_BINARY


def is_ingestible(document: dict) -> bool:
    """Atajo para la Fase R: si la plantilla se traduce hoy tal cual.

    Deliberadamente estricto — solo :attr:`Bucket.INGESTIBLE_NOW`. Una
    plantilla de cualquier otro cubo se descarta en la ingesta en vez de
    traducirse a medias, porque una traducción parcial produciría un check que
    corre pero comprueba algo distinto de lo que la plantilla dice.
    """
    return classify_template(document).bucket is Bucket.INGESTIBLE_NOW


def summarize(profiles: List[TemplateProfile]) -> Dict[str, object]:
    """Agrega una lista de perfiles en el histograma que la Fase U4 pide.

    Args:
        profiles: Los perfiles de todas las plantillas censadas.

    Returns:
        Un diccionario con el total, el reparto por cubo (absoluto y en
        porcentaje), el reparto por protocolo, el recuento de obstáculos y el
        dato que de verdad decide la Fase R: la fracción de las plantillas
        **HTTP** que son ingeribles hoy tal cual.
    """
    total = len(profiles)
    by_bucket: Dict[str, int] = {bucket.value: 0 for bucket in Bucket}
    by_protocol: Dict[str, int] = {}
    blocker_counts: Dict[str, int] = {}

    for profile in profiles:
        by_bucket[profile.bucket.value] += 1
        protocol = profile.protocol or "desconocido"
        by_protocol[protocol] = by_protocol.get(protocol, 0) + 1
        for blocker in profile.blockers:
            blocker_counts[blocker] = blocker_counts.get(blocker, 0) + 1

    http_profiles = [profile for profile in profiles if profile.protocol == "http"]
    http_ingestible = sum(1 for http_profile in http_profiles if http_profile.bucket is Bucket.INGESTIBLE_NOW)

    return {
        "total": total,
        "by_bucket": by_bucket,
        "by_bucket_pct": {
            key: round(100.0 * value / total, 2) if total else 0.0
            for key, value in by_bucket.items()
        },
        "by_protocol": dict(sorted(by_protocol.items(), key=lambda kv: -kv[1])),
        "blockers": dict(sorted(blocker_counts.items(), key=lambda kv: -kv[1])),
        "http_total": len(http_profiles),
        "http_ingestible_now": http_ingestible,
        "http_ingestible_pct": (
            round(100.0 * http_ingestible / len(http_profiles), 2) if http_profiles else 0.0
        ),
    }
