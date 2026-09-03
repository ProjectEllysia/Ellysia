"""Lybra's active-detection runtime — the engine's identity layer.

This is where Lybra stops inferring vulnerabilities from a version number and
starts actively *confirming* them. It runs declarative checks against a service
and, when one fires, emits a finding marked confirmed with a high Quality of
Detection — a real, observed problem rather than a suspicion.

A check describes an HTTP request and the conditions ("matchers") that decide
whether it fired. The checks live in a bundled YAML feed whose schema
deliberately mirrors the shape of Nuclei's own templates. JSON is still
accepted by the loader — the two are the same object graph, and an external
feed may arrive as either — but the first-party feed is YAML.

The scope of this layer covers the three highest-value, lowest-cost families the
roadmap names first: exposed paths (like ``/.git/config``), missing security
headers, and TLS/certificate hygiene (self-signed, expired, deprecated
protocol — a ``type: "tls"`` check, evaluated against a handshake instead of an
HTTP request/response), plus the raw protocol probes of ``type: "network"``
(Fase N) and the first-party plugins of ``type: "script"`` (Fase R) for what no
text matcher can express — a binary protocol, a multi-step negotiation. Request
chaining and payloads/fuzzing are deliberate follow-ups.

The runtime is pure given an injected ``fetch`` callable, so it can be
unit-tested with hand-crafted responses and never touches the network in tests.
In production the manager wires the real :class:`HttpProbe`, and only when an
opt-in config flag is set — active checks reach out and touch the target, and so
must wait on the authorized-targets register the roadmap calls for.
"""

from __future__ import annotations

import json
import logging
import re
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Tuple

import yaml

from .engine import Service
from .correlation import PRIORITY_LADDER

logger = logging.getLogger(__name__)

# The version stamped onto every finding this runtime produces, for
# traceability. Bumped whenever the feed gains a new check family or a new
# protocol under an existing one (checks-2: "ftp-anonymous-login", the first
# ``type: "network"`` check; checks-3: "redis-unauthenticated-access", the
# second ``network`` protocol; checks-4: "smb-signing-not-required", the first
# ``type: "script"`` check; checks-5: "snmp-default-community", the first
# check over UDP; checks-6: el vocabulario ``read``/``expectBanner``, que es
# capacidad nueva del esquema y no el arreglo de un check suelto) — nunca por
# arreglar un check ya existente, que sube su propio ``version`` (ver
# ``Check.check_id``). Los dos checks ``network`` suben además a ``version: 2``
# en checks-6: su comportamiento cambia, y un hallazgo guardado tiene que poder
# decir cuál de las dos formas lo produjo.
CHECKS_FEED_VERSION = "lybra-checks-14"
# Quality of Detection for a finding a check actively confirmed, as opposed to
# one merely inferred from a version.
QOD_CONFIRMED = 99

# The feed shipped in the package's feeds/ directory, alongside every other
# Lybra feed (tech_signatures.json for the HTTP dissector, ...). YAML rather
# than JSON since Fase R: it is Nuclei's own format — which this schema aims to
# stay reasonably compatible with — and it takes comments, which in a feed of
# detection rules is the difference between being able to explain why a check
# exists and not.
_BUNDLED_FEED = Path(__file__).parent / "feeds" / "checks_feed.yaml"
# Un mismo conjunto de puertos respondía antes a dos preguntas que no son la
# misma —"¿esto habla TLS?" y "¿esto merece checks de higiene TLS?"— y las
# respondía mal a las dos: tenía dos elementos, 443 y 8443. Un panel de
# administración HTTPS en 9443 se sondeaba en claro y no recibía ningún check
# de certificado.
#
# Ahora cada pregunta se responde por su lado. El **esquema** (http o https) ya
# no se deduce del puerto: se observa, intentando el handshake (ver
# :func:`negotiates_tls`). Lo que queda aquí es sólo la **candidatura**: a qué
# servicios merece la pena acercarse siquiera.
_HTTP_SERVICE_NAMES = {"http", "https", "http-proxy", "https-alt", "http-alt"}

# Puertos donde es habitual encontrar TLS. Deciden qué servicios reciben los
# checks de higiene de certificado, no cómo se habla con ellos. La lista es una
# red de seguridad barata, no una verdad: un TLS en un puerto que no esté aquí
# se sondea igual de bien (el esquema se observa), pero no recibe los checks de
# certificado. Ampliarla es gratis; hacerla innecesaria es #283, que ataca la
# misma enfermedad —decidir por número de puerto— desde el otro lado.
_TLS_HYGIENE_PORTS = {443, 8443, 9443, 10443, 4443, 7443, 8834, 9091, 5986, 636, 3269}

# APIs de administración que hablan HTTP y publican su versión en un JSON sin
# autenticar (L17). Cada familia tiene su propio predicado —y no uno común—
# porque el runtime de checks selecciona los servicios por ese nombre: con un
# único ``admin_api``, el check de Docker se ejecutaría también contra el 9200
# de Elasticsearch, seis peticiones donde basta una.
_DOCKER_SERVICE_NAMES = {"docker"}
_DOCKER_PORTS = {2375, 2376}
_ELASTICSEARCH_SERVICE_NAMES = {"elasticsearch"}
_ELASTICSEARCH_PORTS = {9200}
_KIBANA_SERVICE_NAMES = {"kibana"}
_KIBANA_PORTS = {5601}
_KUBERNETES_SERVICE_NAMES = {"kubernetes", "kube-apiserver"}
_KUBERNETES_PORTS = {6443}
_ETCD_SERVICE_NAMES = {"etcd"}
_ETCD_PORTS = {2379}
_CONSUL_SERVICE_NAMES = {"consul"}
_CONSUL_PORTS = {8500}

# La unión, para lo que sí es común: decidir si un puerto pertenece a esta
# familia y, con ello, que entre en el conjunto HTTP.
_ADMIN_API_PORTS = (
    _DOCKER_PORTS | _ELASTICSEARCH_PORTS | _KIBANA_PORTS
    | _KUBERNETES_PORTS | _ETCD_PORTS | _CONSUL_PORTS
)

# Puertos que se consideran servicio HTTP. Incluye los de TLS: un HTTPS en 9443
# tampoco entraba por esta puerta, así que ampliar sólo la lista de TLS no
# habría servido de nada. Y los de las APIs de administración: hablan HTTP, y
# excluirlos dejaba fuera tanto los checks de exposición como los de higiene de
# certificado sobre servicios que son de los más graves que se pueden encontrar
# expuestos (L17).
_HTTP_PORTS = {80, 8080, 8000, 8888, 8008} | _TLS_HYGIENE_PORTS | _ADMIN_API_PORTS
# Service names and ports for FTP — Fase N's first ``type: "network"`` family.
_FTP_SERVICE_NAMES = {"ftp"}
_FTP_PORTS = {21}
# Fase N's remaining priority-1/2 protocols — same "name or well-known port"
# applicability shape as HTTP/FTP above.
_SMTP_SERVICE_NAMES = {"smtp", "submission", "smtps"}
_SMTP_PORTS = {25, 465, 587}
_IMAP_SERVICE_NAMES = {"imap", "imaps"}
_IMAP_PORTS = {143, 993}
_POP3_SERVICE_NAMES = {"pop3", "pop3s"}
_POP3_PORTS = {110, 995}
_SMB_SERVICE_NAMES = {"microsoft-ds", "netbios-ssn"}
_SMB_PORTS = {139, 445}
_MYSQL_SERVICE_NAMES = {"mysql"}
_MYSQL_PORTS = {3306}
_POSTGRES_SERVICE_NAMES = {"postgresql", "postgres"}
_POSTGRES_PORTS = {5432}
_MSSQL_SERVICE_NAMES = {"ms-sql-s", "mssql", "sqlserver"}
_MSSQL_PORTS = {1433}
_MONGODB_SERVICE_NAMES = {"mongodb", "mongo"}
_MONGODB_PORTS = {27017, 27018, 27019}
# 3268 es el Catálogo Global de Active Directory: mismo protocolo, y sirve el
# bosque entero en vez de un solo dominio. 636 y 3269 son sus variantes sobre
# TLS, que hablan LDAP igual una vez levantado el canal.
_RDP_SERVICE_NAMES = {"ms-wbt-server", "rdp", "msrdp", "terminal-server"}
_RDP_PORTS = {3389}
_LDAP_SERVICE_NAMES = {"ldap", "ldaps", "ldapssl", "globalcatldap", "globalcatldapssl"}
_LDAP_PORTS = {389, 636, 3268, 3269}
# El subconjunto que va cifrado, para la comprobación de "389 en claro
# conviviendo con un 636".
LDAPS_PORTS = {636, 3269}
_REDIS_SERVICE_NAMES = {"redis"}
_REDIS_PORTS = {6379}
_VNC_SERVICE_NAMES = {"vnc"}
_VNC_PORTS = {5900}
# SNMP — el primer protocolo de esta tabla que habla UDP (Fase N/Ronda 1,
# roadmap §6.3). 161 también aparece en WELL_KNOWN_PORTS como TCP, así que
# is_snmp_service (más abajo) es el único predicado de este módulo que mira
# service.protocol: sin esa guarda, un 161/tcp abierto arrastraría al
# dissector y al check a un datagrama que ese servicio nunca contestará.
_SNMP_SERVICE_NAMES = {"snmp"}
_SNMP_PORTS = {161}

# El resto de la superficie UDP (L22). Todos comparten con SNMP la guarda de
# protocolo por el mismo motivo: 53, 123, 137 y 1434 existen también como
# puertos TCP, y mandarle un datagrama a un servicio TCP es tiempo perdido y
# un hallazgo duplicado con la misma ``dedup_key``.
_DNS_SERVICE_NAMES = {"domain", "dns"}
_DNS_PORTS = {53}
_NTP_SERVICE_NAMES = {"ntp"}
_NTP_PORTS = {123}
_NETBIOS_SERVICE_NAMES = {"netbios-ns", "netbios"}
_NETBIOS_PORTS = {137}
_MDNS_SERVICE_NAMES = {"mdns", "zeroconf"}
_MDNS_PORTS = {5353}
_IKE_SERVICE_NAMES = {"isakmp", "ike"}
_IKE_PORTS = {500}
_MSSQL_BROWSER_SERVICE_NAMES = {"ms-sql-m", "sqlbrowser"}
_MSSQL_BROWSER_PORTS = {1434}


# =========================================================================
# HTTP RESPONSE + MATCHERS
# =========================================================================

@dataclass(frozen=True)
class Response:
    """A minimal HTTP response that matchers evaluate against.

    Attributes:
        status: The HTTP status code.
        body: The response body, decoded to text.
        headers: The response headers, with their keys lowercased.
    """
    status: int
    body: str
    headers: Dict[str, str]


@dataclass(frozen=True)
class Matcher:
    """One condition a response must satisfy for a check to fire.

    A matcher tests either the status code, the presence of any of a set of
    words, or a regular expression, against a chosen part of the response. When
    ``negative`` is set, the sense is inverted — useful for asserting that
    something is *absent*, such as a missing security header.

    Attributes:
        type: The kind of test — ``"status"``, ``"word"`` or ``"regex"``.
        part: Which part of the response to test — ``"body"``, ``"header"`` or
            ``"status"``.
        values: The status codes, words or patterns to test for.
        negative: If ``True``, the match result is inverted.
    """
    type: str
    part: str = "body"
    values: tuple = ()
    negative: bool = False

    def matches(self, response: Response) -> bool:
        """Return whether this matcher is satisfied by a response.

        Args:
            resp: The response to test.

        Returns:
            The test result, inverted if ``negative`` is set.
        """
        result = self._raw_match(response)
        return (not result) if self.negative else result

    def _raw_match(self, response: Response) -> bool:
        """Run the matcher's test, before any ``negative`` inversion."""
        if self.type == "status":
            return response.status in {int(expected_status) for expected_status in self.values}
        text = self._part_text(response)
        if self.type == "word":
            low = text.lower()
            return any(str(word).lower() in low for word in self.values)
        if self.type == "regex":
            return any(re.search(str(pattern), text) for pattern in self.values)
        return False

    def _part_text(self, response: Response) -> str:
        """Return the response text this matcher's ``part`` refers to."""
        if self.part == "header":
            return "\n".join(f"{k}: {v}" for k, v in response.headers.items())
        if self.part == "status":
            return str(response.status)
        return response.body


@dataclass(frozen=True)
class Request:
    """A single request plus the matchers that decide whether it fired.

    ``method``/``path`` drive a ``type: "http"`` check; ``send`` drives a
    ``type: "network"`` one instead — a raw payload written to the check's
    (single, shared across all of a check's requests) TCP connection, with the
    server's reply matched exactly like an HTTP response. ``send=None`` means
    "write nothing, just read" — the shape a banner-only check needs, since a
    protocol like FTP volunteers its banner unprompted.

    Attributes:
        method: The HTTP method. Unused by ``type: "network"``.
        path: The request path. Unused by ``type: "network"``.
        matchers: The matchers to evaluate against the response.
        condition: How to combine the matchers — ``"and"`` (all must match) or
            ``"or"`` (any).
        send: For ``type: "network"``, the raw payload to write before
            reading a reply (e.g. ``"USER anonymous\\r\\n"``). ``None`` reads
            without writing anything first. Unused by ``type: "http"``.
        read: For ``type: "network"``, how the reply *ends* — see
            :data:`NETWORK_READ_MODES`. The transport cannot know this on its
            own: where a reply stops is a fact about the protocol, so the feed
            declares it. Defaults to ``"line"``, the original behaviour.
            Unused by ``type: "http"``.
    """
    method: str = "GET"
    path: str = "/"
    matchers: tuple = ()
    condition: str = "and"
    send: Optional[str] = None
    read: str = "line"

    def evaluate(self, response: Response) -> bool:
        """Return whether this request's matchers are satisfied by a response.

        Args:
            resp: The response to the request.

        Returns:
            ``True`` if the matchers pass under the request's condition. A request
            with no matchers never fires.
        """
        if not self.matchers:
            return False
        results = [matcher.matches(response) for matcher in self.matchers]
        return all(results) if self.condition == "and" else any(results)


@dataclass(frozen=True)
class Check:
    """A declarative detection check (``type: "http"`` or ``type: "tls"``).

    Attributes:
        id: The check's short identifier, e.g. ``"git-config-exposure"``.
        version: The check's version number.
        type: The check kind — ``"http"`` (request/matchers) or ``"tls"``
            (hygiene rule evaluated against a handshake, see ``tls_rule``).
        category: The finding category to emit, e.g. ``"exposed_path"``.
        severity: A human-facing severity label.
        service: The service kind this check applies to, e.g. ``"http"``.
        mode: ``"safe"`` or ``"aggressive"`` — governs whether the runtime will
            run it in safe mode.
        requests: The requests the check makes; all must fire for it to match.
            Unused by ``type: "tls"`` checks.
        finding: A template of finding fields (title, qod, confirmed, ...) merged
            into the emitted finding.
        tls_rule: For ``type: "tls"`` checks, which hygiene rule to evaluate
            (see ``_TLS_RULES``). Unused by ``type: "http"`` checks.
        script: For ``type: "script"`` checks, the id of the first-party plugin
            that implements it (see ``script_checks.default_script_plugins``).
            Unused by every other type.
        namespace: Who authored this check — ``"lybra"`` for the first-party
            feed, ``"nuclei"`` for one translated from an upstream template.
            A translated check is not ours and must not claim to be: it shows
            up in ``check_id`` so a finding's provenance is readable.
        feed_version: The version of the feed this check came from, or ``None``
            to fall back to :data:`CHECKS_FEED_VERSION`. A single global
            constant stopped being truthful once checks could come from two
            feeds with independent version lines.
        expect_banner: For ``type: "network"``, whether the server volunteers a
            greeting the moment the connection opens (FTP, SMTP, POP3 and IMAP
            all do; Redis and MySQL do not). When set, the runtime reads and
            **discards** that greeting before writing the check's first
            payload. Without it the greeting is still sitting in the socket
            buffer and every subsequent read comes back one reply out of step
            — the whole check then matches against the wrong text and silently
            never fires.
        tags: Free-form labels (Nuclei's ``info.tags``, plus vendor/product
            metadata). Not used by the runtime, which runs whatever it is
            given: they exist so a *selector* can decide which of thousands of
            ingested checks are worth running against a given service before
            the runtime ever sees them (see ``ingest.selector``).
    """
    id: str
    version: int
    type: str
    category: str
    severity: str
    service: str
    mode: str
    requests: tuple
    finding: dict
    tls_rule: Optional[str] = None
    script: Optional[str] = None
    namespace: str = "lybra"
    feed_version: Optional[str] = None
    expect_banner: bool = False
    tags: tuple = ()

    @property
    def check_id(self) -> str:
        """The fully-qualified, versioned check id, e.g. ``lybra:git-config@1``."""
        return f"{self.namespace}:{self.id}@{self.version}"


# =========================================================================
# FEED LOADING
# =========================================================================

def load_feed_document(path: Path) -> dict:
    """Read a feed file into its raw document, dispatching on the extension.

    YAML is the feed's own format (Fase R); JSON is still accepted because the
    two shapes are the same object graph, and an externally-supplied feed may
    arrive as either. Only the deserializer differs — :func:`_parse_check` is
    given identical dicts in both cases, which is what makes the migration a
    format change rather than a behaviour one.

    Args:
        path: The feed file.

    Returns:
        The parsed document.
    """
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in (".yaml", ".yml"):
        return yaml.safe_load(text) or {}
    return json.loads(text)


def load_checks(path: Optional[str] = None) -> List[Check]:
    """Load and parse a check feed.

    Args:
        path: Path to a feed file, YAML or JSON. Defaults to the feed bundled
            with this module.

    Returns:
        The parsed checks.
    """
    feed_path = Path(path) if path else _BUNDLED_FEED
    data = load_feed_document(feed_path)
    return [_parse_check(check) for check in data.get("checks", [])]


def _parse_check(c: dict) -> Check:
    """Build a :class:`Check` from its raw document representation.

    Applies sensible defaults for optional fields and accepts a matcher's target
    values under any of ``words`` / ``regex`` / ``value``.
    """
    requests = tuple(
        Request(
            method=request.get("method", "GET"),
            path=request.get("path", "/"),
            condition=request.get("matchers-condition", "and"),
            send=request.get("send"),
            read=_parse_read_mode(request.get("read"), c.get("id")),
            matchers=tuple(
                Matcher(
                    type=matcher["type"],
                    part=matcher.get("part", "body"),
                    values=tuple(matcher.get("words") or matcher.get("regex") or matcher.get("value") or []),
                    negative=matcher.get("negative", False),
                )
                for matcher in request.get("matchers", [])
            ),
        )
        for request in c.get("requests", [])
    )
    check = Check(
        id=c["id"],
        version=c.get("version", 1),
        type=c.get("type", "http"),
        category=c.get("category", "exposed_path"),
        severity=c.get("severity", "INFO"),
        service=c.get("service", "http"),
        mode=c.get("mode", "safe"),
        requests=requests,
        finding=c.get("finding", {}),
        tls_rule=c.get("tlsRule"),
        script=c.get("script"),
        expect_banner=bool(c.get("expectBanner", False)),
    )
    _assert_service_is_reachable(check)
    return check


def _assert_service_is_reachable(check: Check) -> None:
    """Fail loudly when a ``network`` check names a protocol nobody can match.

    A check whose ``service`` has no predicate can never apply to anything: it
    is a bug in the feed, not a runtime case. Left to fall through it looks
    exactly like "this check simply did not fire against this host", which is
    normal and unremarkable — so nobody ever finds out. Raising here puts the
    error where a human is looking, at load time.

    Only ``network`` checks are validated: the other families do not dispatch
    on this field (``http`` and ``tls`` decide by service shape, ``script``
    delegates to its plugin), so an odd ``service`` there is a label and not a
    routing decision.

    Args:
        check: The freshly parsed check.

    Raises:
        ValueError: If a ``network`` check names an unknown protocol.
    """
    if check.type != "network" or check.service in _NETWORK_SERVICE_MATCHERS:
        return
    raise ValueError(
        f"Check {check.id!r}: el servicio {check.service!r} no tiene predicado "
        f"(disponibles: {', '.join(sorted(_NETWORK_SERVICE_MATCHERS))})"
    )


def _parse_read_mode(declared: Optional[str], check_id: Optional[str]) -> str:
    """Validate a request's declared ``read`` mode, defaulting to ``"line"``.

    A mode nobody implements is a feed bug, not a runtime case: left to fall
    back silently it would read one line where the protocol needs a block and
    the check would simply never fire — the same class of silent false
    negative this whole change exists to remove. So it raises at load time,
    where a human is looking.

    Args:
        declared: The feed's ``read`` value, or ``None`` when absent.
        check_id: The check being parsed, for the error message.

    Returns:
        The validated mode name.

    Raises:
        ValueError: If ``declared`` names a mode that does not exist.
    """
    if declared is None:
        return "line"
    mode = str(declared).strip().lower()
    if mode not in NETWORK_READ_MODES:
        raise ValueError(
            f"Check {check_id!r}: modo de lectura {declared!r} desconocido "
            f"(disponibles: {', '.join(sorted(NETWORK_READ_MODES))})"
        )
    return mode


# =========================================================================
# FEED VALIDATION
# =========================================================================

# Las familias de check que el runtime sabe despachar. Un ``type`` fuera de
# esta lista no lanza: cae por los cuatro ``_applies_*`` y desaparece.
CHECK_TYPES = ("http", "tls", "network", "script")

# Los modos de ejecución. ``aggressive`` sólo corre cuando el runtime lo
# autoriza explícitamente; cualquier otra palabra deja el check sin modo
# reconocible.
CHECK_MODES = ("safe", "aggressive")

# Las familias de hallazgo que un check puede declarar. No es el vocabulario
# entero de ``Finding.category`` —el motor emite además ``open_port``,
# ``outdated_software``, ``fingerprint`` y ``surface_change`` por su cuenta,
# sin pasar por el feed—, sino lo que tiene sentido que declare una regla de
# detección. Una categoría inventada no rompe nada visible: el hallazgo se
# guarda igual y aparece bajo una familia que ningún filtro de la interfaz
# conoce.
CHECK_CATEGORIES = (
    "exposed_path",
    # Un servicio entero alcanzable sin credenciales, no un fichero suelto que
    # se coló bajo la raíz web (L17). La distinción no es cosmética: un
    # `exposed_path` es un descuido del despliegue, y un `exposed_service` es
    # el propio servicio ofreciéndose sin puerta — una API de Docker en claro
    # es ejecución remota de código como root sin exploit ninguno.
    "exposed_service",
    "default_credentials",
    "security_header",
    "network_config",
    "tls",
    "vulnerability",
    "web_finding",
)

# Los tipos de matcher que ``Matcher._raw_match`` implementa. Cualquier otro
# devuelve ``False`` sin decir nada, que en un matcher negativo significa
# además lo contrario de lo que el autor quería.
MATCHER_TYPES = ("status", "word", "regex")

# Las partes de la respuesta que ``Matcher._part_text`` sabe leer. Una parte
# desconocida cae en el defecto (``body``), así que un ``part: "headers"`` en
# plural busca en el cuerpo y nunca encuentra la cabecera.
MATCHER_PARTS = ("body", "header", "status")


def validate_checks(checks: Iterable[Check]) -> List[str]:
    """Comprobar que ningún check está muerto por construcción.

    El feed son **datos que se ejecutan**: reglas que deciden si un hallazgo de
    seguridad existe. Y su forma de fallar es siempre la misma, la peor: en
    silencio. Un ``tlsRule`` mal escrito cae por ``check.tls_rule not in
    _TLS_RULES`` y el check no aplica nunca; un ``script`` que no existe cae
    por ``plugin is None``; un ``type`` con un typo no lo reconoce ninguno de
    los cuatro ``_applies_*``. En los tres casos el escaneo termina en verde y
    lo único que ocurre es que una vulnerabilidad deja de detectarse.

    Esta función no juzga si un check es *bueno* —eso lo miden los bancos de la
    Fase 1—, sólo si puede llegar a ejecutarse. Devuelve los problemas en vez
    de lanzar, para poder revisar un feed entero de una pasada en lugar de
    arreglar de uno en uno; el test que la usa afirma que la lista está vacía.

    Args:
        checks: Los checks ya parseados (``load_checks`` o ``translate_all``).

    Returns:
        Una lista de problemas legibles, vacía si el feed está sano.
    """
    # Importación diferida a propósito: ``script_checks`` importa predicados de
    # este módulo, así que un import arriba cerraría el ciclo. Es el mismo
    # motivo por el que ``ScriptContext`` vive aquí y no junto a los plugins.
    from .script_checks import default_script_plugins

    script_ids = set(default_script_plugins())
    problems: List[str] = []
    seen: set = set()

    for check in checks:
        name = check.id or "<sin id>"

        if not check.id:
            problems.append("Un check no declara 'id'")
        if (check.id, check.version) in seen:
            problems.append(f"Check {name!r}: duplicado en (id, version)={(check.id, check.version)}")
        seen.add((check.id, check.version))

        if not isinstance(check.version, int) or isinstance(check.version, bool) or check.version < 1:
            problems.append(f"Check {name!r}: 'version' debe ser un entero positivo, no {check.version!r}")
        if check.type not in CHECK_TYPES:
            problems.append(f"Check {name!r}: tipo {check.type!r} desconocido (disponibles: {', '.join(CHECK_TYPES)})")
        if check.mode not in CHECK_MODES:
            problems.append(f"Check {name!r}: modo {check.mode!r} desconocido (disponibles: {', '.join(CHECK_MODES)})")
        if check.severity not in PRIORITY_LADDER:
            problems.append(f"Check {name!r}: severidad {check.severity!r} fuera de la escalera ({', '.join(PRIORITY_LADDER)})")
        if check.category not in CHECK_CATEGORIES:
            problems.append(f"Check {name!r}: categoría {check.category!r} desconocida (disponibles: {', '.join(CHECK_CATEGORIES)})")

        if check.type == "tls" and check.tls_rule not in _TLS_RULES:
            problems.append(
                f"Check {name!r}: regla TLS {check.tls_rule!r} sin implementación "
                f"(disponibles: {', '.join(sorted(_TLS_RULES))})"
            )
        if check.type == "script" and check.script not in script_ids:
            problems.append(
                f"Check {name!r}: script {check.script!r} sin plugin "
                f"(disponibles: {', '.join(sorted(script_ids))})"
            )
        if check.type == "network" and check.service not in _NETWORK_SERVICE_MATCHERS:
            problems.append(
                f"Check {name!r}: el servicio {check.service!r} no tiene predicado "
                f"(disponibles: {', '.join(sorted(_NETWORK_SERVICE_MATCHERS))})"
            )

        # Un check http/network sin peticiones no puede casar nada: el runtime
        # exige que **todas** las peticiones acierten, y sobre cero peticiones
        # eso es vacuamente cierto o directamente inalcanzable según el camino.
        # Los tls y los script no las usan.
        if check.type in ("http", "network") and not check.requests:
            problems.append(f"Check {name!r}: de tipo {check.type!r} y sin ninguna petición")

        for position, request in enumerate(check.requests):
            where = f"Check {name!r}, petición {position}"
            if request.read not in NETWORK_READ_MODES:
                problems.append(f"{where}: modo de lectura {request.read!r} desconocido")
            if not request.matchers:
                problems.append(f"{where}: sin ningún matcher, así que nunca decide nada")
            for matcher in request.matchers:
                if matcher.type not in MATCHER_TYPES:
                    problems.append(f"{where}: matcher de tipo {matcher.type!r} desconocido")
                if matcher.part not in MATCHER_PARTS:
                    problems.append(f"{where}: matcher sobre la parte {matcher.part!r}, que no existe")
                if not matcher.values:
                    problems.append(f"{where}: matcher {matcher.type!r} sin valores que buscar")

    return problems


# =========================================================================
# RUNTIME
# =========================================================================

def is_http_service(service: Service) -> bool:
    """Return whether a service should be probed by HTTP checks.

    Args:
        service: The service to test.

    Returns:
        ``True`` if the service's name or port looks like HTTP.
    """
    return (service.name or "").lower() in _HTTP_SERVICE_NAMES or service.port in _HTTP_PORTS


def is_tls_service(service: Service) -> bool:
    """Return whether a service is a candidate for the TLS hygiene checks.

    Candidacy, not identification: this says "merece la pena intentar el
    handshake aquí", and the checks themselves abandon quietly if there is no
    TLS on the other side. It is deliberately *not* the function that decides
    whether to speak HTTPS to a service — that is observed, not guessed (see
    :func:`negotiates_tls`).

    Args:
        service: The service to test.

    Returns:
        ``True`` if the service's port is one where TLS is common enough to be
        worth a handshake.
    """
    return service.port in _TLS_HYGIENE_PORTS


def is_ftp_service(service: Service) -> bool:
    """Return whether a service should be probed by FTP ``type: "network"`` checks.

    Args:
        service: The service to test.

    Returns:
        ``True`` if the service's name or port looks like FTP.
    """
    return (service.name or "").lower() in _FTP_SERVICE_NAMES or service.port in _FTP_PORTS


def is_smtp_service(service: Service) -> bool:
    """Return whether a service should be probed by the SMTP dissector."""
    return (service.name or "").lower() in _SMTP_SERVICE_NAMES or service.port in _SMTP_PORTS


def is_imap_service(service: Service) -> bool:
    """Return whether a service should be probed by the IMAP dissector."""
    return (service.name or "").lower() in _IMAP_SERVICE_NAMES or service.port in _IMAP_PORTS


def is_pop3_service(service: Service) -> bool:
    """Return whether a service should be probed by the POP3 dissector."""
    return (service.name or "").lower() in _POP3_SERVICE_NAMES or service.port in _POP3_PORTS


def is_smb_service(service: Service) -> bool:
    """Return whether a service should be probed by the SMB dissector."""
    return (service.name or "").lower() in _SMB_SERVICE_NAMES or service.port in _SMB_PORTS


def is_mysql_service(service: Service) -> bool:
    """Return whether a service should be probed by the MySQL dissector."""
    return (service.name or "").lower() in _MYSQL_SERVICE_NAMES or service.port in _MYSQL_PORTS


def is_postgres_service(service: Service) -> bool:
    """Return whether a service should be probed by the PostgreSQL dissector."""
    return ((service.name or "").lower() in _POSTGRES_SERVICE_NAMES
            or service.port in _POSTGRES_PORTS)


def is_mssql_service(service: Service) -> bool:
    """Return whether a service should be probed by the SQL Server dissector."""
    return ((service.name or "").lower() in _MSSQL_SERVICE_NAMES
            or service.port in _MSSQL_PORTS)


def is_mongodb_service(service: Service) -> bool:
    """Return whether a service should be probed by the MongoDB dissector.

    27018 y 27019 entran junto al 27017: son los puertos por defecto de un
    ``mongos`` y de un servidor de configuración en un despliegue fragmentado,
    y ahí es donde vive el catálogo entero del clúster.
    """
    return ((service.name or "").lower() in _MONGODB_SERVICE_NAMES
            or service.port in _MONGODB_PORTS)


def is_ldap_service(service: Service) -> bool:
    """Return whether a service should be probed by the LDAP dissector."""
    return (service.name or "").lower() in _LDAP_SERVICE_NAMES or service.port in _LDAP_PORTS


def is_rdp_service(service: Service) -> bool:
    """Return whether a service should be probed by the RDP dissector."""
    return (service.name or "").lower() in _RDP_SERVICE_NAMES or service.port in _RDP_PORTS


def is_redis_service(service: Service) -> bool:
    """Return whether a service should be probed by the Redis dissector or
    ``type: "network"`` checks (Fase N)."""
    return (service.name or "").lower() in _REDIS_SERVICE_NAMES or service.port in _REDIS_PORTS


def is_vnc_service(service: Service) -> bool:
    """Return whether a service should be probed by the VNC dissector."""
    return (service.name or "").lower() in _VNC_SERVICE_NAMES or service.port in _VNC_PORTS


def is_snmp_service(service: Service) -> bool:
    """Return whether a service should be probed by the SNMP dissector/check.

    The only predicate in this module that inspects ``service.protocol``: 161
    is a recognised TCP port too (``WELL_KNOWN_PORTS``), and the SNMP probe
    speaks UDP exclusively, so without this guard a 161/tcp open port would
    be handed a datagram it can never answer — and would collide on
    ``dedup_key`` with the genuine 161/udp finding (see
    ``lybra/correlation.py::compute_dedup_key``). ``protocol or "tcp"``
    defaults an inventory-origin service (empty protocol) to non-UDP too.
    """
    if (service.protocol or "tcp").lower() != "udp":
        return False
    return (service.name or "").lower() in _SNMP_SERVICE_NAMES or service.port in _SNMP_PORTS


def is_admin_api_service(service: Service) -> bool:
    """Si el servicio es una de las APIs de administración de :mod:`http_apis`.

    Decide qué puertos reclama ``AdminApiDissector``. No es un predicado de
    check —para eso están los seis de abajo, uno por producto— sino el que
    separa esta familia de la sonda HTTP genérica.
    """
    return service.port in _ADMIN_API_PORTS


def is_docker_service(service: Service) -> bool:
    """Si el servicio es la API de Docker (2375 en claro, 2376 con TLS)."""
    return (service.name or "").lower() in _DOCKER_SERVICE_NAMES or service.port in _DOCKER_PORTS


def is_elasticsearch_service(service: Service) -> bool:
    """Si el servicio es la API REST de Elasticsearch."""
    return ((service.name or "").lower() in _ELASTICSEARCH_SERVICE_NAMES
            or service.port in _ELASTICSEARCH_PORTS)


def is_kibana_service(service: Service) -> bool:
    """Si el servicio es Kibana."""
    return (service.name or "").lower() in _KIBANA_SERVICE_NAMES or service.port in _KIBANA_PORTS


def is_kubernetes_service(service: Service) -> bool:
    """Si el servicio es el servidor de API de Kubernetes."""
    return ((service.name or "").lower() in _KUBERNETES_SERVICE_NAMES
            or service.port in _KUBERNETES_PORTS)


def is_etcd_service(service: Service) -> bool:
    """Si el servicio es etcd."""
    return (service.name or "").lower() in _ETCD_SERVICE_NAMES or service.port in _ETCD_PORTS


def is_consul_service(service: Service) -> bool:
    """Si el servicio es el agente de Consul."""
    return (service.name or "").lower() in _CONSUL_SERVICE_NAMES or service.port in _CONSUL_PORTS


def _is_udp(service: Service) -> bool:
    """Si el servicio se descubrió por UDP.

    ``protocol or "tcp"`` da por no-UDP a un servicio de origen inventario, que
    llega con el protocolo vacío.
    """
    return (service.protocol or "tcp").lower() == "udp"


def is_dns_service(service: Service) -> bool:
    """Return whether a service should be probed by the DNS dissector."""
    return _is_udp(service) and (
        (service.name or "").lower() in _DNS_SERVICE_NAMES or service.port in _DNS_PORTS)


def is_ntp_service(service: Service) -> bool:
    """Return whether a service should be probed by the NTP dissector."""
    return _is_udp(service) and (
        (service.name or "").lower() in _NTP_SERVICE_NAMES or service.port in _NTP_PORTS)


def is_netbios_service(service: Service) -> bool:
    """Return whether a service should be probed by the NetBIOS-NS dissector."""
    return _is_udp(service) and (
        (service.name or "").lower() in _NETBIOS_SERVICE_NAMES
        or service.port in _NETBIOS_PORTS)


def is_mdns_service(service: Service) -> bool:
    """Return whether a service should be probed by the mDNS dissector."""
    return _is_udp(service) and (
        (service.name or "").lower() in _MDNS_SERVICE_NAMES or service.port in _MDNS_PORTS)


def is_ike_service(service: Service) -> bool:
    """Return whether a service should be probed by the IKE dissector."""
    return _is_udp(service) and (
        (service.name or "").lower() in _IKE_SERVICE_NAMES or service.port in _IKE_PORTS)


def is_mssql_browser_service(service: Service) -> bool:
    """Return whether a service is the UDP SQL Server Browser.

    Distinto de :func:`is_mssql_service`, que reclama el 1433/tcp: son dos
    servicios del mismo producto con dos protocolos y dos sondas.
    """
    return _is_udp(service) and (
        (service.name or "").lower() in _MSSQL_BROWSER_SERVICE_NAMES
        or service.port in _MSSQL_BROWSER_PORTS)


def _network_service_matchers() -> Dict[str, Callable[[Service], bool]]:
    """Derive the ``service`` → predicate map from this module's own predicates.

    A ``type: "network"`` check declares which protocol it targets as a plain
    string (``service: ftp``), and the runtime needs the predicate that decides
    whether a discovered service *is* that protocol. That map used to be
    written out by hand and had **two** entries while the module already
    defined eleven predicates: a check for SMTP, MySQL or VNC loaded fine,
    validated fine, and was then dropped without a word.

    Deriving it removes the second edit entirely — defining
    ``is_mongodb_service`` is all it takes for ``service: mongodb`` to work.

    Introspection rather than the ``@register_dissector`` decorator the
    fingerprinting package uses, and for a reason: a decorator would have to
    restate the protocol name (``@service_predicate("ftp")``) that the
    function name already carries, which is one more place for the two to
    disagree. Here the naming convention *is* the registration.
    """
    suffix = "_service"
    return {
        name[len("is_"):-len(suffix)]: predicate
        for name, predicate in globals().items()
        if name.startswith("is_") and name.endswith(suffix) and callable(predicate)
    }


_NETWORK_SERVICE_MATCHERS: Dict[str, Callable[[Service], bool]] = _network_service_matchers()


# Protocol versions considered deprecated/weak for a service exposed today.
_WEAK_TLS_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}

# Familias de cifrado que hoy se consideran débiles: sin autenticación (aNULL),
# sin cifrado (eNULL), exportación, DES/3DES, RC4 y MD5. El nombre del suite
# negociado los delata como subcadena — "ECDHE-RSA-DES-CBC3-SHA" trae "DES", y
# "TLS_RSA_WITH_RC4_128_SHA" trae "RC4". Se compara en mayúsculas porque OpenSSL
# y la RFC nombran los suites en formatos distintos.
_WEAK_TLS_CIPHER_TOKENS = ("NULL", "EXPORT", "DES", "RC4", "MD5", "_CBC3_", "3DES")

# TLS hygiene rules a ``type: "tls"`` check can reference via ``tlsRule`` in the
# feed. Each takes the ``TlsInfo`` a probe returned (duck-typed — this module
# never imports the fingerprint module, to avoid a checks<->fingerprint
# import cycle) and decides whether the check fires.
_TLS_RULES: Dict[str, Callable] = {
    "self_signed": lambda info: info.self_signed,
    "expired": lambda info: info.expired,
    "expiring_soon": lambda info: not info.expired and info.days_until_expiry is not None and info.days_until_expiry <= 30,
    "deprecated_protocol": lambda info: info.protocol in _WEAK_TLS_PROTOCOLS,
    "weak_cipher": lambda info: bool(info.cipher) and any(
        token in info.cipher.upper() for token in _WEAK_TLS_CIPHER_TOKENS),
}


@dataclass(frozen=True)
class ScriptContext:
    """The restricted API a ``type: "script"`` plugin runs against (Fase R).

    A script check exists for what a declarative one cannot express: binary
    protocols, multi-step negotiations, anything needing real logic. What it
    does *not* get is free rein — a plugin never opens its own connections at
    its own pace, it receives the same pieces the runtime already holds. That
    keeps one rate policy and one place where the engine touches the network.

    The class lives here, next to the runtime, rather than beside the concrete
    plugins: those import applicability predicates from this module, so putting
    the base here is what keeps the dependency one-way.

    Attributes:
        target: The host the check runs against.
        service: The specific service being evaluated.
        rate_limiter: The per-host limiter; a plugin acquires it before each
            network exchange, exactly as the dissectors do.
        mode: ``"safe"`` or ``"aggressive"`` — the mode the runtime already
            authorised this check under, in case a plugin wants to adapt.
        sibling_services: Los demás servicios descubiertos en el **mismo host**.
            Hay hallazgos que no son propiedad de un servicio sino de la
            relación entre dos: un LDAP en claro en el 389 no dice nada por sí
            solo, y dice bastante si el mismo host publica además un 636. El
            runtime ya tiene la lista completa mientras itera, así que dársela
            al plugin no cuesta ninguna petición de red — y sin ella, el plugin
            tendría que descubrir puertos por su cuenta, que es justo lo que
            esta clase existe para impedir.
    """
    target: str
    service: Service
    rate_limiter: Optional["HostRateLimiter"] = None
    mode: str = "safe"
    sibling_services: tuple = ()

    def acquire(self) -> None:
        """Respect the host's rate limit before touching the network."""
        if self.rate_limiter is not None:
            self.rate_limiter.acquire(self.target)


class ScriptPlugin:
    """The logic behind a ``type: "script"`` check.

    Same shape as :class:`~.fingerprinting.dispatch.Dissector` — applicability
    plus action — so knowing one means knowing the other.

    **First-party only.** Only plugins we write and review are accepted here.
    Third-party Python is never executed in-process, because Python cannot be
    sandboxed with any guarantee inside the same process; the route for that,
    if it were ever wanted, is a subprocess with ``rlimit``/seccomp and narrow
    IPC — not this registry.
    """

    plugin_id: str = ""

    def applies(self, service: Service) -> bool:
        """Return whether this plugin should evaluate ``service`` at all."""
        raise NotImplementedError

    def run(self, context: ScriptContext) -> bool:
        """Run the check.

        Returns:
            ``True`` if the check fires. ``False`` both when the condition does
            not hold and when no evidence could be gathered — no evidence means
            no finding, the same rule the declarative families follow on a
            transport failure.
        """
        raise NotImplementedError


@dataclass(frozen=True)
class _CheckFamily:
    """One check ``type`` (http/tls/network) as the runtime's uniform loop sees it.

    Where :meth:`CheckRuntime.run` used to be three near-identical loops — one
    literally written per check type — each type now supplies one of these
    instead: whether it wants a look at a given service at all
    (``applies_to_service``), whether one specific check within that type
    applies (``check_matches``), and how to actually run it
    (``run_check``). Adding a fourth type (Fase R's planned ``script``) means
    adding one more family, not a fourth loop.
    """
    applies_to_service: Callable[[Service], bool]
    check_matches: Callable[[Check, Service], bool]
    run_check: Callable[[Check, str, Service], Optional[dict]]


class CheckRuntime:
    """Runs a set of checks against a host's HTTP services and emits findings.

    The runtime is pure with respect to the network: it never opens a connection
    itself, it calls the injected ``fetch``. That is what lets tests drive it with
    canned responses.

    Args:
        checks: The checks to run.
        fetch: A ``(host, port, method, path) -> Response | None`` callable. A
            ``None`` result means the request failed or timed out, in which case
            the check is abandoned rather than counted as a hit.
        mode: ``"safe"`` runs only checks marked safe; ``"aggressive"`` runs both.
        rate_limiter: An optional per-host limiter applied before each request.
        tls_fetch: An optional ``(host, port) -> TlsInfo | None`` callable for
            ``type: "tls"`` checks. When omitted, TLS checks are simply skipped
            — callers that never wire a TLS probe pay nothing for this family.
        network_open: An optional ``(host, port) -> NetworkSession | None``
            callable for ``type: "network"`` checks (Fase N). One session is
            opened per check per service and every request in that check is
            exchanged over the *same* connection, in order — this is what
            makes a login sequence like FTP's ``USER``/``PASS`` work. Omitted
            the same way ``tls_fetch`` is: callers that never wire a network
            probe pay nothing for this family.
        script_plugins: An optional ``{plugin_id: ScriptPlugin}`` registry for
            ``type: "script"`` checks (Fase R). Injected rather than imported
            so this module never has to import the fingerprinting package,
            which would close an import cycle (the dissectors import their
            applicability predicates from here). Omitted the same way the two
            above are.
    """

    def __init__(
        self,
        checks: Iterable[Check],
        fetch: Callable[[str, Optional[int], str, str], Optional[Response]],
        mode: str = "safe",
        rate_limiter: Optional["HostRateLimiter"] = None,
        tls_fetch: Optional[Callable[[str, int], object]] = None,
        network_open: Optional[Callable[[str, int], Optional["NetworkSession"]]] = None,
        script_plugins: Optional[Dict[str, object]] = None,
        mapper: Optional[Callable] = None,
    ) -> None:
        self._checks = list(checks)
        self._fetch = fetch
        self._mode = mode
        self._rl = rate_limiter
        self._tls_fetch = tls_fetch
        self._network_open = network_open
        self._script_plugins = dict(script_plugins or {})
        # Cómo se recorren los servicios. Por defecto, el ``map`` de siempre:
        # uno detrás de otro. El manager inyecta aquí un pool acotado por host
        # (L23), igual que ya inyecta las sondas — este módulo no conoce la
        # configuración ni monta hilos por su cuenta.
        self._mapper: Callable = mapper or map
        # El host y sus servicios de la ejecución en curso: los rellena
        # :meth:`run`, y viven aquí para que un plugin de tipo ``script``
        # pueda ver los servicios hermanos sin descubrirlos por su cuenta.
        self._host = ''
        self._services: Tuple[Service, ...] = ()
        # Sondas compartidas dentro de una ejecución; :meth:`run` las vacía al
        # empezar. Aquí sólo para que el objeto esté completo desde que nace.
        self._responses: Dict[tuple, Optional[Response]] = {}
        self._handshakes: Dict[tuple, object] = {}
        self._families: Tuple[_CheckFamily, ...] = (
            _CheckFamily(
                applies_to_service=is_http_service,
                check_matches=lambda check, service: self._applies(check),
                run_check=self._run_check,
            ),
            _CheckFamily(
                applies_to_service=lambda service: self._tls_fetch is not None and is_tls_service(service),
                check_matches=lambda check, service: self._applies_tls(check),
                run_check=self._run_tls_check,
            ),
            _CheckFamily(
                applies_to_service=lambda service: self._network_open is not None,
                check_matches=self._applies_network,
                run_check=self._run_network_check,
            ),
            _CheckFamily(
                applies_to_service=lambda service: bool(self._script_plugins),
                check_matches=self._applies_script,
                run_check=self._run_script_check,
            ),
        )

    def run(self, host: str, services: Iterable[Service]) -> List[dict]:
        """Run every applicable check against a host's HTTP, TLS and network services.

        Probes are shared within one call: several checks reading the same
        evidence make one request between them, not one each. See
        :meth:`_probe_response` for why that is a property of this loop and not
        a caching layer.

        Los servicios se evalúan **a la vez** dentro de un pool acotado (L23),
        no en fila india: estos checks son espera de red casi entera, y un
        servicio que no contesta retrasaba a todos los que venían detrás. El
        ritmo por host lo sigue marcando el limitador, que es seguro entre
        hilos; el pool sólo decide cuántas sondas pueden estar esperando a la
        vez. El orden de los hallazgos no cambia — ver
        :meth:`_run_for_service`.

        Args:
            host: The target host.
            services: The host's discovered services (non-applicable ones are
                skipped per check family).

        Returns:
            A finding dict for each check that fired.
        """
        # La caché nace y muere con la ejecución: dos escaneos del mismo
        # objetivo tienen que volver a mirar, porque entre uno y otro el
        # objetivo ha podido cambiar — que es justo lo que un escáner mide.
        self._responses: Dict[tuple, Optional[Response]] = {}
        self._handshakes: Dict[tuple, object] = {}

        services = tuple(services)
        # Los plugins de tipo ``script`` pueden necesitar ver los servicios
        # hermanos del mismo host (ver ``ScriptContext.sibling_services``). La
        # lista ya está aquí; guardarla evita que un plugin tenga que
        # redescubrirla por su cuenta.
        self._services = services
        self._host = host

        per_service = self._mapper(self._run_for_service, services)
        return [finding for group in per_service for finding in group]

    def _run_for_service(self, service: Service) -> List[dict]:
        """Ejecuta todos los checks aplicables a **un** servicio.

        Es la unidad de trabajo del pool (L23), y la razón de que el pool sea
        seguro sin candados: las cachés de respuesta y de handshake se indexan
        por ``(host, puerto, ...)``, así que **cada hilo toca sólo las claves de
        su propio servicio**. Dos checks del mismo servicio siguen compartiendo
        una petición, que es para lo que la caché existe; dos servicios distintos
        no compiten por ninguna entrada.

        Args:
            service: El servicio a evaluar.

        Returns:
            Los hallazgos de ese servicio, en el orden del feed.
        """
        findings: List[dict] = []
        for family in self._families:
            if not family.applies_to_service(service):
                continue
            for check in self._checks:
                if not family.check_matches(check, service):
                    continue
                finding = family.run_check(check, self._host, service)
                if finding is not None:
                    findings.append(finding)
        return findings

    def _applies(self, check: Check) -> bool:
        """Return whether an ``http`` check should run in the current mode."""
        if check.type != "http":
            return False
        return self._applies_mode(check)

    def _applies_tls(self, check: Check) -> bool:
        """Return whether a TLS check should run in the current mode."""
        if check.type != "tls" or check.tls_rule not in _TLS_RULES:
            return False
        return self._applies_mode(check)

    def _applies_network(self, check: Check, service: Service) -> bool:
        """Return whether a ``type: "network"`` check should run against a service.

        Dispatches on the check's declared ``service`` (e.g. ``"ftp"``) via
        :data:`_NETWORK_SERVICE_MATCHERS`, so the runtime itself never needs to
        know about a specific protocol — only each protocol's applicability
        predicate does.

        A check the feed loader already rejected cannot reach this point, so an
        unknown protocol here means a check that never went through it — one
        translated from a Nuclei template, whose ``service`` is whatever the
        upstream document said. It is still a check that can never fire, so it
        is logged rather than silently skipped: the two cases (unknown protocol
        / protocol that does not apply to this service) are not the same thing
        and must not look the same.
        """
        if check.type != "network":
            return False
        matches = _NETWORK_SERVICE_MATCHERS.get(check.service)
        if matches is None:
            logger.warning(
                "Check %s declara el servicio %r, que no tiene predicado: no se ejecutará",
                check.check_id, check.service,
            )
            return False
        if not matches(service):
            return False
        return self._applies_mode(check)

    def _applies_script(self, check: Check, service: Service) -> bool:
        """Return whether a ``type: "script"`` check should run against a service.

        Applicability is delegated to the plugin itself (``plugin.applies``),
        the same way a ``network`` check delegates to its protocol predicate —
        the runtime stays ignorant of what SMB, or any other protocol, is.
        """
        if check.type != "script":
            return False
        plugin = self._script_plugins.get(check.script)
        if plugin is None or not plugin.applies(service):
            return False
        return self._applies_mode(check)

    def _applies_mode(self, check: Check) -> bool:
        """Return whether ``check`` is allowed to run under the current safe/aggressive mode."""
        return not (self._mode == "safe" and check.mode == "aggressive")

    def _run_check(self, check: Check, host: str, service: Service) -> Optional[dict]:
        """Run one check against one service, returning a finding if it fired.

        Every request in the check must fire (they are combined with AND). If any
        request fails to reach the target or does not match, the check produces
        nothing.
        """
        for request in check.requests:
            response = self._probe_response(host, service, request.method, request.path)
            if response is None or not request.evaluate(response):
                return None
        return self._finding(check, service)

    def _probe_response(self, host: str, service: Service, method: str, path: str) -> Optional[Response]:
        """Return the response for one request, asking the target only once.

        Every check runs independently, which is what keeps them simple, but
        the feed has three ``security_header`` checks and all three inspect the
        headers of the same ``GET /``. Run literally, that is three identical
        requests, three rate-limiter waits, and three entries in the target's
        access log for one bit of information.

        Noise on the target is not a side issue for a security scanner: it
        shows up in the SIEM of whoever hired us. So a response is fetched once
        per ``(method, path)`` and shared by every check that asks for it,
        within one :meth:`run`.

        A transport failure is remembered too. Not caching it would mean three
        attempts against a service that is down — the case where retrying costs
        the most and informs the least.
        """
        key = (host, service.port, method, path)
        if key in self._responses:
            return self._responses[key]
        if self._rl is not None:
            self._rl.acquire(host)
        response = self._fetch(host, service.port, method, path)
        self._responses[key] = response
        return response

    def _probe_handshake(self, host: str, service: Service):
        """Return the TLS handshake facts for one service, negotiating once.

        Same reasoning as :meth:`_probe_response`: the three ``tls`` checks in
        the feed evaluate three different rules over the **same** ``TlsInfo``,
        so there is no reason to shake hands three times with the same port.
        """
        key = (host, service.port)
        if key in self._handshakes:
            return self._handshakes[key]
        if self._rl is not None:
            self._rl.acquire(host)
        info = self._tls_fetch(host, service.port)
        self._handshakes[key] = info
        return info

    def _run_tls_check(self, check: Check, host: str, service: Service) -> Optional[dict]:
        """Run one TLS hygiene check against one service's handshake.

        A transport failure (unreachable, handshake error) abandons the check —
        no evidence means no finding, the same rule ``_run_check`` follows.
        """
        info = self._probe_handshake(host, service)
        if info is None or not _TLS_RULES[check.tls_rule](info):
            return None
        return self._finding(check, service)

    def _run_network_check(self, check: Check, host: str, service: Service) -> Optional[dict]:
        """Run one network check against one service, returning a finding if it fired.

        Opens a single session and exchanges every request's ``send`` payload
        over it in order (combined with AND, same as ``_run_check``) — the
        session, not a fresh connection per request, is what lets a login
        sequence like FTP's ``USER``/``PASS`` see its own prior state.

        When the check declares ``expectBanner``, the server's unprompted
        greeting is read and thrown away first. It has to be: the greeting is
        already in the socket buffer at connect time, so leaving it there would
        put every later read one reply out of step — the check would evaluate
        ``USER``'s matchers against the greeting and never fire.
        """
        if self._rl is not None:
            self._rl.acquire(host)
        session = self._network_open(host, service.port)
        if session is None:
            return None
        try:
            if check.expect_banner:
                # Read as a block: a greeting may span several continuation
                # lines, and a single-line one ends the block immediately.
                session.exchange(None, read="block")
            for request in check.requests:
                response = session.exchange(request.send, read=request.read)
                if response is None or not request.evaluate(response):
                    return None
            return self._finding(check, service)
        finally:
            session.close()

    def _run_script_check(self, check: Check, host: str, service: Service) -> Optional[dict]:
        """Run one ``type: "script"`` check against one service (Fase R).

        The plugin handles its own rate limiting through the context, since
        only it knows how many exchanges it needs — unlike the declarative
        families, where the runtime knows because the feed spells it out.

        A plugin that raises is contained here rather than being allowed to sink
        the whole scan: these are first-party plugins, but they run arbitrary
        multi-step protocol logic, and one throwing on a malformed reply from
        some appliance must cost that one check and nothing more.
        """
        plugin = self._script_plugins.get(check.script)
        context = ScriptContext(
            target=host,
            service=service,
            rate_limiter=self._rl,
            mode=self._mode,
            sibling_services=self._services,
        )
        try:
            fired = plugin.run(context)
        except Exception:  # noqa: BLE001 - a broken plugin costs its own check, not the scan
            logger.exception("Script check %s failed against %s", check.check_id, host)
            return None
        return self._finding(check, service) if fired else None

    def _finding(self, check: Check, service: Service) -> dict:
        """Build the finding dict for a check that fired against a service."""
        finding_template = check.finding
        return {
            "title":        finding_template.get("title", check.id),
            "category":     check.category,
            "port":         service.port,
            "service":      service.name or check.service,
            "protocol":     service.protocol,
            "cve_ids":      finding_template.get("cve_ids"),
            "source":       "lybra",
            "check_id":     check.check_id,
            "feed_version": check.feed_version or CHECKS_FEED_VERSION,
            "qod":          finding_template.get("qod", QOD_CONFIRMED),
            "confirmed":    finding_template.get("confirmed", True),
            "state":        "open",
        }


# =========================================================================
# HTTP PROBE + RATE LIMITER (the network edge)
# =========================================================================

class HostRateLimiter:
    """Enforces a minimum interval between requests to the same host.

    Thread-safe, so it can be shared across concurrent probes without letting any
    single host be hit faster than the configured rate — and **without holding
    anyone else up while it waits**. The waiting happens outside the lock: the
    turn is reserved under it (a few microseconds of bookkeeping), and the
    sleeping is done after releasing it.

    That distinction is the whole point of this class's shape. With the sleep
    inside the lock, a probe waiting its turn for host A also blocked every
    probe heading for host B — a limiter meant to protect *one* host at a time
    was throttling all of them at once, and the wait bought nobody any
    protection.

    Reserving the turn before sleeping (writing the *future* timestamp, not the
    current one) is what makes concurrent callers for the same host stagger
    instead of all waking up at the same instant and firing together.

    Args:
        min_interval: The minimum time, in seconds, between two requests to the
            same host.
        clock: An injectable monotonic clock, so a test can assert the schedule
            instead of waiting for it.
        sleeper: An injectable sleep, same reason.
    """

    def __init__(
        self,
        min_interval: float = 0.2,
        clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        self._min = min_interval
        self._last: Dict[str, float] = {}
        self._lock = threading.Lock()
        self._clock = clock
        self._sleeper = sleeper

    def acquire(self, host: str) -> None:
        """Block, if necessary, until it is safe to hit ``host`` again.

        Args:
            host: The host about to be requested.
        """
        with self._lock:
            now = self._clock()
            # El turno se reserva escribiendo la marca *futura*, no la actual:
            # así dos hilos que piden el mismo host se escalonan en vez de
            # despertarse a la vez y disparar juntos.
            #
            # Un host que no se ha visto nunca se distingue con None y no con
            # un 0.0 por defecto: contra un reloj real da igual (0.0 queda
            # infinitamente atrás), pero contra uno inyectado que empiece en
            # cero, ese 0.0 haría esperar a la primera petición de cada host.
            last_turn = self._last.get(host)
            earliest = now if last_turn is None else max(now, last_turn + self._min)
            self._last[host] = earliest
        wait = earliest - now
        if wait > 0:
            self._sleeper(wait)


def negotiates_tls(host: str, port: int, timeout: float = 5.0, connect: Optional[Callable] = None) -> bool:
    """Return whether ``host:port`` completes a TLS handshake.

    The question "is this HTTPS?" used to be answered by looking the port up in
    a set of two. This asks the service instead, which is the only way to be
    right about a panel someone chose to publish on 9443, or about a plain HTTP
    server sitting on 8443 — the inverse mistake, and just as real.

    Deliberately implemented here with ``ssl`` rather than by reusing
    ``fingerprinting.tls.TlsProbe``, which does exactly this handshake plus
    certificate parsing: this module must not import the fingerprinting
    package, because the dissectors in it import their applicability predicates
    from here and the two imports would close a cycle (the same reason
    ``_TLS_RULES`` is duck-typed). What is shared is the reasoning, not the
    code — and what this needs is a yes/no, not a certificate.

    Args:
        host: The target host.
        port: The target port.
        timeout: The connection timeout, in seconds.
        connect: An injectable ``(address, timeout) -> socket`` callable, the
            same pattern the probes use.

    Returns:
        ``True`` if the handshake completed, ``False`` on any failure —
        including a plaintext server, which answers a TLS ``ClientHello`` with
        something that is not a ``ServerHello`` and fails the handshake.
    """
    connect = connect or socket.create_connection
    context = ssl._create_unverified_context()
    try:
        with connect((host, port), timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host):
                return True
    except Exception as err:  # noqa: BLE001 - cualquier fallo significa "no es TLS"
        logger.debug("Scheme detection: %s:%s does not speak TLS (%s)", host, port, err)
        return False


class HttpProbe:
    """Performs the runtime's actual HTTP requests — safe, read-only GETs.

    A 4xx or 5xx response is returned as an ordinary :class:`Response`, not an
    error: a 404 for ``/.git/config`` is a meaningful "not exposed" result that a
    matcher needs to see. Only an actual transport failure (connection refused,
    timeout) yields ``None``, which tells the runtime to abandon the check rather
    than treat it as a hit.

    Args:
        timeout: The per-request timeout, in seconds.
        max_bytes: The maximum number of response body bytes to read.
        detect_scheme: An injectable ``(host, port) -> bool`` telling whether
            the service speaks TLS. Defaults to :func:`negotiates_tls`; a test
            passes a stub instead of opening a socket.
        user_agent: The ``User-Agent`` header the probe presents (L39).
    """

    def __init__(
        self,
        timeout: int = 8,
        max_bytes: int = 131072,
        detect_scheme: Optional[Callable[[str, Optional[int]], bool]] = None,
        user_agent: str = "Lybra/1.0",
    ) -> None:
        self._timeout = timeout
        self._max_bytes = max_bytes
        self._user_agent = user_agent
        self._detect_scheme = detect_scheme or (lambda host, port: negotiates_tls(host, port, timeout))
        # El esquema se observa una vez por servicio y se recuerda: la pregunta
        # es sobre el servicio, no sobre la petición, y no cambia entre una y
        # otra dentro del mismo escaneo.
        self._schemes: Dict[tuple, str] = {}
        # E7: este probe se queda deliberadamente en ``urllib`` mientras el
        # resto del tráfico HTTP ordinario del proyecto (aegis/pills.py,
        # lybra/kb.py) usa ``requests``. Una sonda de seguridad necesita
        # control fino sobre el contexto TLS de *cada* salto, y ``requests``
        # esconde justo eso: su ``verify=False`` sí cubre las redirecciones,
        # pero no deja sustituir el ``SSLContext`` por handler, que es lo que
        # el caso de abajo necesita. No es inconsistencia, es un requisito
        # distinto — y por eso vive aquí y no en el camino común.
        #
        # We are scanning arbitrary hosts whose certificates we do not control,
        # so every HTTPS leg — including one reached via a same-host redirect,
        # e.g. a plain "http://" request answered with "Location: https://..." —
        # must skip verification. A plain per-call context only covers the
        # *initial* request; urllib's redirect handler opens the follow-up
        # itself and falls back to the verifying default context, so a host
        # that redirects HTTP to a self-signed HTTPS login page looked like a
        # transport failure instead of a response to fingerprint.
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ssl._create_unverified_context())
        )

    def fetch(self, host: str, port: Optional[int], method: str, path: str) -> Optional[Response]:
        """Make a request and return it as a :class:`Response`.

        Args:
            host: The target host.
            port: The target port (decides http vs https).
            method: The HTTP method.
            path: The request path.

        Returns:
            The response, or ``None`` on a transport failure.
        """
        result = self._request(host, port, method, path)
        if result is None:
            return None
        status, body, headers = result
        return self._to_response(status, body, headers)

    def fetch_bytes(self, host: str, port: Optional[int], path: str) -> Optional[bytes]:
        """Fetch raw bytes for binary content such as a favicon.

        Text-decoding a binary payload (as :meth:`fetch` does for the response
        body) would corrupt it, so this returns the untouched bytes instead.

        Args:
            host: The target host.
            port: The target port.
            path: The request path.

        Returns:
            The raw response bytes on a 200, otherwise ``None`` — the caller only
            cares whether the file is actually there.
        """
        result = self._request(host, port, "GET", path)
        if result is None:
            return None
        status, body, _headers = result
        return body if status == 200 else None

    def _request(self, host: str, port: Optional[int], method: str, path: str) -> Optional[tuple]:
        """Perform the raw HTTP request, returning ``(status, body, headers)``.

        A 4xx/5xx is returned normally; only a transport failure returns ``None``.
        HTTPS uses an unverified TLS context, since we are scanning arbitrary
        hosts whose certificates we do not control.
        """
        scheme = self._scheme_for(host, port)
        netloc = f"{host}:{port}" if port else host
        url = f"{scheme}://{netloc}{path}"
        try:
            request = urllib.request.Request(url, method=method, headers={"User-Agent": self._user_agent})
            with self._opener.open(request, timeout=self._timeout) as response:
                return response.status, response.read(self._max_bytes), dict(response.headers)
        except urllib.error.HTTPError as err:
            body = err.read(self._max_bytes) if hasattr(err, "read") else b""
            return err.code, body, dict(err.headers or {})
        except Exception as err:  # noqa: BLE001 - transport failure: abandon this check
            logger.debug("HTTP probe failed for %s: %s", url, err)
            return None

    def _scheme_for(self, host: str, port: Optional[int]) -> str:
        """Return ``"https"`` or ``"http"`` for a service, observing it once.

        A service with no port at all (an inventory entry, say) is not
        something to shake hands with, so it keeps the plain default rather
        than paying for a probe that has nowhere to connect.
        """
        if port is None:
            return "http"
        key = (host, port)
        if key not in self._schemes:
            self._schemes[key] = "https" if self._detect_scheme(host, port) else "http"
        return self._schemes[key]

    @staticmethod
    def _to_response(status: int, body: bytes, headers) -> Response:
        """Assemble a :class:`Response` from raw request parts, lowercasing headers."""
        text = body.decode("utf-8", "replace") if isinstance(body, bytes) else str(body)
        header_map = {str(k).lower(): str(v) for k, v in dict(headers).items()}
        return Response(status=status, body=text, headers=header_map)


# =========================================================================
# NETWORK PROBE (the network edge for ``type: "network"`` checks — Fase N)
# =========================================================================

# How a reply ends, declared per request by the feed (``read:``). The transport
# cannot infer this: "one line" is a property of some protocols and of no
# others, and guessing it wrong does not raise — it just reads the wrong bytes
# and the check never fires.
#
#   line       One line, terminated by LF. The original behaviour and the
#              default: right for a protocol whose every reply is one line.
#   block      A multi-line status block, the shape FTP/SMTP/POP3 use: lines
#              whose status code is followed by "-" are continuations, and the
#              first line *without* that dash closes the block. Degrades to a
#              single line when the server does not use continuations, which is
#              what makes it safe as the banner reader for any protocol.
#   resp-bulk  Redis' RESP bulk string: a "$<n>" header line followed by
#              exactly n bytes of payload. Any other first line (an error like
#              "-NOAUTH ...", a simple "+OK") is returned as-is, because that
#              *is* the whole reply.
NETWORK_READ_MODES = ("line", "block", "resp-bulk")

# A status line whose code is followed by "-" instead of a space: the reply
# continues on the next line (RFC 959 §4.2 for FTP, RFC 5321 §4.2 for SMTP).
_STATUS_CONTINUATION_RE = re.compile(rb"^\d{3}-")


class NetworkSession:
    """One TCP connection, shared across every request of a single check run.

    Deliberately protocol-agnostic: it knows nothing about FTP, Redis or any
    other protocol a check targets. What it does know is that *where a reply
    ends* is a protocol decision, so the feed declares it per request (see
    :data:`NETWORK_READ_MODES`) and this class only implements the mechanics.
    The reply comes back decoded as text, so the existing word/regex matchers
    evaluate it exactly like an HTTP response (``status=0`` and empty
    ``headers``, since neither concept exists here).

    Reads are buffered: whatever a read mode does not consume stays for the
    next one, which is what lets a bulk-string read hand back the leftovers
    instead of losing them. It also stops the previous byte-at-a-time
    ``recv(1)`` loop, one system call per byte received.

    Args:
        sock: The connected socket this session wraps.
        max_bytes: The maximum number of bytes to read for a single reply. A
            hostile or broken server must not be able to make us read forever.
    """

    _CHUNK = 4096

    def __init__(self, sock, max_bytes: int = 65536) -> None:
        self._sock = sock
        self._max_bytes = max_bytes
        self._buffer = b""

    def exchange(self, send: Optional[str], read: str = "line") -> Optional[Response]:
        """Write ``send`` (if any), then read one reply under the given mode.

        Args:
            send: The raw payload to write first, or ``None`` to only read —
                the shape a banner-only read needs, since some protocols (FTP)
                volunteer a greeting unprompted right after connecting.
            read: How the reply ends — one of :data:`NETWORK_READ_MODES`.

        Returns:
            A :class:`Response` wrapping the decoded reply (``status=0``,
            empty ``headers``), or ``None`` on a transport failure or an empty
            reply.
        """
        try:
            if send is not None:
                self._sock.sendall(send.encode("utf-8"))
            if read == "block":
                data = self._read_block()
            elif read == "resp-bulk":
                data = self._read_resp_bulk()
            else:
                data = self._read_line()
        except OSError as err:
            logger.debug("Network check exchange failed: %s", err)
            return None
        text = data.decode("utf-8", "ignore").strip()
        if not text:
            return None
        return Response(status=0, body=text, headers={})

    def close(self) -> None:
        """Close the underlying socket, ignoring any error."""
        try:
            self._sock.close()
        except OSError:
            pass

    def _fill(self) -> bool:
        """Pull one more chunk off the socket into the buffer.

        Returns:
            ``False`` when the peer closed the connection (nothing more will
            ever arrive), ``True`` otherwise.
        """
        chunk = self._sock.recv(self._CHUNK)
        if not chunk:
            return False
        self._buffer += chunk
        return True

    def _read_line(self) -> bytes:
        """Read up to and including the next LF, or whatever arrived before EOF."""
        while b"\n" not in self._buffer and len(self._buffer) < self._max_bytes:
            if not self._fill():
                break
        line, separator, rest = self._buffer.partition(b"\n")
        self._buffer = rest
        return line + separator

    def _read_block(self) -> bytes:
        """Read a status block: continuation lines plus the line that closes it."""
        block = b""
        while len(block) < self._max_bytes:
            line = self._read_line()
            if not line:
                break
            block += line
            if not _STATUS_CONTINUATION_RE.match(line):
                break
        return block

    def _read_resp_bulk(self) -> bytes:
        """Read a RESP bulk string, or hand back a non-bulk reply untouched.

        A bulk string announces its own length (``$3116``), so unlike every
        other reply here its end is a byte count and not a delimiter. A reply
        that is not a bulk string — an error, a simple string — is complete as
        the single line it already is.
        """
        header = self._read_line()
        if not header.startswith(b"$"):
            return header
        try:
            length = int(header[1:].strip())
        except ValueError:
            return header
        if length < 0:                      # "$-1" is RESP's null bulk string
            return header
        length = min(length, self._max_bytes)
        while len(self._buffer) < length:
            if not self._fill():
                break
        payload, self._buffer = self._buffer[:length], self._buffer[length:]
        # RESP cierra el bulk con un CRLF que no cuenta en la longitud
        # anunciada. Se descarta si ya está en el buffer, para que no se cuele
        # como una línea vacía en la lectura siguiente. Deliberadamente no se
        # pide más al socket para conseguirlo: el servidor manda ese CRLF
        # pegado al contenido, y un recv extra sólo podría bloquear hasta el
        # timeout — perdiendo una respuesta que ya teníamos entera.
        if self._buffer.startswith(b"\r\n"):
            self._buffer = self._buffer[2:]
        elif self._buffer.startswith(b"\n"):
            self._buffer = self._buffer[1:]
        return payload


class NetworkProbe:
    """Opens the raw TCP connection a :class:`NetworkSession` wraps.

    The connection function is injectable — it defaults to
    ``socket.create_connection`` but a test can pass a fake — the same pattern
    :class:`~.fingerprinting.ssh.SshProbe` and :class:`~.fingerprinting.tls.TlsProbe`
    already use.

    Args:
        timeout: The connection timeout, in seconds.
        connect: An injectable ``(address, timeout) -> socket`` callable.
    """

    def __init__(self, timeout: float = 5.0, connect: Optional[Callable] = None) -> None:
        self._timeout = timeout
        self._connect = connect or socket.create_connection

    def open(self, host: str, port: Optional[int]) -> Optional[NetworkSession]:
        """Connect to ``host:port`` and return a session, or ``None`` on failure.

        Args:
            host: The target host.
            port: The target port.

        Returns:
            A :class:`NetworkSession`, or ``None`` if the connection failed.
        """
        try:
            sock = self._connect((host, port), self._timeout)
        except OSError as err:
            logger.debug("Network probe connect failed for %s:%s: %s", host, port, err)
            return None
        return NetworkSession(sock)
