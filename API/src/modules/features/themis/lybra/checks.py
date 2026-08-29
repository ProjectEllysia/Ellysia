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

logger = logging.getLogger(__name__)

# The version stamped onto every finding this runtime produces, for
# traceability. Bumped whenever the feed gains a new check family or a new
# protocol under an existing one (checks-2: "ftp-anonymous-login", the first
# ``type: "network"`` check; checks-3: "redis-unauthenticated-access", the
# second ``network`` protocol; checks-4: "smb-signing-not-required", the first
# ``type: "script"`` check; checks-5: "snmp-default-community", the first
# check over UDP) — never for a fix to an existing check, which bumps that
# check's own ``version`` instead (see ``Check.check_id``).
CHECKS_FEED_VERSION = "lybra-checks-5"
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
# Service names and ports that indicate an HTTP-speaking service worth probing.
_HTTP_SERVICE_NAMES = {"http", "https", "http-proxy", "https-alt", "http-alt"}
_HTTP_PORTS = {80, 443, 8080, 8443, 8000, 8888, 8008}
# Ports we should reach over TLS.
_TLS_PORTS = {443, 8443}
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
    """
    method: str = "GET"
    path: str = "/"
    matchers: tuple = ()
    condition: str = "and"
    send: Optional[str] = None

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
    return Check(
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
    )


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
    """Return whether a service should be probed by TLS hygiene checks.

    Args:
        service: The service to test.

    Returns:
        ``True`` if the service's port is one we reach over TLS.
    """
    return service.port in _TLS_PORTS


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


# Maps a ``type: "network"`` check's declared ``service`` (the feed's plain
# string, e.g. ``"ftp"``) to the predicate that decides whether a discovered
# Service is that protocol. One entry per protocol Fase N adds — the runtime
# itself (``CheckRuntime._applies_network``) stays protocol-agnostic.
_NETWORK_SERVICE_MATCHERS: Dict[str, Callable[[Service], bool]] = {
    "ftp": is_ftp_service,
    "redis": is_redis_service,
}


# Protocol versions considered deprecated/weak for a service exposed today.
_WEAK_TLS_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}

# TLS hygiene rules a ``type: "tls"`` check can reference via ``tlsRule`` in the
# feed. Each takes the ``TlsInfo`` a probe returned (duck-typed — this module
# never imports the fingerprint module, to avoid a checks<->fingerprint
# import cycle) and decides whether the check fires.
_TLS_RULES: Dict[str, Callable] = {
    "self_signed": lambda info: info.self_signed,
    "expired": lambda info: info.expired,
    "expiring_soon": lambda info: not info.expired and info.days_until_expiry is not None and info.days_until_expiry <= 30,
    "deprecated_protocol": lambda info: info.protocol in _WEAK_TLS_PROTOCOLS,
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
    """
    target: str
    service: Service
    rate_limiter: Optional["HostRateLimiter"] = None
    mode: str = "safe"

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
    ) -> None:
        self._checks = list(checks)
        self._fetch = fetch
        self._mode = mode
        self._rl = rate_limiter
        self._tls_fetch = tls_fetch
        self._network_open = network_open
        self._script_plugins = dict(script_plugins or {})
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

        Args:
            host: The target host.
            services: The host's discovered services (non-applicable ones are
                skipped per check family).

        Returns:
            A finding dict for each check that fired.
        """
        findings: List[dict] = []
        for service in services:
            for family in self._families:
                if not family.applies_to_service(service):
                    continue
                for check in self._checks:
                    if not family.check_matches(check, service):
                        continue
                    finding = family.run_check(check, host, service)
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
        """
        if check.type != "network":
            return False
        matches = _NETWORK_SERVICE_MATCHERS.get(check.service)
        if matches is None or not matches(service):
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
            if self._rl is not None:
                self._rl.acquire(host)
            response = self._fetch(host, service.port, request.method, request.path)
            if response is None or not request.evaluate(response):
                return None
        return self._finding(check, service)

    def _run_tls_check(self, check: Check, host: str, service: Service) -> Optional[dict]:
        """Run one TLS hygiene check against one service's handshake.

        A transport failure (unreachable, handshake error) abandons the check —
        no evidence means no finding, the same rule ``_run_check`` follows.
        """
        if self._rl is not None:
            self._rl.acquire(host)
        info = self._tls_fetch(host, service.port)
        if info is None or not _TLS_RULES[check.tls_rule](info):
            return None
        return self._finding(check, service)

    def _run_network_check(self, check: Check, host: str, service: Service) -> Optional[dict]:
        """Run one network check against one service, returning a finding if it fired.

        Opens a single session and exchanges every request's ``send`` payload
        over it in order (combined with AND, same as ``_run_check``) — the
        session, not a fresh connection per request, is what lets a login
        sequence like FTP's ``USER``/``PASS`` see its own prior state.
        """
        if self._rl is not None:
            self._rl.acquire(host)
        session = self._network_open(host, service.port)
        if session is None:
            return None
        try:
            for request in check.requests:
                response = session.exchange(request.send)
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
    single host be hit faster than the configured rate.

    Args:
        min_interval: The minimum time, in seconds, between two requests to the
            same host.
    """

    def __init__(self, min_interval: float = 0.2) -> None:
        self._min = min_interval
        self._last: Dict[str, float] = {}
        self._lock = threading.Lock()

    def acquire(self, host: str) -> None:
        """Block, if necessary, until it is safe to hit ``host`` again.

        Args:
            host: The host about to be requested.
        """
        with self._lock:
            wait = self._min - (time.monotonic() - self._last.get(host, 0.0))
            if wait > 0:
                time.sleep(wait)
            self._last[host] = time.monotonic()


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
    """

    def __init__(self, timeout: int = 8, max_bytes: int = 131072) -> None:
        self._timeout = timeout
        self._max_bytes = max_bytes
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
        scheme = "https" if port in _TLS_PORTS else "http"
        netloc = f"{host}:{port}" if port else host
        url = f"{scheme}://{netloc}{path}"
        try:
            request = urllib.request.Request(url, method=method, headers={"User-Agent": "Lybra/1.0"})
            with self._opener.open(request, timeout=self._timeout) as response:
                return response.status, response.read(self._max_bytes), dict(response.headers)
        except urllib.error.HTTPError as err:
            body = err.read(self._max_bytes) if hasattr(err, "read") else b""
            return err.code, body, dict(err.headers or {})
        except Exception as err:  # noqa: BLE001 - transport failure: abandon this check
            logger.debug("HTTP probe failed for %s: %s", url, err)
            return None

    @staticmethod
    def _to_response(status: int, body: bytes, headers) -> Response:
        """Assemble a :class:`Response` from raw request parts, lowercasing headers."""
        text = body.decode("utf-8", "replace") if isinstance(body, bytes) else str(body)
        header_map = {str(k).lower(): str(v) for k, v in dict(headers).items()}
        return Response(status=status, body=text, headers=header_map)


# =========================================================================
# NETWORK PROBE (the network edge for ``type: "network"`` checks — Fase N)
# =========================================================================

class NetworkSession:
    """One TCP connection, shared across every request of a single check run.

    Deliberately protocol-agnostic: it knows nothing about FTP, SMB or any
    other protocol a future check targets — it only writes a payload (if any)
    and reads back one line, decoded as text so the existing word/regex
    matchers can evaluate it exactly like an HTTP response (``status=0`` and
    empty ``headers``, since neither concept exists here).

    Args:
        sock: The connected socket this session wraps.
        max_bytes: The maximum number of bytes to read per line.
    """

    def __init__(self, sock, max_bytes: int = 4096) -> None:
        self._sock = sock
        self._max_bytes = max_bytes

    def exchange(self, send: Optional[str]) -> Optional[Response]:
        """Write ``send`` (if any), then read and return one line of reply.

        Args:
            send: The raw payload to write first, or ``None`` to only read —
                the shape a banner-only check needs, since some protocols
                (FTP) volunteer a line unprompted right after connecting.

        Returns:
            A :class:`Response` wrapping the decoded line (``status=0``,
            empty ``headers``), or ``None`` on any transport failure.
        """
        try:
            if send is not None:
                self._sock.sendall(send.encode("utf-8"))
            data = b""
            while not data.endswith(b"\n") and len(data) < self._max_bytes:
                chunk = self._sock.recv(1)
                if not chunk:
                    break
                data += chunk
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
