"""Lybra's active-detection runtime — the engine's identity layer.

This is where Lybra stops inferring vulnerabilities from a version number and
starts actively *confirming* them. It runs declarative checks against a service
and, when one fires, emits a finding marked confirmed with a high Quality of
Detection — a real, observed problem rather than a suspicion.

A check describes an HTTP request and the conditions ("matchers") that decide
whether it fired. The checks are stored as JSON in a bundled feed file. The
schema deliberately mirrors the shape of Nuclei's YAML templates, but is
serialized as JSON so the feed needs no extra dependency; ingesting Nuclei's
own YAML templates is left for a later phase.

The scope of this layer covers the three highest-value, lowest-cost families the
roadmap names first: exposed paths (like ``/.git/config``), missing security
headers, and TLS/certificate hygiene (self-signed, expired, deprecated
protocol — a ``type: "tls"`` check, evaluated against a handshake instead of an
HTTP request/response). Request chaining, payloads/fuzzing and first-party
script plugins are deliberate follow-ups.

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
from typing import Callable, Dict, Iterable, List, Optional

from .engine import Service

logger = logging.getLogger(__name__)

# The version stamped onto every finding this runtime produces, for
# traceability. Bumped whenever the feed gains a new check family (Fase N's
# "ftp-anonymous-login", the first ``type: "network"`` check, is what earned
# checks-2) — never for a fix to an existing check, which bumps that check's
# own ``version`` instead (see ``Check.check_id``).
CHECKS_FEED_VERSION = "lybra-checks-2"
# Quality of Detection for a finding a check actively confirmed, as opposed to
# one merely inferred from a version.
QOD_CONFIRMED = 99

# The JSON feed shipped in the package's feeds/ directory, alongside every
# other Lybra feed (tech_signatures.json for the HTTP dissector, ...).
_BUNDLED_FEED = Path(__file__).parent / "feeds" / "checks_feed.json"
# Service names and ports that indicate an HTTP-speaking service worth probing.
_HTTP_SERVICE_NAMES = {"http", "https", "http-proxy", "https-alt", "http-alt"}
_HTTP_PORTS = {80, 443, 8080, 8443, 8000, 8888, 8008}
# Ports we should reach over TLS.
_TLS_PORTS = {443, 8443}
# Service names and ports for FTP — Fase N's first ``type: "network"`` family.
_FTP_SERVICE_NAMES = {"ftp"}
_FTP_PORTS = {21}


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

    def matches(self, resp: Response) -> bool:
        """Return whether this matcher is satisfied by a response.

        Args:
            resp: The response to test.

        Returns:
            The test result, inverted if ``negative`` is set.
        """
        result = self._raw_match(resp)
        return (not result) if self.negative else result

    def _raw_match(self, resp: Response) -> bool:
        """Run the matcher's test, before any ``negative`` inversion."""
        if self.type == "status":
            return resp.status in {int(v) for v in self.values}
        text = self._part_text(resp)
        if self.type == "word":
            low = text.lower()
            return any(str(w).lower() in low for w in self.values)
        if self.type == "regex":
            return any(re.search(str(p), text) for p in self.values)
        return False

    def _part_text(self, resp: Response) -> str:
        """Return the response text this matcher's ``part`` refers to."""
        if self.part == "header":
            return "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        if self.part == "status":
            return str(resp.status)
        return resp.body


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

    def evaluate(self, resp: Response) -> bool:
        """Return whether this request's matchers are satisfied by a response.

        Args:
            resp: The response to the request.

        Returns:
            ``True`` if the matchers pass under the request's condition. A request
            with no matchers never fires.
        """
        if not self.matchers:
            return False
        results = [m.matches(resp) for m in self.matchers]
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

    @property
    def check_id(self) -> str:
        """The fully-qualified, versioned check id, e.g. ``lybra:git-config@1``."""
        return f"lybra:{self.id}@{self.version}"


# =========================================================================
# FEED LOADING
# =========================================================================

def load_checks(path: Optional[str] = None) -> List[Check]:
    """Load and parse a check feed.

    Args:
        path: Path to a JSON feed file. Defaults to the feed bundled with this
            module.

    Returns:
        The parsed checks.
    """
    feed_path = Path(path) if path else _BUNDLED_FEED
    data = json.loads(feed_path.read_text(encoding="utf-8"))
    return [_parse_check(c) for c in data.get("checks", [])]


def _parse_check(c: dict) -> Check:
    """Build a :class:`Check` from its raw JSON representation.

    Applies sensible defaults for optional fields and accepts a matcher's target
    values under any of ``words`` / ``regex`` / ``value``.
    """
    requests = tuple(
        Request(
            method=r.get("method", "GET"),
            path=r.get("path", "/"),
            condition=r.get("matchers-condition", "and"),
            send=r.get("send"),
            matchers=tuple(
                Matcher(
                    type=m["type"],
                    part=m.get("part", "body"),
                    values=tuple(m.get("words") or m.get("regex") or m.get("value") or []),
                    negative=m.get("negative", False),
                )
                for m in r.get("matchers", [])
            ),
        )
        for r in c.get("requests", [])
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


# Maps a ``type: "network"`` check's declared ``service`` (the feed's plain
# string, e.g. ``"ftp"``) to the predicate that decides whether a discovered
# Service is that protocol. One entry per protocol Fase N adds — the runtime
# itself (``CheckRuntime._applies_network``) stays protocol-agnostic.
_NETWORK_SERVICE_MATCHERS: Dict[str, Callable[[Service], bool]] = {
    "ftp": is_ftp_service,
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
    """

    def __init__(
        self,
        checks: Iterable[Check],
        fetch: Callable[[str, Optional[int], str, str], Optional[Response]],
        mode: str = "safe",
        rate_limiter: Optional["HostRateLimiter"] = None,
        tls_fetch: Optional[Callable[[str, int], object]] = None,
        network_open: Optional[Callable[[str, int], Optional["NetworkSession"]]] = None,
    ) -> None:
        self._checks = list(checks)
        self._fetch = fetch
        self._mode = mode
        self._rl = rate_limiter
        self._tls_fetch = tls_fetch
        self._network_open = network_open

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
            if is_http_service(service):
                for check in self._checks:
                    if not self._applies(check):
                        continue
                    finding = self._run_check(check, host, service)
                    if finding is not None:
                        findings.append(finding)
            if self._tls_fetch is not None and is_tls_service(service):
                for check in self._checks:
                    if not self._applies_tls(check):
                        continue
                    finding = self._run_tls_check(check, host, service)
                    if finding is not None:
                        findings.append(finding)
            if self._network_open is not None:
                for check in self._checks:
                    if not self._applies_network(check, service):
                        continue
                    finding = self._run_network_check(check, host, service)
                    if finding is not None:
                        findings.append(finding)
        return findings

    def _applies(self, check: Check) -> bool:
        """Return whether a check should run against a service in the current mode."""
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
            resp = self._fetch(host, service.port, request.method, request.path)
            if resp is None or not request.evaluate(resp):
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
                resp = session.exchange(request.send)
                if resp is None or not request.evaluate(resp):
                    return None
            return self._finding(check, service)
        finally:
            session.close()

    def _finding(self, check: Check, service: Service) -> dict:
        """Build the finding dict for a check that fired against a service."""
        f = check.finding
        return {
            "title":        f.get("title", check.id),
            "category":     check.category,
            "port":         service.port,
            "service":      service.name or check.service,
            "cve_ids":      f.get("cve_ids"),
            "source":       "lybra",
            "check_id":     check.check_id,
            "feed_version": CHECKS_FEED_VERSION,
            "qod":          f.get("qod", QOD_CONFIRMED),
            "confirmed":    f.get("confirmed", True),
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
            req = urllib.request.Request(url, method=method, headers={"User-Agent": "Lybra/1.0"})
            with self._opener.open(req, timeout=self._timeout) as resp:
                return resp.status, resp.read(self._max_bytes), dict(resp.headers)
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
