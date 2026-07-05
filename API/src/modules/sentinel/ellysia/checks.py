"""Ellysia's own active-detection runtime (Fase R, the L2 identity layer).

A small, versioned engine that runs declarative checks against a service and
emits actively-**confirmed** findings (``qod=99``, ``confirmed=true``) — the step
beyond version inference. The check schema mirrors the roadmap's YAML shape but
is serialized as JSON here so the feed needs no extra dependency; Nuclei-template
ingestion (which does want YAML) is a later phase.

Scope of this phase: ``http`` checks (request + matchers) covering the two
highest-value, lowest-cost families — exposed paths and security headers. TLS
checks, extractors/DSL/payloads, script plugins and the version→confirmador
chaining are deliberate follow-ups.

The runtime is pure given an injected ``fetch`` callable, so it is unit-tested
with crafted responses and never needs the network in tests. The manager wires
the real :class:`HttpProbe`, behind an opt-in config flag (active checks touch
the target and await the authorized-targets register from the roadmap §6).
"""

from __future__ import annotations

import json
import logging
import re
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

CHECKS_FEED_VERSION = "ellysia-checks-1"
QOD_CONFIRMED = 99  # actively confirmed by a check, not inferred from a version

_BUNDLED_FEED = Path(__file__).parent / "checks_feed.json"
_HTTP_SERVICE_NAMES = {"http", "https", "http-proxy", "https-alt", "http-alt"}
_HTTP_PORTS = {80, 443, 8080, 8443, 8000, 8888, 8008}
_TLS_PORTS = {443, 8443}


# =========================================================================
# HTTP RESPONSE + MATCHERS
# =========================================================================

@dataclass(frozen=True)
class Response:
    """A minimal HTTP response the matchers evaluate (header keys lowercased)."""
    status: int
    body: str
    headers: Dict[str, str]


@dataclass(frozen=True)
class Matcher:
    """One condition on a response: a status code, a word, or a regex."""
    type: str                       # status | word | regex
    part: str = "body"              # body | header | status
    values: tuple = ()
    negative: bool = False

    def matches(self, resp: Response) -> bool:
        result = self._raw_match(resp)
        return (not result) if self.negative else result

    def _raw_match(self, resp: Response) -> bool:
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
        if self.part == "header":
            return "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        if self.part == "status":
            return str(resp.status)
        return resp.body


@dataclass(frozen=True)
class Request:
    """A single request and the matchers that decide whether it fired."""
    method: str = "GET"
    path: str = "/"
    matchers: tuple = ()
    condition: str = "and"          # and | or

    def evaluate(self, resp: Response) -> bool:
        if not self.matchers:
            return False
        results = [m.matches(resp) for m in self.matchers]
        return all(results) if self.condition == "and" else any(results)


@dataclass(frozen=True)
class Check:
    """A declarative detection check (currently ``type: http`` only)."""
    id: str
    version: int
    type: str
    category: str
    severity: str
    service: str
    mode: str                       # safe | aggressive
    requests: tuple
    finding: dict

    @property
    def check_id(self) -> str:
        return f"ellysia:{self.id}@{self.version}"


# =========================================================================
# FEED LOADING
# =========================================================================

def load_checks(path: Optional[str] = None) -> List[Check]:
    """Load the check feed (the bundled JSON by default)."""
    feed_path = Path(path) if path else _BUNDLED_FEED
    data = json.loads(feed_path.read_text(encoding="utf-8"))
    return [_parse_check(c) for c in data.get("checks", [])]


def _parse_check(c: dict) -> Check:
    requests = tuple(
        Request(
            method=r.get("method", "GET"),
            path=r.get("path", "/"),
            condition=r.get("matchers-condition", "and"),
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
    )


# =========================================================================
# RUNTIME
# =========================================================================

def is_http_service(service: Service) -> bool:
    """Whether a service should be probed by HTTP checks."""
    return (service.name or "").lower() in _HTTP_SERVICE_NAMES or service.port in _HTTP_PORTS


class CheckRuntime:
    """Runs a set of checks against a host's HTTP services and emits findings.

    Args:
        checks: The loaded checks.
        fetch: ``(host, port, method, path) -> Response | None``. None means the
            request failed/timed out — the check is abandoned, never a false hit.
        mode: "safe" runs only ``mode: safe`` checks; "aggressive" runs both.
        rate_limiter: Optional per-host limiter applied before each request.
    """

    def __init__(
        self,
        checks: Iterable[Check],
        fetch: Callable[[str, Optional[int], str, str], Optional[Response]],
        mode: str = "safe",
        rate_limiter: Optional["HostRateLimiter"] = None,
    ) -> None:
        self._checks = list(checks)
        self._fetch = fetch
        self._mode = mode
        self._rl = rate_limiter

    def run(self, host: str, services: Iterable[Service]) -> List[dict]:
        findings: List[dict] = []
        for service in services:
            if not is_http_service(service):
                continue
            for check in self._checks:
                if not self._applies(check, service):
                    continue
                finding = self._run_check(check, host, service)
                if finding is not None:
                    findings.append(finding)
        return findings

    def _applies(self, check: Check, service: Service) -> bool:
        if check.type != "http":
            return False
        if self._mode == "safe" and check.mode == "aggressive":
            return False
        return True

    def _run_check(self, check: Check, host: str, service: Service) -> Optional[dict]:
        # Every request in a check must fire (AND across requests).
        for request in check.requests:
            if self._rl is not None:
                self._rl.acquire(host)
            resp = self._fetch(host, service.port, request.method, request.path)
            if resp is None or not request.evaluate(resp):
                return None
        return self._finding(check, service)

    def _finding(self, check: Check, service: Service) -> dict:
        f = check.finding
        return {
            "title":        f.get("title", check.id),
            "category":     check.category,
            "port":         service.port,
            "service":      service.name or "http",
            "cve_ids":      f.get("cve_ids"),
            "source":       "ellysia",
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
    """Enforces a minimum interval between requests to the same host."""

    def __init__(self, min_interval: float = 0.2) -> None:
        self._min = min_interval
        self._last: Dict[str, float] = {}
        self._lock = threading.Lock()

    def acquire(self, host: str) -> None:
        with self._lock:
            wait = self._min - (time.monotonic() - self._last.get(host, 0.0))
            if wait > 0:
                time.sleep(wait)
            self._last[host] = time.monotonic()


class HttpProbe:
    """Performs the actual (safe, read-only) HTTP requests for the runtime.

    A 4xx/5xx is returned as a normal :class:`Response` (a 404 to ``/.git/config``
    is a meaningful "not exposed" result, not an error). Any transport failure
    returns None so the check is simply abandoned.
    """

    def __init__(self, timeout: int = 8, max_bytes: int = 131072) -> None:
        self._timeout = timeout
        self._max_bytes = max_bytes

    def fetch(self, host: str, port: Optional[int], method: str, path: str) -> Optional[Response]:
        scheme = "https" if port in _TLS_PORTS else "http"
        netloc = f"{host}:{port}" if port else host
        url = f"{scheme}://{netloc}{path}"
        context = ssl._create_unverified_context() if scheme == "https" else None
        try:
            req = urllib.request.Request(url, method=method, headers={"User-Agent": "Ellysia/1.0"})
            with urllib.request.urlopen(req, timeout=self._timeout, context=context) as resp:
                return self._to_response(resp.status, resp.read(self._max_bytes), resp.headers)
        except urllib.error.HTTPError as err:
            body = err.read(self._max_bytes) if hasattr(err, "read") else b""
            return self._to_response(err.code, body, err.headers or {})
        except Exception as err:  # noqa: BLE001 - transport failure: abandon this check
            logger.debug("HTTP probe failed for %s: %s", url, err)
            return None

    @staticmethod
    def _to_response(status: int, body: bytes, headers) -> Response:
        text = body.decode("utf-8", "replace") if isinstance(body, bytes) else str(body)
        header_map = {str(k).lower(): str(v) for k, v in dict(headers).items()}
        return Response(status=status, body=text, headers=header_map)
