"""The Redis dissector — Fase N.

Unlike FTP/SMTP/MySQL, Redis does not volunteer anything on a bare connect —
it waits for a command. Sending ``INFO`` (a read-only, standard admin command)
is the same class of action as an HTTP ``GET /``: it does not write or modify
anything on the target. A server that requires authentication replies with a
``NOAUTH`` error instead of the info payload, which correctly yields no
identification here — and separately makes the *lack* of that error a useful
signal in its own right for the ``redis-unauthenticated-access`` active check
(``checks_feed.json``), reusing this exact same probe pattern declaratively.

Module named ``redis_probe`` rather than ``redis`` to avoid any risk of
shadowing the third-party ``redis`` package other modules in this codebase
import (TaskQueue's RQ backend).
"""

from __future__ import annotations

import logging
import re
import socket
from dataclasses import dataclass
from typing import Callable, Optional

from ..checks import is_redis_service
from .dispatch import Dissector, DissectorResult
from .registry import register_dissector

logger = logging.getLogger(__name__)

_VERSION_RE = re.compile(r"redis_version:([\w.\-]+)")
_MAX_REPLY_BYTES = 65536


@dataclass(frozen=True)
class RedisFingerprint:
    """The result of fingerprinting a Redis service.

    Attributes:
        product: ``"Redis"``, or ``None`` if the ``INFO`` reply carried no
            recognisable version (including the auth-required case).
        version: The reported Redis version, or ``None``.
        confidence: A 0.0-1.0 self-assessed confidence in the identification.
    """
    product: Optional[str]
    version: Optional[str]
    confidence: float


def parse_redis_info(reply: str) -> Optional[str]:
    """Extract the ``redis_version`` field from an ``INFO`` command's reply.

    Args:
        reply: The raw (RESP-framed) reply text.

    Returns:
        The version string, or ``None`` if absent — notably including the
        case where the server demanded authentication first.
    """
    match = _VERSION_RE.search(reply or "")
    return match.group(1) if match else None


def fingerprint_redis(reply: str) -> RedisFingerprint:
    """Fingerprint a Redis service from its ``INFO`` reply."""
    version = parse_redis_info(reply)
    return RedisFingerprint(
        product="Redis" if version else None,
        version=version,
        confidence=0.9 if version else 0.0,
    )


# =========================================================================
# PROBE (the network edge: raw socket, no redis-py client involved)
# =========================================================================

class RedisProbe:
    """Connects to a Redis port, sends ``INFO``, and reads the reply.

    Bounded to a handful of reads so a server that never responds (e.g. one
    firewalled to accept-but-not-answer) cannot hang the scan indefinitely —
    each individual ``recv`` failure or timeout simply ends the read early
    with whatever was collected so far.

    Args:
        timeout: The per-operation timeout, in seconds.
        connect: An injectable ``(address, timeout) -> socket`` callable.
    """

    def __init__(self, timeout: float = 5.0, connect: Optional[Callable] = None) -> None:
        self._timeout = timeout
        self._connect = connect or socket.create_connection

    def fetch(self, host: str, port: int = 6379) -> Optional[str]:
        """Connect, send ``INFO``, and return the decoded reply.

        Returns:
            The reply text, or ``None`` on connection failure or an empty reply.
        """
        try:
            sock = self._connect((host, port), self._timeout)
        except OSError as err:
            logger.debug("Redis probe connect failed for %s:%s: %s", host, port, err)
            return None
        try:
            sock.sendall(b"INFO\r\n")
            data = b""
            for _ in range(5):
                try:
                    chunk = sock.recv(4096)
                except OSError:
                    break
                if not chunk:
                    break
                data += chunk
                if b"redis_version:" in data or len(data) >= _MAX_REPLY_BYTES:
                    break
            return data.decode("utf-8", "ignore") or None
        except OSError as err:
            logger.debug("Redis probe failed for %s:%s: %s", host, port, err)
            return None
        finally:
            try:
                sock.close()
            except OSError:
                pass


@register_dissector
class RedisDissector(Dissector):
    label = "Redis"

    def __init__(self, probe: Optional[RedisProbe] = None) -> None:
        self._probe = probe or RedisProbe()

    def applies(self, service) -> bool:
        return is_redis_service(service)

    def probe(self, target, service, rate_limiter):
        rate_limiter.acquire(target)
        reply = self._probe.fetch(target, service.port or 6379)
        if reply is None:
            return None
        fingerprint = fingerprint_redis(reply)
        return DissectorResult(fingerprint.product, fingerprint.version, self.label)
