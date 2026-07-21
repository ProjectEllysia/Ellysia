"""
Traceroute service for the Themis module.

Runs a single traceroute from the Ellysia server to a target host and parses the
output into a normalized list of hops. This is invoked on demand (the first
time a user opens a scan detail for a given target) and the result is cached
in the database by ``TracerouteManager`` so the probe is not repeated on every
view.

The parser is platform-aware:
    - POSIX (the Ellysia production server): ``traceroute``.
    - Windows (developer machines): ``tracert`` as a best-effort fallback.

A hop is a dict::

    {"ttl": int, "ip": str | None, "hostname": str | None, "rtt_ms": float | None}

A hop with ``ip is None`` represents a non-responding (timed-out) hop ("* * *").
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
import sys
from typing import List, Optional, Dict, Any

import src.modules.system.config_reading as CR


logger = logging.getLogger(__name__)


# IPv4 or (loosely) IPv6 address.
_IP_RE = re.compile(
    r"\b(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,})\b"
)
# Round-trip time, e.g. "1.234 ms".
_RTT_RE = re.compile(r"([\d.]+)\s*ms")
# "hostname (1.2.3.4)" (POSIX) form.
_PAREN_RE = re.compile(r"([^\s()]+)\s*\(([^)]+)\)")
# "hostname [1.2.3.4]" (Windows) form.
_BRACKET_RE = re.compile(r"([^\s\[\]]+)\s*\[([^\]]+)\]")


class TracerouteService:
    """Runs and parses a traceroute to a single target."""

    def trace(self, target: str) -> List[Dict[str, Any]]:
        """Run a traceroute to ``target`` and return the parsed hops.

        Args:
            target: IP address or hostname to trace the route to.

        Returns:
            Ordered list of hop dicts (see module docstring). Empty list if the
            traceroute binary is unavailable or produced no parseable hops.
        """
        max_hops = CR.get_themis_traceroute_max_hops()
        timeout = CR.get_themis_traceroute_timeout()

        cmd = self._build_command(target, max_hops)
        if cmd is None:
            logger.error(
                "No se encontró binario de traceroute/tracert en el PATH. "
                "En el contenedor de la API instala 'traceroute' (ver Dockerfile)."
            )
            return []

        logger.info(f"Ejecutando traceroute: {' '.join(cmd)}")
        try:
            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            # Partial output is still useful: parse whatever arrived before the
            # timeout instead of discarding the whole trace.
            logger.warning(f"Traceroute a '{target}' agotó el tiempo ({timeout}s)")
            partial = exc.output or ""
            if isinstance(partial, bytes):
                partial = partial.decode("utf-8", errors="replace")
            return self._parse(partial)
        except (OSError, ValueError) as exc:
            logger.error(f"Error ejecutando traceroute a '{target}': {exc}", exc_info=True)
            return []

        hops = self._parse(proc.stdout or "")
        if not hops:
            # El comando se ejecutó pero no produjo saltos parseables. La causa
            # más común en contenedores es la falta de CAP_NET_RAW (mensaje
            # "Operation not permitted") o que la red filtre el ICMP. Se registra
            # la salida cruda para poder diagnosticarlo sin adivinar.
            snippet = (proc.stdout or "").strip()[:500] or "(sin salida)"
            logger.warning(
                f"Traceroute a '{target}' no devolvió saltos "
                f"(returncode={proc.returncode}). Salida: {snippet}"
            )
        return hops

    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def _build_command(target: str, max_hops: int) -> Optional[List[str]]:
        """Build the platform-specific traceroute command, or None if missing."""
        if sys.platform.startswith("win"):
            tracert = shutil.which("tracert")
            if not tracert:
                return None
            # -d: no DNS resolution; -h: max hops; -w: per-hop wait (ms).
            return [tracert, "-d", "-h", str(max_hops), "-w", "1000", target]

        traceroute = shutil.which("traceroute")
        if not traceroute:
            return None
        # -q 1: one probe per hop (faster); -m: max hops; -w: per-hop wait (s).
        # Names are resolved by traceroute itself (no -n) for a richer graph.
        # sudo -n: non-interactive (requires NOPASSWD in sudoers) — same pattern
        # as Nmap scans. Needed because -T (TCP SYN) requires CAP_NET_RAW.
        return ["sudo", "-n", traceroute, "-T", "-q", "1", "-m", str(max_hops), "-w", "2", target]

    def _parse(self, output: str) -> List[Dict[str, Any]]:
        """Parse raw traceroute/tracert output into normalized hops."""
        hops: List[Dict[str, Any]] = []

        for raw_line in output.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            match = re.match(r"^(\d+)\s+(.*)$", line)
            if not match:
                # Skip headers ("traceroute to ...", "Tracing route ...", etc.).
                continue

            ttl = int(match.group(1))
            rest = match.group(2)

            hostname, ip = self._extract_host_ip(rest)
            rtt = self._extract_rtt(rest)

            hops.append({
                "ttl": ttl,
                "ip": ip,
                "hostname": hostname if hostname and hostname != ip else None,
                "rtt_ms": rtt,
            })

        return hops

    @staticmethod
    def _extract_host_ip(rest: str) -> tuple[Optional[str], Optional[str]]:
        """Pull (hostname, ip) out of a single hop line body."""
        paren = _PAREN_RE.search(rest)
        if paren:
            return paren.group(1), paren.group(2)

        bracket = _BRACKET_RE.search(rest)
        if bracket:
            return bracket.group(1), bracket.group(2)

        ip_match = _IP_RE.search(rest)
        if ip_match:
            return None, ip_match.group(1)

        # No address: a timed-out hop ("* * *" / "Request timed out.").
        return None, None

    @staticmethod
    def _extract_rtt(rest: str) -> Optional[float]:
        """Return the first round-trip time in milliseconds, if any."""
        rtt_match = _RTT_RE.search(rest)
        if not rtt_match:
            return None
        try:
            return round(float(rtt_match.group(1)), 3)
        except (TypeError, ValueError):
            return None
