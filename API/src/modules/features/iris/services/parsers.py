"""
Email parsing utilities for Iris.

Covers the full pipeline from raw text to structured data that rules can
inspect: RFC 5322 raw header parsing, RFC 2047 encoded-word decoding, full
``.eml`` message parsing (body/links/attachments) into a ``MessageContext``,
and ``Received:`` chain parsing into a graph-friendly path.

Merged from the former ``header_parser.py``, ``header_decode.py``,
``message_parser.py`` and ``received_parser.py`` — all four served the same
objective (turning raw email text into structured data) and were split
across files for no reason beyond size.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from email import message_from_string
from email.header import decode_header, make_header
from email.message import Message
from email.utils import parsedate_to_datetime
from typing import Any, Dict, List, Optional


# =============================================================================
# Raw header parsing
# =============================================================================
#
# Rules receive this dict so they can look up headers by lowercase key
# (e.g. headers["received-spf"], headers["dkim-signature"]).
#
# Continuation lines (starting with space or tab) are folded into the
# most recent header, matching RFC 5322 semantics.

def parse_raw_headers(raw: str) -> Dict[str, str]:
    """Parse raw RFC 5322 header text into a ``{name: value}`` dict.

    Handles:
    - Standard ``Key: Value`` headers (keys lowercased).
    - Continuation lines (folded whitespace per RFC 5322 section 2.2.3).
    - Carriage-return / newline line endings.

    Args:
        raw: The raw header block as a plain string.

    Returns:
        A dictionary mapping lowercase header names to their full values.
        Headers that appear multiple times are represented by the
        **first** (topmost) occurrence, folding its own continuation
        lines into it as they arrive. MTAs *prepend* trace headers
        (``Received``, ``Authentication-Results``, ``ARC-Seal``...), so
        the topmost occurrence of a repeated header is the newest one —
        added by the receiving MTA closest to delivery — while any
        occurrence further down is older and, for headers an attacker
        controls the content of before it ever reaches an MTA (e.g. by
        forging their own ``Authentication-Results`` line in the message
        they send), attacker-injected. Keeping "last occurrence wins"
        here handed a one-line spoofing bypass to every rule that reads
        ``Authentication-Results``/``ARC-Seal`` from this dict (A1, N5).
    """
    headers: Dict[str, str] = {}
    current_key: str | None = None
    current_value: str | None = None
    # True while folding continuation lines that belong to a *repeat*
    # occurrence of a header already captured above — those continuation
    # lines must not be appended onto the retained first occurrence.
    is_repeat_occurrence = False

    for line in raw.split("\n"):
        line = line.rstrip("\r")

        # continuation line (starts with space or tab)
        if line and line[0] in (" ", "\t") and current_key is not None:
            if is_repeat_occurrence:
                continue
            current_value = (current_value or "") + " " + line.strip()
            headers[current_key] = (current_value or "").strip()
            continue

        # new header
        if ":" in line:
            key, _, val = line.partition(":")
            current_key = key.strip().lower()
            current_value = val.strip()
            is_repeat_occurrence = current_key in headers
            if not is_repeat_occurrence:
                headers[current_key] = current_value

    return headers


# =============================================================================
# RFC 2047 encoded-word decoding
# =============================================================================
#
# Phishing campaigns frequently MIME-encode the Subject and From display
# name (e.g. ``=?UTF-8?B?...?=``) so that naive substring scanners never
# see the underlying words. Content rules must decode headers *before*
# matching keywords or brand names, otherwise the check is trivially
# bypassed.

def decode_mime_words(value: str) -> str:
    """Decode RFC 2047 encoded-words in a header value to Unicode text.

    Handles mixed encoded / unencoded segments (e.g. an encoded display
    name followed by a plain ``<addr@host>``). Falls back to the
    original string if the value cannot be decoded.

    Args:
        value: The raw header value, possibly containing encoded-words.

    Returns:
        The decoded Unicode string, or the original value on failure.
    """
    if not value:
        return value
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


# =============================================================================
# Full message (.eml) parsing
# =============================================================================
#
# Building on ``parse_raw_headers`` above, this uses the stdlib ``email``
# package to additionally extract the body (plain/HTML), every hyperlink
# found in the HTML/text body, real MIME attachment metadata, and the full
# ``Received:`` chain (collapsed into one entry by ``parse_raw_headers``,
# but needed in full here for hop analysis).
#
# When *raw* is only a headers block (no body/MIME parts), every
# body-derived field is simply empty — rules that need the full context
# degrade to a neutral result rather than failing, so this parser is safe
# to use unconditionally for both legacy headers-only submissions and full
# messages.

_ANCHOR_RE = re.compile(
    r'<a\b[^>]*href\s*=\s*["\']([^"\']+)["\'][^>]*>(.*?)</a>',
    re.IGNORECASE | re.DOTALL,
)
_HREF_RE = re.compile(r'href\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
_TAG_RE = re.compile(r"<[^>]+>")
_BARE_URL_RE = re.compile(r'(?<![\'"=])(https?://[^\s<>\'")]+)', re.IGNORECASE)


@dataclass
class Link:
    """A single hyperlink found in the message body."""
    href: str
    text: str = ""


@dataclass
class Attachment:
    """A real MIME attachment part found in the message."""
    filename: Optional[str]
    content_type: str
    size: int
    content: bytes = field(default=b"", repr=False)


@dataclass
class MessageContext:
    """Rich representation of a parsed email message.

    Header-only rules keep receiving the plain ``headers`` dict (via
    ``parse_raw_headers``). Rules registered with ``needs_context=True``
    receive this object instead — see ``services/registry.py`` and the
    dispatch logic in ``managers.IrisManager._run_analysis``.

    When the submitted message is a "report phishing" forward (Outlook/
    Gmail attach the original email as a ``message/rfc822`` MIME part
    rather than quoting it inline), every field above describes the
    *unwrapped original* — the message that actually matters for
    analysis — not the forwarding envelope. ``unwrapped_from_forward``
    and the ``wrapper_*`` fields preserve just enough of the outer
    message's identity for the report to say so, and ``wrapper_context``
    carries the *full* parsed wrapper so the caller can run the rule
    engine on it too (N1): a real "report phishing" forward is benign to
    unwrap, but an attacker can just as easily send their own phishing as
    the outer message and staple a benign ``.eml`` on as a
    ``message/rfc822`` attachment — unwrapping unconditionally then
    means the 40 rules never see the phishing the victim actually
    received. Analyzing only the unwrapped inner message is what a
    forward-unaware submission always wants; the ingestion pipeline
    (Fase 3+) is exactly the "automatic, no human forwarding" case where
    that assumption stops holding, so it must evaluate both and keep the
    worse verdict.
    """
    headers: Dict[str, str]
    body_text: str = ""
    body_html: str = ""
    links: List[Link] = field(default_factory=list)
    attachments: List[Attachment] = field(default_factory=list)
    received_headers: List[str] = field(default_factory=list)
    unwrapped_from_forward: bool = False
    wrapper_from: str = ""
    wrapper_subject: str = ""
    wrapper_context: Optional["MessageContext"] = None


def _decode_payload(part: Message) -> str:
    try:
        payload = part.get_payload(decode=True)
    except Exception:
        return ""
    if not payload:
        return ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except (LookupError, UnicodeDecodeError):
        return payload.decode("utf-8", errors="replace")


def _extract_links(html: str) -> List[Link]:
    links: List[Link] = []
    seen_hrefs = set()
    for m in _ANCHOR_RE.finditer(html):
        href = m.group(1).strip()
        text = _TAG_RE.sub("", m.group(2)).strip()
        links.append(Link(href=href, text=text))
        seen_hrefs.add(href)
    for m in _HREF_RE.finditer(html):
        href = m.group(1).strip()
        if href not in seen_hrefs:
            links.append(Link(href=href, text=""))
            seen_hrefs.add(href)
    return links


def _extract_bare_urls(text: str) -> List[Link]:
    return [Link(href=url, text=url) for url in _BARE_URL_RE.findall(text)]


def _find_nested_forward(msg: Message) -> Optional[Message]:
    """Find the first ``message/rfc822`` part in *msg*, if any.

    This is how Outlook/Gmail's "report phishing" button attaches the
    original email: as a nested full message, not quoted inline. The
    stdlib email parser represents such a part's payload as a
    single-element list containing the nested ``Message`` object (which
    is also why ``Message.is_multipart()`` is True for it — walking the
    tree and skipping multipart parts, as the body/attachment loop below
    does, silently ignores it otherwise).
    """
    if not msg.is_multipart():
        return None
    for part in msg.walk():
        if part.get_content_type() == "message/rfc822":
            payload = part.get_payload()
            if isinstance(payload, list) and payload:
                return payload[0]
    return None


def _message_context_from(msg: Message, raw_for_headers: str) -> MessageContext:
    """Build a ``MessageContext`` from an already-parsed ``Message`` object.

    ``raw_for_headers`` is passed through ``parse_raw_headers`` separately
    from *msg* because the header-folding rules there operate on raw
    text, not a ``Message`` object; for the top-level message this is the
    original ``raw`` input, for an unwrapped nested message it's the
    nested part's own ``.as_string()``.
    """
    headers = parse_raw_headers(raw_for_headers)

    body_text = ""
    body_html = ""
    attachments: List[Attachment] = []

    if msg.is_multipart():
        for part in msg.walk():
            if part.is_multipart():
                continue
            disposition = (part.get("Content-Disposition") or "").lower()
            content_type = part.get_content_type()
            filename = part.get_filename()

            if filename or "attachment" in disposition:
                payload = part.get_payload(decode=True) or b""
                attachments.append(Attachment(
                    filename=filename,
                    content_type=content_type,
                    size=len(payload),
                    content=payload,
                ))
                continue

            if content_type == "text/plain" and not body_text:
                body_text = _decode_payload(part)
            elif content_type == "text/html" and not body_html:
                body_html = _decode_payload(part)
    else:
        content_type = msg.get_content_type()
        if content_type == "text/html":
            body_html = _decode_payload(msg)
        elif content_type.startswith("text/"):
            body_text = _decode_payload(msg)

    links = _extract_links(body_html) if body_html else []
    if not links and body_text:
        links = _extract_bare_urls(body_text)

    received_headers = [v for k, v in msg.items() if k.lower() == "received"]

    return MessageContext(
        headers=headers,
        body_text=body_text,
        body_html=body_html,
        links=links,
        attachments=attachments,
        received_headers=received_headers,
    )


def parse_raw_message(raw: str) -> MessageContext:
    """Parse a full raw RFC 5322 / MIME message into a ``MessageContext``.

    Args:
        raw: The full raw message text (headers + body), or just a
             headers block — both are accepted.

    Returns:
        A ``MessageContext`` with whatever could be extracted. Body,
        links and attachments are empty lists/strings when *raw* has no
        body (headers-only input).

        When *raw* is a "report phishing" forward carrying the original
        email as a ``message/rfc822`` part, the returned context
        describes that *nested original* instead of the forwarding
        envelope. ``unwrapped_from_forward`` is set, ``wrapper_from``/
        ``wrapper_subject`` retain the forwarding envelope's identity for
        the report to reference, and ``wrapper_context`` carries the full
        parsed wrapper (N1) so the caller can run the rule engine on it
        too and keep the worse of the two verdicts — see
        ``MessageContext`` for why analyzing only the unwrapped inner
        message is unsafe once submissions are no longer human-forwarded.
    """
    msg = message_from_string(raw)

    nested = _find_nested_forward(msg)
    if nested is not None:
        # NOTE: deliberately read the wrapper's From/Subject via the
        # already-parsed ``msg`` object, not ``parse_raw_headers(raw)``.
        # That line-based parser has no concept of a MIME boundary — fed
        # the *entire* raw multipart text, it happily keeps "reading
        # headers" past the blank-line separator and into the nested
        # part's own header block, so its last "From:"/"Subject:" match
        # ends up being the *inner* message's, silently defeating the
        # whole point of capturing the wrapper's identity.
        context = _message_context_from(nested, nested.as_string())
        context.unwrapped_from_forward = True
        context.wrapper_from = decode_mime_words(msg.get("from", "") or "")
        context.wrapper_subject = decode_mime_words(msg.get("subject", "") or "")
        context.wrapper_context = _message_context_from(msg, raw)
        return context

    return _message_context_from(msg, raw)


# =============================================================================
# Título de presentación derivado del asunto
# =============================================================================
#
# La ingesta automática desde buzón no tiene título aportado por el usuario:
# se deriva del ``Subject`` del mensaje en vez de etiquetar el análisis como
# "Auto (<cuenta>)" — el asunto es la etiqueta natural de un correo en el
# historial.

_SUBJECT_FALLBACK_TITLE = "Correo sin asunto"

#: Límite del campo ``IrisAnalysis.title`` (String(120)).
_MAX_TITLE_LENGTH = 120


def build_subject_title(raw: str) -> str:
    """Título de presentación de un análisis ingerido: el asunto del mensaje.

    Se lee del contexto ya desenvuelto por ``parse_raw_message`` — cuando la
    ingesta captura un "report phishing" forward (``message/rfc822``), el
    asunto que interesa es el del mensaje interno analizado, no el del
    envoltorio. El asunto llega en bruto desde el proveedor, así que se
    decodifican los encoded-words RFC 2047 (``=?UTF-8?B?...?=``), se eliminan
    los caracteres de control (un asunto plegado no debe colar saltos de
    línea al campo ``title`` ni al asunto de un correo posterior) y se
    recorta a los 120 caracteres que admite ``IrisAnalysis.title``.

    Returns:
        El asunto normalizado, o ``_SUBJECT_FALLBACK_TITLE`` si el mensaje
        no trae asunto.
    """
    context = parse_raw_message(raw)
    subject = decode_mime_words(context.headers.get("subject", ""))
    subject = re.sub(r"[\x00-\x1f\x7f]", "", subject)
    subject = " ".join(subject.split())
    return subject[:_MAX_TITLE_LENGTH].strip() or _SUBJECT_FALLBACK_TITLE


# =============================================================================
# ``Received:`` header parsing
# =============================================================================
#
# RFC 5321 §4.4 defines the on-wire shape of a Received line as a sequence
# of ``KEY VALUE`` tokens (with several optional/repeating fields) followed
# by a trailing ``; timestamp``. Real-world mail servers take many
# liberties with whitespace, parentheses, and optional fields, so the
# parser is intentionally **tolerant**: anything that cannot be matched is
# preserved in the ``raw`` field of the hop and the unparsed structured
# fields are returned as ``None``. Callers must always be able to render
# the verbatim header even when structured fields are missing.
#
# Two helpers are exposed:
#
# - :func:`parse_received_line` parses a single line.
# - :func:`build_path` parses a list of Received lines in **delivery**
#   order (``received[0]`` = final hop, ``received[-1]`` = origin), and
#   returns a path ordered **oldest -> newest** plus a list of transitions
#   between consecutive hops (delay, suspicious flags). The transition
#   flags are the same ones surfaced by the ``Received Path Anomaly``
#   rule, so the visual graph and the score stay in sync.

# A bare IPv4 literal, optionally surrounded by brackets.
_IP_RE = re.compile(r"\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]")

# RFC 1918 / loopback ranges we treat as private. The list mirrors the
# one in ``services/rules/received_chain.py`` so the two stay consistent.
_PRIVATE_PREFIXES = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
    "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.",
    "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.", "127.", "0.0.0.0",
)

# Tokens in the Received grammar (the prefix before ``; timestamp``).
_KNOWN_KEYS = {"from", "by", "with", "via", "id", "for", "received"}


def _is_private_ip(ip: str) -> bool:
    return any(ip.startswith(prefix) for prefix in _PRIVATE_PREFIXES) or ip == "0.0.0.0"


def _hop_timestamp(line: str) -> Optional[datetime]:
    _, _, ts = line.rpartition(";")
    if not ts.strip():
        return None
    try:
        return parsedate_to_datetime(ts.strip())
    except (TypeError, ValueError, IndexError):
        return None


def _extract_ip(text: str) -> Optional[str]:
    """Return the first IPv4 literal found in *text*, or ``None``."""
    m = _IP_RE.search(text)
    if m:
        return m.group(1)
    # Fallback: bare IPv4 not in brackets, common in HELO/EHLO echoes.
    bare = re.search(r"(?<!\d)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?!\d)", text)
    return bare.group(1) if bare else None


def _split_tokens(prefix: str) -> List[str]:
    """Split the comment-heavy Received prefix into a flat token list.

    We strip the outermost parentheses and treat their contents as part
    of the surrounding token, since servers freely attach HELO/EHLO data
    in parentheses immediately after the IP they refer to. Anything we
    can't cleanly split falls back to a whitespace split so we never
    drop information.
    """
    flat = prefix.strip()
    if not flat:
        return []
    # Walk char-by-char; collapse "( ... )" into the surrounding token.
    tokens: List[str] = []
    buf: List[str] = []
    depth = 0
    for ch in flat:
        if ch == "(":
            depth += 1
            buf.append(ch)
        elif ch == ")":
            depth = max(0, depth - 1)
            buf.append(ch)
        elif ch.isspace() and depth == 0:
            if buf:
                tokens.append("".join(buf))
                buf = []
        else:
            buf.append(ch)
    if buf:
        tokens.append("".join(buf))
    return tokens


def _detect_tls(line: str, with_value: Optional[str], protocol: Optional[str]) -> bool:
    """Heuristic: was this hop encrypted?

    Servers usually signal TLS via either:
      * ``with = ESMTPS`` / ``ESMTPSA`` (encrypted submission)
      * ``with = ... version=TLSv1.x``
      * A literal ``(using TLSv1.x)`` somewhere in the line
    """
    if with_value:
        upper = with_value.upper()
        if "ESMTPS" in upper or "ESMTPSA" in upper:
            return True
        if "TLS" in upper:
            return True
        # HTTPS / internal Microsoft handoffs ("with HTTPS") are encrypted.
        if "HTTPS" in upper:
            return True
    if protocol and "TLS" in protocol.upper():
        return True
    if "version=TLS" in line:
        return True
    return False


def _is_cleartext_smtp_relay(hop: Dict[str, Any]) -> bool:
    """True only when a hop accepted mail over *unencrypted* SMTP/ESMTP.

    A genuine TLS downgrade means an encrypted hop handed off to a hop that
    received the message in clear text over SMTP *from another host*. The
    final internal delivery hops (``with HTTPS``, ``with LMTP``, local
    mailstore handoffs, ``Received: by ... with SMTP id`` notes that carry no
    ``from``, or hops with no ``with`` token at all) are not cleartext relays
    — treating their absence of a TLS marker as a "downgrade" was the source
    of constant false positives on ordinary Gmail/Outlook-routed mail.
    """
    if hop.get("tls"):
        return False
    # A real inbound relay names the host it received *from*. A ``by``-only
    # hop is an internal handoff, not a cleartext network relay.
    if not hop.get("from"):
        return False
    with_value = (hop.get("with") or "").upper()
    if not with_value:
        return False
    # ESMTP/SMTP without an "S" (already excluded by tls=False) is a real
    # cleartext relay; LMTP/HTTP/local deliveries are not.
    return with_value.startswith("ESMTP") or with_value.startswith("SMTP")


def parse_received_line(line: str) -> Dict[str, Any]:
    """Parse a single ``Received:`` header line into a structured dict.

    Args:
        line: The full header value, with or without the leading
            ``Received:`` token (we accept both shapes).

    Returns:
        A dict with keys ``from``, ``fromIp``, ``by``, ``with``,
        ``protocol``, ``tls``, ``timestamp``, ``flags`` and ``raw``.
        Fields that could not be extracted are ``None`` (or empty for
        ``flags``); the original line is always preserved in ``raw``.
    """
    raw = line.strip()
    # Strip the leading "Received:" if present.
    body = re.sub(r"^received\s*:\s*", "", raw, flags=re.IGNORECASE)

    timestamp = _hop_timestamp(body)
    prefix, _, _ = body.rpartition(";")
    if not prefix.strip():
        prefix = body

    tokens = _split_tokens(prefix)

    fields: Dict[str, Optional[str]] = {
        "from": None,
        "by": None,
        "with": None,
        "protocol": None,
        "id": None,
        "for": None,
    }
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        lower = tok.lower()
        if lower in _KNOWN_KEYS and i + 1 < len(tokens):
            # Repeated keys: keep the first non-null value seen.
            if fields.get(lower) is None:
                fields[lower] = tokens[i + 1]
            i += 2
        else:
            # Unrecognized token: stash into ``id`` (commonly holds
            # opaque MTA identifiers) and keep moving.
            if fields["id"] is None:
                fields["id"] = tok
            i += 1

    from_text = fields.get("from") or ""
    # The IP for the sending hop is often in the ``(...)`` block
    # immediately following the ``from`` address, not inside the
    # ``from`` token itself. Scan the full prefix so we catch both
    # shapes (bare IP in ``from``, or IP in trailing parentheses).
    from_ip = _extract_ip(from_text) or _extract_ip(prefix)

    flags: List[str] = []
    if from_ip and _is_private_ip(from_ip):
        flags.append("private_ip")

    tls = _detect_tls(raw, fields.get("with"), fields.get("protocol"))

    return {
        "from": from_text or None,
        "fromIp": from_ip,
        "by": fields.get("by"),
        "with": fields.get("with"),
        "protocol": fields.get("protocol"),
        "id": fields.get("id"),
        "for": fields.get("for"),
        "tls": tls,
        "timestamp": timestamp.isoformat() if timestamp else None,
        "flags": flags,
        "raw": raw,
    }


def _delay_ms(prev: Optional[datetime], curr: Optional[datetime]) -> Optional[int]:
    if prev is None or curr is None:
        return None
    delta = (curr - prev).total_seconds() * 1000.0
    return int(delta)


def build_path(received_headers: List[str]) -> Dict[str, Any]:
    """Build a graph-friendly representation of a Received chain.

    Args:
        received_headers: The full chain in **delivery order**
            (``received_headers[0]`` is the final delivery hop,
            ``received_headers[-1]`` is the origin). The same
            convention used elsewhere in Iris (see
            ``MessageContext.received_headers``).

    Returns:
        A dict with keys:
          * ``hops``: list of parsed hop dicts, ordered **oldest ->
            newest** so the first entry is the origin.
          * ``transitions``: list of edges between consecutive hops
            (oldest -> newest direction). Each entry includes
            ``from``, ``to``, ``delayMs`` and ``suspicious`` plus
            ``reasons`` when applicable.
          * ``hopsCount``: total number of hops (== len(hops)).
          * ``available``: True whenever a chain was present.
    """
    if not received_headers:
        return {
            "hops": [],
            "transitions": [],
            "hopsCount": 0,
            "available": False,
            "reason": "no Received chain available",
        }

    # Parse first; then reverse to oldest -> newest.
    parsed: List[Dict[str, Any]] = [parse_received_line(line) for line in received_headers]
    parsed.reverse()

    transitions: List[Dict[str, Any]] = []
    for idx in range(len(parsed) - 1):
        prev_hop = parsed[idx]
        curr_hop = parsed[idx + 1]
        # Re-derive timestamps from the original delivery-order lines:
        # after `parsed.reverse()`, parsed[idx] corresponds to
        # received_headers[N-1-idx] where N == len(received_headers).
        n = len(received_headers)
        prev_line = received_headers[n - 1 - idx]
        curr_line = received_headers[n - 2 - idx]
        prev_ts = _hop_timestamp(prev_line)
        curr_ts = _hop_timestamp(curr_line)
        delay = _delay_ms(prev_ts, curr_ts)

        reasons: List[str] = []
        if prev_hop["tls"] and _is_cleartext_smtp_relay(curr_hop):
            reasons.append("tls_downgrade")
        if delay is not None and delay < 0:
            reasons.append("time_inversion")

        transitions.append({
            "from": idx + 1,           # 1-based hop numbers for the UI
            "to": idx + 2,
            "delayMs": delay,
            "suspicious": bool(reasons),
            "reasons": reasons,
        })

    # Re-stamp each hop with its 1-based index for the UI.
    hops: List[Dict[str, Any]] = []
    for idx, hop in enumerate(parsed):
        stamped = dict(hop)
        stamped["hop"] = idx + 1
        stamped["index"] = len(parsed) - idx  # original index in delivery order
        hops.append(stamped)

    return {
        "hops": hops,
        "transitions": transitions,
        "hopsCount": len(hops),
        "available": True,
    }
