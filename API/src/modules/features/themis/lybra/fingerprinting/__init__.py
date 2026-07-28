"""Lybra's own service fingerprinting — the identification layer (Fase F).

Instead of trusting ``nmap -sV`` blindly, this package identifies a service's
product and version on its own terms. One module per protocol, chosen for the
best value-for-effort in the roadmap:

``http``
    The ``Server``/``X-Powered-By`` headers, the page ``<title>``, a favicon
    hash, and a data-driven, Wappalyzer-style technology signature feed.

``ssh``
    The identification banner plus **HASSH** — a fingerprint of the algorithm
    lists a server advertises in its ``SSH_MSG_KEXINIT`` packet, parsed
    straight off a raw socket, no SSH library involved.

``tls``
    A single-handshake hygiene check — negotiated protocol version, self-signed
    and expiry status of the certificate. Not JARM (full bit-exact
    *identification*, a separate and larger effort left for later).

``concordance``
    The protocol-agnostic "does our fingerprint match Nmap's?" comparison and
    aggregate metric every dissector above shares — see its own docstring for
    the governing principle (Nmap stays the oracle until a family's
    concordance is proven).

That said, a service found by Lybra's own transport (Fase T, no Nmap
involved) never had a Nmap reading to defer to in the first place — it carries
no product/version at all. For that case, and only that case,
``LybraEngineManager._fingerprint_services`` uses a dissector's output to
fill the gap: without it, the version matcher (Fase 1) would have nothing to
look up and a self-discovery-only scan would never find a single CVE. The
result still goes in at the same low-confidence, unconfirmed tier a Nmap CPE
match would (``qod=70``) — this closes a blind spot, it does not raise
confidence beyond what the matcher already assigns any version-based guess.

Two techniques are deliberately left for later: full JARM fingerprinting (too
large and risky to ship without a live TLS lab to validate it against) and OS
fingerprinting (which the roadmap itself rates low value). Both stay
oracle-only — handled by Nmap — until picked up. A fourth protocol, FTP, is
Fase N's opening move (roadmap §"Fase N") and lives in ``ftp``.
"""

from __future__ import annotations

from .http import (
    HttpFingerprint,
    TechMatcher,
    TechSignature,
    load_tech_signatures,
    fingerprint_http,
)
from .ssh import (
    SSH_MSG_KEXINIT,
    SshFingerprint,
    parse_ssh_banner,
    parse_kexinit,
    compute_hassh_server,
    fingerprint_ssh,
    SshProbe,
)
from .tls import (
    TlsInfo,
    TlsProbe,
)
from .ftp import (
    FtpFingerprint,
    parse_ftp_banner,
    fingerprint_ftp,
    FtpProbe,
)
from .concordance import (
    QOD_FINGERPRINT,
    agrees_with_nmap,
    concordance_rate,
)

__all__ = [
    "HttpFingerprint",
    "TechMatcher",
    "TechSignature",
    "load_tech_signatures",
    "fingerprint_http",
    "SSH_MSG_KEXINIT",
    "SshFingerprint",
    "parse_ssh_banner",
    "parse_kexinit",
    "compute_hassh_server",
    "fingerprint_ssh",
    "SshProbe",
    "TlsInfo",
    "TlsProbe",
    "FtpFingerprint",
    "parse_ftp_banner",
    "fingerprint_ftp",
    "FtpProbe",
    "QOD_FINGERPRINT",
    "agrees_with_nmap",
    "concordance_rate",
]
