"""
Body link analysis rule (Fase 2) — the biggest gap of the header-only model.

Real phishing links live in the body, not the subject. This rule inspects
every hyperlink extracted by the full-message parser for the classic
link-cloaking and evasion patterns: visible text claiming one domain while
the href points to another, IDN/punycode homographs, IP-literal hosts, known
URL shorteners, credential-in-URL tricks, unusually deep subdomains, dense
percent-encoding obfuscation, embedded ``data:`` payloads, and
credential-harvesting keywords in the path/query of a link that doesn't
belong to the sender or a known brand.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from ..registry import iris_rules, RuleResult
from ..shared import (
    canonical_brands, extract_domain, find_brand_in_subdomain,
    registrable_domain, registrable_label, shortener_domains, url_host,
    url_phishing_keywords,
)

_DOMAIN_IN_TEXT_RE = re.compile(
    r"\b((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,})\b",
    re.IGNORECASE,
)
_IP_HOST_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
_PERCENT_ENCODED_RE = re.compile(r"%[0-9A-Fa-f]{2}")

# More than this many labels in a host is structurally unusual for a
# legitimate sender (``click.email.notices.secure-portal-x7.info``) — kept
# as a low-weight signal since deep-but-legitimate infra hosts do exist.
MAX_NORMAL_HOST_LABELS = 4

# Below this many percent-encoded triplets we don't even bother checking the
# ratio — a couple of ``%20``s in a query string is completely normal.
MIN_ENCODED_TRIPLETS = 4
# Share of the URL's length made up of percent-encoded triplets (each worth
# 3 characters) above which the encoding looks like deliberate obfuscation
# rather than ordinary query-string escaping.
DENSE_ENCODING_RATIO = 0.3

MAX_SCORE_FLOOR = -25


def _has_dense_encoding(href: str) -> bool:
    count = len(_PERCENT_ENCODED_RE.findall(href))
    if count < MIN_ENCODED_TRIPLETS:
        return False
    return (count * 3) / max(len(href), 1) >= DENSE_ENCODING_RATIO


@iris_rules.register(
    name="Body Links", category="content_analysis",
    description=(
        "Analiza los enlaces reales del cuerpo: texto visible vs href, "
        "punycode/IDN, IPs literales, acortadores de URL, credenciales en la "
        "URL, subdominios excesivos, codificación densa, payloads data: y "
        "keywords de cosecha de credenciales en el path/query."
    ),
    needs_context=True,
)
def check_body_links(context) -> RuleResult:
    links = context.links
    if not links:
        return RuleResult(score=0, verdict="neutral", details={"link_count": 0})

    sender_domain = registrable_domain(extract_domain(context.headers.get("from", "")))
    brands = canonical_brands()
    phishing_keywords = url_phishing_keywords()

    findings: list[dict] = []
    score = 0
    seen_types: set[str] = set()

    for link in links:
        href = link.href or ""
        try:
            parsed = urlparse(href)
        except ValueError:
            continue

        # A ``data:`` URI as a clickable link target has no host to inspect
        # and is itself unusual enough to flag on sight — legitimate mail
        # essentially never links to an inline data payload.
        if parsed.scheme == "data":
            findings.append({"type": "data_uri_link", "href": href[:120]})
            seen_types.add("data_uri_link")
            score -= 10
            continue

        # Userinfo-as-lure: ``http://paypal.com@evil.io/`` — the text before
        # ``@`` is attacker-controlled and can be *any* string designed to
        # look like the real destination, while the browser only ever
        # navigates to the host after it. Legitimate mail never encodes
        # credentials (or lookalike hosts) this way.
        if parsed.scheme in ("http", "https") and "@" in parsed.netloc:
            findings.append({"type": "userinfo_credential_lure", "href": href})
            seen_types.add("userinfo_credential_lure")
            score -= 15

        host = url_host(href)
        if not host:
            continue

        # Brand-as-subdomain impersonation: a known brand (or the sender's own
        # domain) appears as a left-hand label while the real registrable
        # domain is someone else's — e.g. ``github.com.sessions-security.com``.
        # This is the highest-confidence body-link phishing signal and the
        # most common one missed by visible-text cloak detection (the visible
        # text often carries no domain at all).
        brand_hit = find_brand_in_subdomain(host)
        host_reg = registrable_domain(host)
        sender_impersonation = bool(
            sender_domain
            and host_reg != sender_domain
            and ("." + sender_domain + ".") in ("." + host + ".")
        )
        if brand_hit or sender_impersonation:
            findings.append({
                "type": "brand_impersonation",
                "href": link.href,
                "host": host,
                "real_domain": host_reg,
                "impersonates": (brand_hit or {}).get("brand") or sender_domain,
            })
            seen_types.add("brand_impersonation")
            score -= 20

        if any(label.startswith("xn--") for label in host.split(".")):
            findings.append({"type": "punycode", "href": link.href})
            seen_types.add("punycode")
            score -= 8

        if _IP_HOST_RE.match(host):
            findings.append({"type": "ip_literal", "href": link.href})
            seen_types.add("ip_literal")
            score -= 6

        if host in shortener_domains():
            findings.append({"type": "shortener", "href": link.href})
            seen_types.add("shortener")
            score -= 4

        text_domain_match = _DOMAIN_IN_TEXT_RE.search(link.text or "")
        if text_domain_match:
            claimed = text_domain_match.group(1).lower()
            if claimed != host and not host.endswith("." + claimed) and claimed not in host:
                findings.append({
                    "type": "cloaked_link",
                    "visible_text": link.text.strip(),
                    "actual_href": link.href,
                })
                seen_types.add("cloaked_link")
                score -= 12

        # Unusually deep host — structurally weird even when no single label
        # matches a known brand. Low weight: legitimate deep CDN/infra
        # subdomains do exist, this is a soft additive signal, not a gate.
        if len(host.split(".")) > MAX_NORMAL_HOST_LABELS:
            findings.append({"type": "excessive_subdomains", "href": href, "host": host})
            seen_types.add("excessive_subdomains")
            score -= 5

        if _has_dense_encoding(href):
            findings.append({"type": "dense_encoding", "href": href})
            seen_types.add("dense_encoding")
            score -= 6

        # Credential-harvesting keywords in the path/query — only counted
        # against a host that is neither the sender's own domain nor a known
        # brand's domain, since "login"/"verify"/"account" are completely
        # normal on a company's own site. An insecure (http) page asking for
        # credentials on top of that is the textbook harvesting-page pattern.
        if host_reg != sender_domain and registrable_label(host) not in brands:
            path_and_query = f"{parsed.path} {parsed.query}".lower()
            kw_hits = [kw for kw in phishing_keywords if kw in path_and_query]
            if kw_hits:
                is_insecure = parsed.scheme == "http"
                finding_type = "insecure_credential_page" if is_insecure else "credential_harvest_path"
                findings.append({
                    "type": finding_type, "href": href, "keywords": kw_hits,
                })
                seen_types.add(finding_type)
                score -= 10 if is_insecure else 6

    if not findings:
        return RuleResult(score=1, verdict="pass", details={"link_count": len(links)})

    score = max(score, MAX_SCORE_FLOOR)
    return RuleResult(
        score=score, verdict="fail",
        details={"link_count": len(links), "findings": findings, "types": sorted(seen_types)},
        recommendation=(
            "Se detectaron enlaces sospechosos en el cuerpo del correo "
            f"({', '.join(sorted(seen_types))}). No hagas clic sin verificar el destino real."
        ),
    )
