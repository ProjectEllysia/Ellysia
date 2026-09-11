"""
Body link rules — where do the real hyperlinks in the message body
actually go, and does that match what they claim to be?

- **Body Links**: the workhorse check — visible text vs. href mismatch
  (cloaking), IDN/punycode homographs, IP-literal hosts, known URL
  shorteners, credential-in-URL tricks (``user@host``), unusually deep
  subdomains, dense percent-encoding obfuscation, embedded ``data:``
  payloads, and credential-harvesting keywords in the path/query of a
  link that doesn't belong to the sender or a known brand. The per-URL
  heuristics themselves live in ``shared.analyze_url()`` so QR Code Links
  (below) can apply the exact same scrutiny to a URL that never appeared
  as clickable text.
- **QR Code Links** (D1, "quishing"): decodes any QR codes embedded in
  image attachments/inline images and runs the decoded URL through
  ``shared.analyze_url()`` — a QR code is a way to smuggle a phishing URL
  past every text/link-based scanner, since it never appears as text or
  an ``<a href>`` anywhere in the message.
- **Compromised Legitimate Domain**: a *trusted* domain hosting an open
  redirector or an opaque short-path typical of a phishing kit staged on
  a compromised legitimate site — a different threat model from Body
  Links (attacker-owned lookalike domain), so scored separately.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import cv2
import numpy as np

import src.modules.system.config_reading as CR
from ..registry import iris_rules, RuleResult
from ..evidence import attachment_evidence, link_evidence, qr_url_evidence, unique_evidence
from ..wordlists import esp_tracker_domains, redirect_params
from ..text import analyze_url, extract_domain, registrable_domain, url_host


def _max_score_floor() -> float:
    return CR.get_iris_scoring_weight("body_links.floor", -25)


@iris_rules.register(
    name="Body Links", is_self_anchoring=True, is_body_dependent=True, category="content_analysis", family="links",
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

    findings: list[dict] = []
    score = 0
    seen_types: set[str] = set()

    anchored_evidence: list[dict] = []
    for link_index, link in enumerate(links):
        link_findings, link_score = analyze_url(link.href or "", sender_domain, link.text or "")
        findings.extend(link_findings)
        score += link_score
        seen_types.update(link_finding["type"] for link_finding in link_findings)
        if link_findings:
            anchored_evidence.append(link_evidence(link_index, link))

    if not findings:
        return RuleResult(score=1, verdict="pass", details={"link_count": len(links)})

    score = max(score, _max_score_floor())
    return RuleResult(
        score=score, verdict="fail",
        details={"link_count": len(links), "findings": findings, "types": sorted(seen_types)},
        evidence=anchored_evidence,
        recommendation=(
            "Se detectaron enlaces sospechosos en el cuerpo del correo "
            f"({', '.join(sorted(seen_types))}). No hagas clic sin verificar el destino real."
        ),
    )


def _qr_score_floor() -> float:
    return CR.get_iris_scoring_weight("qr_code_links.floor", -25)


def _decode_qr_urls(image_bytes: bytes) -> list[str]:
    """Decode every QR code in *image_bytes*, returning only the payloads
    that look like a URL (a QR can encode arbitrary text/vCards/WiFi
    credentials — only a URL payload is relevant to a phishing check).

    Returns an empty list for anything that isn't a decodable image or
    has no QR code — this is a best-effort scan, not a hard requirement.
    """
    if not image_bytes:
        return []
    try:
        arr = np.frombuffer(image_bytes, dtype=np.uint8)
        img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
        if img is None:
            return []
        ok, decoded_info, _points, _straight = cv2.QRCodeDetector().detectAndDecodeMulti(img)
    except cv2.error:
        return []
    if not ok:
        return []
    return [text for text in decoded_info if text.startswith(("http://", "https://"))]


@iris_rules.register(
    name="QR Code Links", is_self_anchoring=True, is_body_dependent=True, category="content_analysis", family="links",
    description=(
        "Decodifica códigos QR en imágenes inline/adjuntas y analiza la URL "
        "resultante con la misma batería de chequeos que Body Links "
        "(quishing: URLs que nunca aparecen como texto/enlace clicable)."
    ),
    needs_context=True,
)
def check_qr_code_links(context) -> RuleResult:
    images = [(attachment_index, att) for attachment_index, att in enumerate(context.attachments)
              if (att.content_type or "").startswith("image/")]
    if not images:
        return RuleResult(score=0, verdict="neutral", details={"image_count": 0})

    sender_domain = registrable_domain(extract_domain(context.headers.get("from", "")))

    findings: list[dict] = []
    score = 0
    seen_types: set[str] = set()
    qr_urls: list[str] = []

    anchored_evidence: list[dict] = []
    for attachment_index, image in images:
        for url in _decode_qr_urls(image.content):
            qr_urls.append(url)
            url_findings, url_score = analyze_url(url, sender_domain)
            for url_finding in url_findings:
                findings.append({**url_finding, "source": "qr_code", "filename": image.filename})
            score += url_score
            seen_types.update(url_finding["type"] for url_finding in url_findings)
            if url_findings:
                anchored_evidence.append(attachment_evidence(attachment_index, image))
                anchored_evidence.append(qr_url_evidence(attachment_index, url))

    if not qr_urls:
        return RuleResult(score=0, verdict="pass", details={"image_count": len(images), "qr_count": 0})

    if not findings:
        return RuleResult(
            score=1, verdict="pass",
            details={"image_count": len(images), "qr_count": len(qr_urls), "qr_urls": qr_urls},
        )

    score = max(score, _qr_score_floor())
    return RuleResult(
        score=score, verdict="fail",
        details={
            "image_count": len(images), "qr_count": len(qr_urls),
            "qr_urls": qr_urls, "findings": findings, "types": sorted(seen_types),
        },
        evidence=unique_evidence(anchored_evidence),
        recommendation=(
            "El correo contiene un código QR que decodifica a una URL sospechosa "
            f"({', '.join(sorted(seen_types))}). No lo escanees: un QR es una forma "
            "de esconder un enlace de phishing de cualquier filtro basado en texto."
        ),
    )


def _looks_opaque_path(path: str) -> bool:
    """Long single-segment alphanumeric path, no slashes/dots — typical
    of generated short-URLs used by phishing kits hosted on compromised sites."""
    if not path or "/" in path.lstrip("/"):
        return False
    cleaned = path.lstrip("/")
    if len(cleaned) < 12:
        return False
    if "." in cleaned:
        return False
    alnum_ratio = sum(character.isalnum() for character in cleaned) / len(cleaned)
    return alnum_ratio >= 0.95


@iris_rules.register(
    name="Compromised Legitimate Domain", is_self_anchoring=True, is_body_dependent=True,
    category="content_analysis", family="links",
    description=(
        "Detecta enlaces a dominios legítimos que probablemente han sido "
        "comprometidos: open redirectors, paths opacos generados por kits "
        "de phishing, o combinaciones de ambos."
    ),
    needs_context=True,
)
def check_compromised_legitimate_domain(context) -> RuleResult:
    links = context.links or []
    if not links:
        return RuleResult(score=0, verdict="neutral", details={"link_count": 0})

    findings: list[dict] = []
    score = 0

    redirect_param_names = redirect_params()

    anchored_evidence: list[dict] = []
    for link_index, link in enumerate(links):
        href = link.href or ""
        host = url_host(href)
        if not host or not href.startswith(("http://", "https://")):
            continue

        try:
            parsed = urlparse(href)
        except ValueError:
            continue

        evidence: list[str] = []
        query_params = parse_qs(parsed.query, keep_blank_values=True)
        for param, values in query_params.items():
            if param.lower() in redirect_param_names and values:
                target = values[0]
                if target.startswith(("http://", "https://")):
                    target_host = url_host(target)
                    if target_host and target_host != host:
                        evidence.append(f"redirect_param:{param}=>{target_host}")

        if _looks_opaque_path(parsed.path):
            evidence.append(f"opaque_path:{parsed.path}")

        if evidence:
            findings.append({
                "href": href,
                "host": host,
                "evidence": evidence,
            })
            anchored_evidence.append(link_evidence(link_index, link))
            score += (
                CR.get_iris_scoring_weight("compromised_domain.single_evidence", -6)
                if len(evidence) == 1
                else CR.get_iris_scoring_weight("compromised_domain.multi_evidence", -9)
            )

    if not findings:
        return RuleResult(score=0, verdict="pass", details={"link_count": len(links)})

    return RuleResult(
        score=score, verdict="fail",
        details={"link_count": len(links), "findings": findings},
        evidence=anchored_evidence,
        recommendation=(
            "Se detectaron enlaces a dominios aparentemente legítimos con "
            "patrones típicos de sitios comprometidos (open redirectors o "
            "paths opacos generados por kits). Verifica el destino real antes "
            "de hacer clic: el dominio puede haber sido hackeado o abusado."
        ),
    )


@iris_rules.register(
    name="External Login Link", unanchorable_reason=(
        "Señal informativa que no resta puntos: resume los dominios externos de todos los enlaces en conjunto."
    ), is_body_dependent=True,
    category="content_analysis",
    description=(
        "Señal informativa (score 0): ¿hay algún enlace del cuerpo cuyo "
        "dominio registrable difiere del From y no es un ESP conocido? Se "
        "combina con Alarming Keywords fuerte para aproximar el "
        "'primo autenticado' -- dominio propio, auth limpia, marca fuera de "
        "`canonical_brands` -- sin depender de esa lista."
    ),
    needs_context=True,
)
def check_external_login_link(context) -> RuleResult:
    links = context.links or []
    if not links:
        return RuleResult(score=0, verdict="pass", details={"link_count": 0})

    from_domain = registrable_domain(extract_domain(context.headers.get("from", "")))
    esp_domains = esp_tracker_domains()

    external_hosts: set[str] = set()
    for link in links:
        host = url_host(link.href or "")
        if not host:
            continue
        reg = registrable_domain(host)
        if not reg or reg == from_domain or reg in esp_domains or host in esp_domains:
            continue
        external_hosts.add(reg)

    if not external_hosts:
        return RuleResult(score=0, verdict="pass", details={"link_count": len(links)})

    return RuleResult(
        score=0, verdict="fail",
        details={"link_count": len(links), "external_hosts": sorted(external_hosts)},
        recommendation=None,
    )
