"""
Image and attachment rules — content smuggled in non-text form, which
plain-text keyword scanners can't inspect directly.

- **External Image Tracking**: HTML body pulls images from a domain that
  is neither the From domain nor a known ESP — a tracking-pixel /
  address-confirmation pattern, or a credential-harvesting page rendered
  as a screenshot.
- **Image-Only Email**: the entire visible content is a single embedded
  image with essentially no real text — the classic anti-scanner trick
  where the payload lives in the image, not the (empty) text the scanner
  actually inspects.
- **Suspicious Attachments**: dangerous filename extensions, double
  extensions, macro-enabled Office documents, HTML parts (potential HTML
  smuggling), and ZIP archives bundling an executable — plus a SHA256/MD5
  hash of any flagged attachment for threat-intel pivoting.
"""

from __future__ import annotations

import hashlib
import io
import re
import zipfile

import src.modules.system.config_reading as CR
from ..registry import iris_rules, RuleResult
from ..evidence import attachment_evidence, header_evidence
from ..wordlists import (
    dangerous_extensions, esp_tracker_domains,
    macro_extensions, suspicious_mime_types,
)
from ..text import extract_domain, registrable_domain, strip_html, url_host

_IMG_SRC_RE = re.compile(r'<img\b[^>]*src\s*=\s*["\']([^"\']+)["\']',
                          re.IGNORECASE)


@iris_rules.register(
    name="External Image Tracking", unanchorable_reason=(
        "La regla evalúa el cuerpo en conjunto y no registra la posición exacta de lo que encuentra, así que no hay un fragmento concreto que señalar."
    ), is_body_dependent=True,
    category="content_analysis", family="attachment",
    description=(
        "Detecta imágenes (u otros recursos) embebidos desde un dominio "
        "externo que no es el From ni un ESP/marketing conocido. Patrón "
        "de tracking pixel y de phishing con payload en imagen."
    ),
    needs_context=True,
)
def check_external_image_tracking(context) -> RuleResult:
    body_html = context.body_html or ""
    if not body_html:
        return RuleResult(score=0, verdict="neutral", details={"reason": "no html body"})

    from_domain = registrable_domain(extract_domain(context.headers.get("from", "")))

    sources = [match.group(1) for match in _IMG_SRC_RE.finditer(body_html)]

    esp_domains = esp_tracker_domains()

    findings: list[dict] = []
    for source_url in sources:
        if not source_url.startswith(("http://", "https://")):
            continue
        host = url_host(source_url)
        if not host:
            continue
        reg = registrable_domain(host)
        if from_domain and reg == from_domain:
            continue
        if reg in esp_domains or host in esp_domains:
            continue
        findings.append({"src": source_url, "host": host, "registrable": reg})

    if not findings:
        return RuleResult(
            score=0, verdict="pass",
            details={"from_domain": from_domain, "external_image_count": 0},
            recommendation=None,
        )

    # Calibración FP: prácticamente todo correo HTML legítimo sirve sus
    # imágenes desde el CDN de la marca, que casi nunca es ni el dominio del
    # From ni un ESP del allowlist (githubassets.com para github.com,
    # kwcdn.com para temu.com...). Un único host externo era, en la práctica,
    # una penalización fija a todo el correo maquetado, así que baja a 0: el
    # hallazgo se sigue reportando (útil como recomendación de "bloquea la
    # carga de imágenes"), pero deja de empujar el score. Varios hosts
    # externos distintos sí siguen siendo el patrón de tracking/payload.
    unique_hosts = {finding["registrable"] for finding in findings if finding["registrable"]}
    score = (
        CR.get_iris_scoring_weight("external_image_tracking.single_host", 0)
        if len(unique_hosts) == 1
        else CR.get_iris_scoring_weight("external_image_tracking.multi_host", -5)
    )  # recalibración de pesos

    return RuleResult(
        score=score, verdict="fail",
        details={
            "from_domain": from_domain,
            "external_image_count": len(findings),
            "external_image_hosts": sorted(unique_hosts),
            "findings": findings,
        },
        recommendation=(
            f"El cuerpo carga imágenes desde {len(unique_hosts)} dominio(s) "
            f"externo(s) no-ESP ({', '.join(sorted(unique_hosts))}). Esto es "
            "compatible con un tracking pixel de confirmación de dirección "
            "activa o con un payload de phishing renderizado como imagen. "
            "Bloquea la carga automática de imágenes en tu cliente hasta "
            "verificar el remitente."
        ),
    )


_IMG_TAG_RE = re.compile(r"<img\b[^>]*>", re.IGNORECASE)
_SRC_RE = re.compile(r'src\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)


@iris_rules.register(
    name="Image-Only Email", unanchorable_reason=(
        "La señal es la proporción entre imágenes y texto de todo el cuerpo, no un fragmento concreto."
    ), is_body_dependent=True,
    category="content_analysis", family="attachment",
    description=(
        "Detecta correos cuyo contenido visible es esencialmente una sola "
        "imagen (técnica típica anti-scanner: el payload está en la imagen "
        "y el texto extraído es vacío)."
    ),
    needs_context=True,
)
def check_image_only_email(context) -> RuleResult:
    body_html = context.body_html or ""
    body_text = context.body_text or ""

    if not body_html and not body_text:
        return RuleResult(score=0, verdict="neutral", details={"reason": "no body"})

    text_visible = strip_html(body_html).strip()
    text_length = len(text_visible.split())

    img_tags = _IMG_TAG_RE.findall(body_html)
    img_count = len(img_tags)

    external_img_count = 0
    for tag in img_tags:
        src_match = _SRC_RE.search(tag)
        if src_match and src_match.group(1).startswith(("http://", "https://", "data:image")):
            external_img_count += 1

    if img_count == 0:
        return RuleResult(
            score=0, verdict="pass",
            details={"img_count": 0, "text_length": text_length},
            recommendation=None,
        )

    is_image_only = (
        text_length < 10
        and img_count >= 1
        and (external_img_count == img_count or external_img_count >= 1)
    )

    if not is_image_only:
        return RuleResult(
            score=0, verdict="pass",
            details={"img_count": img_count, "text_length": text_length},
            recommendation=None,
        )

    return RuleResult(
        score=CR.get_iris_scoring_weight("image_only_email.fail", -6), verdict="fail",  # recalibración de pesos
        details={
            "img_count": img_count,
            "external_img_count": external_img_count,
            "text_length": text_length,
        },
        recommendation=(
            f"El cuerpo del correo es esencialmente una imagen "
            f"({img_count} <img>, texto extraído de {text_length} palabras). "
            "Esta es una técnica conocida de evasión de filtros: la imagen "
            "renderiza el payload (logo falso, formulario, captcha) que el "
            "scanner de texto no puede leer. Trata con sospecha cualquier "
            "correo cuyo contenido visible no sea texto real."
        ),
    )


ZIP_EXTENSIONS = {".zip"}
ZIP_MIME_TYPES = {"application/zip", "application/x-zip-compressed"}

def _attachment_score_floor() -> float:
    return CR.get_iris_scoring_weight("attachment.floor", -25)


def _extract_filename(content_disposition: str) -> str | None:
    match = re.search(r'filename\s*=\s*["\']?([^"\';\n]+)["\']?', content_disposition, re.IGNORECASE)
    if match:
        return match.group(1).strip()
    match = re.search(r'filename\*\s*=\s*["\']?([^"\';\n]+)["\']?', content_disposition, re.IGNORECASE)
    if match:
        return match.group(1).strip()
    return None


def _get_extension(filename: str) -> str:
    _, _, ext = filename.rpartition(".")
    return "." + ext.lower() if ext else ""


def _has_double_extension(filename: str) -> bool:
    parts = filename.lower().split(".")
    if len(parts) >= 3:
        last = parts[-1]
        second_last = parts[-2]
        if len(last) <= 4 and last.isalpha() and len(second_last) <= 4 and second_last.isalpha():
            return True
    return False


def _zip_contains_executable(content: bytes) -> bool:
    if not content:
        return False
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as zf:
            return any(_get_extension(name) in dangerous_extensions() for name in zf.namelist())
    except (zipfile.BadZipFile, OSError, RuntimeError):
        return False


def _content_hashes(content: bytes) -> dict[str, str] | None:
    """SHA256 + MD5 of an attachment's bytes, for pivoting in threat-intel
    tools (VirusTotal, internal blocklists). ``None`` when there is no
    content to hash (e.g. an empty part)."""
    if not content:
        return None
    return {
        "sha256": hashlib.sha256(content).hexdigest(),
        "md5": hashlib.md5(content).hexdigest(),
    }


def _inspect_real_attachment(att) -> dict | None:
    filename = att.filename or ""
    extension = _get_extension(filename) if filename else ""

    if extension in macro_extensions():
        return {"filename": filename, "extension": extension, "reason": "macro_enabled"}
    if extension in dangerous_extensions():
        return {"filename": filename, "extension": extension, "reason": "dangerous_extension"}
    if filename and _has_double_extension(filename):
        return {"filename": filename, "extension": extension or "(none)", "reason": "double_extension"}
    if att.content_type == "text/html":
        return {"filename": filename or "(html part)", "reason": "html_attachment_possible_smuggling"}
    if extension in ZIP_EXTENSIONS or att.content_type in ZIP_MIME_TYPES:
        if _zip_contains_executable(att.content):
            return {"filename": filename, "reason": "archive_contains_executable"}
    return None


def _reason_scores() -> dict[str, float]:
    return {
        "dangerous_extension": CR.get_iris_scoring_weight("attachment.dangerous_extension", -8),
        "double_extension": CR.get_iris_scoring_weight("attachment.double_extension", -8),
        "macro_enabled": CR.get_iris_scoring_weight("attachment.macro_enabled", -10),
        "html_attachment_possible_smuggling": CR.get_iris_scoring_weight("attachment.html_smuggling", -6),
        "archive_contains_executable": CR.get_iris_scoring_weight("attachment.archive_contains_executable", -12),
    }


def _check_headers_fallback(headers: dict) -> RuleResult:
    """Original header-only heuristic, used when no real MIME parts exist."""
    content_type = headers.get("content-type", "")
    content_disposition = headers.get("content-disposition", "")
    combined = (content_type + " " + content_disposition).lower()

    if "multipart" in combined:
        return RuleResult(
            score=0, verdict="neutral",
            details={"reason": "multipart email — individual parts not inspected at header level"},
        )

    filename = _extract_filename(content_disposition)
    findings: list[dict] = []

    if filename:
        extension = _get_extension(filename)
        if extension in dangerous_extensions():
            findings.append({
                "filename": filename, "extension": extension,
                "double_extension": _has_double_extension(filename),
                "source": "content-disposition",
            })
        elif _has_double_extension(filename):
            findings.append({
                "filename": filename, "extension": extension or "(none)",
                "double_extension": True, "source": "content-disposition",
            })

    for mime in suspicious_mime_types():
        if mime in content_type.lower():
            findings.append({"mime_type": mime, "filename": filename or "unknown", "source": "content-type"})

    if not findings:
        return RuleResult(
            score=0, verdict="pass",
            details={"content_type": content_type, "content_disposition": content_disposition},
        )

    score = 0
    ext_descriptions: list[str] = []
    for finding in findings:
        if "extension" in finding:
            ext_descriptions.append(finding["extension"])
            if finding.get("double_extension"):
                score += CR.get_iris_scoring_weight("attachment_header_fallback.double_extension_bonus", -2)
            score += CR.get_iris_scoring_weight("attachment_header_fallback.dangerous_extension", -6)
        if "mime_type" in finding:
            ext_descriptions.append(finding["mime_type"])
            score += CR.get_iris_scoring_weight("attachment_header_fallback.suspicious_mime", -5)

    score = max(score, _attachment_score_floor())
    return RuleResult(
        score=score, verdict="fail",
        details={
            "content_type": content_type,
            "content_disposition": content_disposition,
            "findings": findings,
        },
        evidence=header_evidence(headers, ("content-disposition", "content-type")),
        recommendation=(
            f"El correo incluye archivos adjuntos con extensiones potencialmente peligrosas: "
            f"{', '.join(ext_descriptions)}. "
            "Estas extensiones son utilizadas frecuentemente para distribuir malware. "
            "No abras estos archivos a menos que estés absolutamente seguro de su procedencia."
        ),
    )


@iris_rules.register(
    name="Suspicious Attachments", is_self_anchoring=True, is_body_dependent=True, category="content_analysis", family="attachment",
    description=(
        "Inspecciona los adjuntos MIME reales (extensiones peligrosas, doble "
        "extensión, macros, HTML smuggling, ZIP con ejecutables); recurre a la "
        "heurística de cabeceras cuando no hay partes MIME disponibles."
    ),
    needs_context=True,
)
def check_suspicious_attachments(context) -> RuleResult:
    attachments = context.attachments

    if not attachments:
        return _check_headers_fallback(context.headers)

    findings: list[dict] = []
    anchored_evidence: list[dict] = []
    for attachment_index, att in enumerate(attachments):
        finding = _inspect_real_attachment(att)
        if not finding:
            continue
        hashes = _content_hashes(att.content)
        if hashes:
            finding.update(hashes)
        findings.append(finding)
        anchored_evidence.append(attachment_evidence(attachment_index, att))

    if not findings:
        return RuleResult(score=0, verdict="pass", details={"attachment_count": len(attachments)})

    reason_scores = _reason_scores()
    score = sum(reason_scores[finding["reason"]] for finding in findings)
    score = max(score, _attachment_score_floor())

    return RuleResult(
        score=score, verdict="fail",
        details={"attachment_count": len(attachments), "findings": findings},
        evidence=anchored_evidence,
        recommendation=(
            "El correo incluye adjuntos potencialmente peligrosos: "
            + ", ".join(finding.get("filename") or finding["reason"] for finding in findings) + ". "
            "No los abras a menos que confíes plenamente en el remitente."
        ),
    )
