"""
Suspicious Attachment Inspection rule.

When the full message is available (Fase 2), inspects every real MIME
part discovered by the message parser: dangerous filename extensions,
double extensions, macro-enabled Office documents, HTML parts (potential
HTML smuggling), and ZIP archives that bundle an executable.

Falls back to the original Content-Type/Content-Disposition header
heuristic when no real MIME parts are available — i.e. a headers-only
submission, where individual parts cannot be inspected.
"""

from __future__ import annotations

import hashlib
import io
import re
import zipfile

from ..registry import iris_rules, RuleResult
from ..shared import dangerous_extensions, macro_extensions, suspicious_mime_types

ZIP_EXTENSIONS = {".zip"}
ZIP_MIME_TYPES = {"application/zip", "application/x-zip-compressed"}

ATTACHMENT_SCORE_FLOOR = -25


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
    ext = _get_extension(filename) if filename else ""

    if ext in macro_extensions():
        return {"filename": filename, "extension": ext, "reason": "macro_enabled"}
    if ext in dangerous_extensions():
        return {"filename": filename, "extension": ext, "reason": "dangerous_extension"}
    if filename and _has_double_extension(filename):
        return {"filename": filename, "extension": ext or "(none)", "reason": "double_extension"}
    if att.content_type == "text/html":
        return {"filename": filename or "(html part)", "reason": "html_attachment_possible_smuggling"}
    if ext in ZIP_EXTENSIONS or att.content_type in ZIP_MIME_TYPES:
        if _zip_contains_executable(att.content):
            return {"filename": filename, "reason": "archive_contains_executable"}
    return None


_REASON_SCORES = {
    "dangerous_extension": -8,
    "double_extension": -8,
    "macro_enabled": -10,
    "html_attachment_possible_smuggling": -6,
    "archive_contains_executable": -12,
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
        ext = _get_extension(filename)
        if ext in dangerous_extensions():
            findings.append({
                "filename": filename, "extension": ext,
                "double_extension": _has_double_extension(filename),
                "source": "content-disposition",
            })
        elif _has_double_extension(filename):
            findings.append({
                "filename": filename, "extension": ext or "(none)",
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
    for f in findings:
        if "extension" in f:
            ext_descriptions.append(f["extension"])
            if f.get("double_extension"):
                score -= 2
            score -= 6
        if "mime_type" in f:
            ext_descriptions.append(f["mime_type"])
            score -= 5

    score = max(score, ATTACHMENT_SCORE_FLOOR)
    return RuleResult(
        score=score, verdict="fail",
        details={
            "content_type": content_type,
            "content_disposition": content_disposition,
            "findings": findings,
        },
        recommendation=(
            f"El correo incluye archivos adjuntos con extensiones potencialmente peligrosas: "
            f"{', '.join(ext_descriptions)}. "
            "Estas extensiones son utilizadas frecuentemente para distribuir malware. "
            "No abras estos archivos a menos que estés absolutamente seguro de su procedencia."
        ),
    )


@iris_rules.register(
    name="Suspicious Attachments", category="content_analysis",
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
    for att in attachments:
        finding = _inspect_real_attachment(att)
        if not finding:
            continue
        hashes = _content_hashes(att.content)
        if hashes:
            finding.update(hashes)
        findings.append(finding)

    if not findings:
        return RuleResult(score=0, verdict="pass", details={"attachment_count": len(attachments)})

    score = sum(_REASON_SCORES[f["reason"]] for f in findings)
    score = max(score, ATTACHMENT_SCORE_FLOOR)

    return RuleResult(
        score=score, verdict="fail",
        details={"attachment_count": len(attachments), "findings": findings},
        recommendation=(
            "El correo incluye adjuntos potencialmente peligrosos: "
            + ", ".join(f.get("filename") or f["reason"] for f in findings) + ". "
            "No los abras a menos que confíes plenamente en el remitente."
        ),
    )
