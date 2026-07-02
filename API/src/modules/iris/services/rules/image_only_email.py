"""
Image-Only Email rule — flags messages whose entire visible content is
a single embedded image (an <img> tag with no meaningful surrounding
text). This is a well-known anti-scanner technique: the image renders
the phishing payload in the victim's inbox, while the text version that
keyword rules and downstream ML actually inspect is empty or trivial.

The rule requires ``needs_context=True`` because it inspects the HTML
body. A legitimate image-only mailer is rare in transactional / business
mail; the heuristic is therefore conservative — empty text + small
HTML footprint + at least one image whose source is external.
"""

import re

from ..registry import iris_rules, RuleResult

_IMG_TAG_RE = re.compile(r"<img\b[^>]*>", re.IGNORECASE)
_SRC_RE = re.compile(r'src\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
_TAG_RE = re.compile(r"<[^>]+>")


def _strip_html(html: str) -> str:
    return _TAG_RE.sub(" ", html or "")


@iris_rules.register(
    name="Image-Only Email",
    category="content_analysis",
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

    text_visible = _strip_html(body_html).strip()
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
        score=-10, verdict="fail",
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
