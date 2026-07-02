"""
URL in Subject rule — flags emails that contain URLs directly in the
Subject line.

While legitimate marketing or transactional emails may include URLs in
the subject, phishing campaigns frequently embed links in the subject
to trick users into clicking before reading the email body.
"""

import re

from ..registry import iris_rules, RuleResult
from ..parsers import decode_mime_words


def _contains_url(text: str) -> list[str]:
    urls: list[str] = []
    patterns = [
        r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(?::\d+)?(?:/[\w\-./?%&+=~#!@]*)?",
        r"(?:www\.)[\w\-]+(?:\.[\w\-]+)+(?::\d+)?(?:/[\w\-./?%&+=~#!@]*)?",
        r"[\w\-.]+\.(?:tk|ml|ga|cf|gq|xyz|click|zip|download|review|top|loan|work|trade|racing|win|stream|men|bid|date|party|science|accountant|faith)(?:/[\w\-./?%&+=~#!@]*)?",
    ]
    for pattern in patterns:
        urls.extend(re.findall(pattern, text, re.IGNORECASE))
    return urls


@iris_rules.register(name="URL in Subject", category="content_analysis",
                     description="Detecta si el asunto del correo contiene URLs (común en phishing)")
def check_url_in_subject(headers: dict) -> RuleResult:
    subject = decode_mime_words(headers.get("subject", ""))

    if not subject:
        return RuleResult(
            score=0, verdict="neutral",
            details={"subject": ""},
            recommendation=None,
        )

    urls_found = _contains_url(subject)

    if not urls_found:
        return RuleResult(
            score=1, verdict="pass",
            details={"subject": subject, "urls_found": []},
            recommendation=None,
        )

    count = len(urls_found)

    return RuleResult(
        score=-5 * min(count, 2),
        verdict="fail",
        details={
            "subject": subject,
            "urls_found": urls_found,
            "url_count": count,
        },
        recommendation=(
            "El asunto del correo contiene enlaces (URLs). "
            "Los correos legítimos rara vez incluyen URLs en el asunto; "
            "esta es una táctica común en phishing para atraer clics compulsivos. "
            "No hagas clic en enlaces del asunto sin verificar antes la legitimidad del correo."
        ),
    )
