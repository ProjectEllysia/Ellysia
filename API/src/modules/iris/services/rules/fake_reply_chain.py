"""
Fake Reply Chain rule — detects when the Subject mimics a reply or
forward but no In-Reply-To or References headers exist.

Phishing campaigns often prepend "Re:" or "Fwd:" to the subject line
to make the email appear to be part of a legitimate conversation,
bypassing the recipient's skepticism. A real reply always carries
In-Reply-To and/or References headers.
"""

import re

from ..registry import iris_rules, RuleResult

REPLY_PREFIXES = [
    r"re(?:\[\d+\])?:",     # Re:, Re[2]:, RE:
    r"fwd?:",               # Fwd:, FW:
    r"aw(?:\[\d+\])?:",     # AW: (German Antowort)
    r"r(?:\[\d+\])?:",      # R:, R[1]:
    r"rv(?:\[\d+\])?:",     # RV: (Spanish reenvío)
    r"enc(?:\s*\()?",       # ENC (encaminado)
]

REPLY_PREFIX_PATTERN = re.compile(
    r"^\s*(?:" + "|".join(REPLY_PREFIXES) + r")\s*",
    re.IGNORECASE,
)


@iris_rules.register(name="Fake Reply Chain", category="header_analysis",
                     description="Detecta si el asunto imita una respuesta o reenvío sin los cabeceras In-Reply-To o References")
def check_fake_reply_chain(headers: dict) -> RuleResult:
    subject = headers.get("subject", "")
    in_reply_to = headers.get("in-reply-to", "")
    references = headers.get("references", "")
    thread_index = headers.get("thread-index", "")
    thread_topic = headers.get("thread-topic", "")

    if not subject:
        return RuleResult(
            score=0, verdict="neutral",
            details={"subject": ""},
            recommendation=None,
        )

    match = REPLY_PREFIX_PATTERN.match(subject)

    if not match:
        return RuleResult(
            score=0, verdict="pass",
            details={"subject": subject, "has_reply_prefix": False},
            recommendation=None,
        )

    reply_prefix = match.group(0).strip()

    has_reply_references = bool(in_reply_to.strip()) or bool(references.strip())
    has_outlook_threading = bool(thread_index.strip()) or bool(thread_topic.strip())
    has_threading = has_reply_references or has_outlook_threading

    if has_threading:
        return RuleResult(
            score=2, verdict="pass",
            details={
                "subject": subject,
                "reply_prefix": reply_prefix,
                "has_threading_headers": True,
                "source": "In-Reply-To/References" if has_reply_references else "Thread-Index/Thread-Topic",
            },
            recommendation=None,
        )

    return RuleResult(
        score=-4, verdict="fail",
        details={
            "subject": subject,
            "reply_prefix": reply_prefix,
            "has_threading_headers": False,
            "in_reply_to": in_reply_to or "missing",
            "references": references or "missing",
            "thread_index": thread_index or "missing",
            "thread_topic": thread_topic or "missing",
        },
        recommendation=(
            f"El asunto del correo comienza con '{reply_prefix}' simulando ser parte de "
            "una conversación previa, pero no se encontraron los cabeceras In-Reply-To, "
            "References, Thread-Index ni Thread-Topic que los mensajes de respuesta legítimos "
            "suelen incluir. Esto es una táctica común de phishing para generar confianza falsa. "
            "No asumas que es una respuesta a un hilo real."
        ),
    )
