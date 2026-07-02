"""
Date Header Anomaly rule — flags emails with suspicious Date headers.

Legitimate email servers maintain accurate clocks. A Date header in the
distant future or far past is a strong indicator of a spoofed or
automatically generated malicious message. A completely missing Date
header is also suspicious.
"""

from datetime import datetime, timedelta, timezone

from email.utils import parsedate_to_datetime

from ..registry import iris_rules, RuleResult

MAX_FUTURE_DAYS = 1
MAX_PAST_DAYS = 365


@iris_rules.register(name="Date Header Anomaly", category="header_analysis",
                     description="Detecta si la cabecera Date está ausente, en el futuro lejano o en el pasado remoto")
def check_date_anomaly(headers: dict) -> RuleResult:
    date_str = headers.get("date", "")

    if not date_str or not date_str.strip():
        return RuleResult(
            score=-3, verdict="missing",
            details={"date": "missing"},
            recommendation="La cabecera Date está ausente. Los correos legítimos siempre incluyen "
                           "una marca de tiempo. Esto puede indicar un correo generado automáticamente "
                           "o malicioso.",
        )

    try:
        parsed = parsedate_to_datetime(date_str)
    except (ValueError, TypeError, OverflowError):
        return RuleResult(
            score=-4, verdict="unparseable",
            details={"date": date_str},
            recommendation=f"No se pudo interpretar la cabecera Date: '{date_str}'. "
                           "Un formato de fecha inválido es sospechoso y puede indicar "
                           "manipulación intencional.",
        )

    now = datetime.now(timezone.utc)

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    if parsed > now + timedelta(days=MAX_FUTURE_DAYS):
        future_days = (parsed - now).days
        return RuleResult(
            score=-4, verdict="future",
            details={
                "date": date_str,
                "parsed": parsed.isoformat(),
                "days_in_future": future_days,
            },
            recommendation=f"La fecha del correo está {future_days} días en el futuro "
                           f"({parsed.strftime('%Y-%m-%d %H:%M UTC')}). "
                           "Los servidores legítimos tienen relojes precisos; "
                           "una fecha futura indica manipulación o spoofing.",
        )

    if parsed < now - timedelta(days=MAX_PAST_DAYS):
        past_days = (now - parsed).days
        return RuleResult(
            score=-2, verdict="past",
            details={
                "date": date_str,
                "parsed": parsed.isoformat(),
                "days_in_past": past_days,
            },
            recommendation=f"La fecha del correo está hace {past_days} días "
                           f"({parsed.strftime('%Y-%m-%d %H:%M UTC')}). "
                           "Correos legítimos antiguos no son comunes; "
                           "podría ser un intento de phishing con plantillas reutilizadas.",
        )

    return RuleResult(
        score=1, verdict="pass",
        details={"date": date_str, "parsed": parsed.isoformat()},
        recommendation=None,
    )
