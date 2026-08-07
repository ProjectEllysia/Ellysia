"""
Avisos por correo sobre una suscripción.

**Este trabajo programado no decide nada.** No degrada, no cancela y no toca
ninguna fila de ``Subscription``: solo lee y manda correos. La vigencia se
calcula al leer (``is_effective``), así que si este job no corre un fin de
semana lo único que se pierde es un aviso — nadie se queda con un plan de pago
gratis ni se le corta a nadie antes de tiempo.

Es la diferencia con el cron nocturno que se usa en todas partes: aquel *aplica*
la degradación, y el día que falla, falla en silencio y a favor del cliente.
"""

import logging
from datetime import date, timedelta

import src.modules.system.config_reading as CR
from src.modules.infrastructure.session import get_db_session
from src.modules.shared import utcnow_naive
from src.modules.tools.herald import EmailMessage, build_mailer, render_email

from ..model import Plan, Subscription

logger = logging.getLogger(__name__)

#: Con cuánta antelación se avisa de que un plan termina.
NOTICE_DAYS_BEFORE = 3

def send_subscription_notices() -> dict[str, int]:
    """Avisa de las suscripciones que terminan pronto y de los impagos vivos.

    Returns:
        Cuántos avisos de cada tipo se mandaron. Un fallo de envío se registra y
        no interrumpe al resto: que no salga un correo no debe impedir que
        salgan los demás.
    """
    now = utcnow_naive()
    session = get_db_session()
    sent = {"expiring": 0, "past_due": 0}

    horizon = now + timedelta(days=NOTICE_DAYS_BEFORE)
    expiring = (
        session.query(Subscription)
        .filter(
            Subscription.status.in_(("active", "trialing", "canceled")),
            Subscription.current_period_end.isnot(None),
            Subscription.current_period_end > now,
            Subscription.current_period_end <= horizon,
        )
        .all()
    )
    for subscription in expiring:
        if _notify(subscription, "expiring", subscription.current_period_end):
            sent["expiring"] += 1

    past_due = (
        session.query(Subscription)
        .filter(
            Subscription.status == "past_due",
            Subscription.grace_until.isnot(None),
            Subscription.grace_until > now,
        )
        .all()
    )
    for subscription in past_due:
        if _notify(subscription, "past_due", subscription.grace_until):
            sent["past_due"] += 1

    logger.info(f"Avisos de suscripcion enviados: {sent}")
    return sent

def _notify(subscription: Subscription, kind: str, deadline) -> bool:
    """Manda un aviso. Devuelve si salió.

    Solo se avisa al **titular**. Los miembros de una organización cuyo dueño no
    ha pagado no reciben nada: verán en la interfaz que ciertas funciones ya no
    están, pero "tu jefe no ha pagado" no es un mensaje nuestro que dar.
    """
    from src.modules.users.model import User

    session = get_db_session()
    user = session.get(User, subscription.user_id)
    if user is None:
        return False

    plan = session.get(Plan, subscription.plan_id)
    try:
        html, text = render_email(
            "subscription_notice",
            recipient_name=user.first_name,
            kind=kind,
            plan_name=plan.name if plan else "",
            deadline=_format(deadline),
            plans_url=f"{CR.general_config().public_url}/mi-plan",
        )
        build_mailer("accounts").send(EmailMessage(
            to=user.email,
            to_name=user.first_name,
            subject=(
                "Hay un problema con tu pago en Ellysia" if kind == "past_due"
                else "Tu plan de Ellysia termina pronto"
            ),
            html_body=html,
            text_body=text,
        ))
        return True
    except Exception as exc:  # pylint: disable=broad-except
        logger.error(f"No se pudo avisar a {user.email} ({kind}): {exc}")
        return False

def _format(moment) -> str:
    """Fecha en el formato que lee un humano español."""
    if isinstance(moment, date):
        return moment.strftime("%d/%m/%Y")
    return str(moment)
