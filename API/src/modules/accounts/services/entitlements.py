"""
Resolución del plan efectivo de un usuario.

Aquí vive la decisión que sostiene toda la capa comercial: **el plan efectivo
se calcula en cada lectura**, a partir del estado y las fechas de la
suscripción. No hay ningún proceso que "aplique" una degradación y, por tanto,
tampoco ninguno que pueda olvidarse de aplicarla — que es como fallan estos
sistemas en todas partes: el cron nocturno no corre un fin de semana y hay
cuentas disfrutando gratis de un plan caducado sin que nadie se entere.

En esta fase la única fuente de derechos es el plan personal. La unión con los
derechos derivados de la organización (el ``max()`` del §4 del diseño) llega
con la fase 5, cuando ``OrganizationMember`` tenga filas.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional, Tuple

from src.modules.infrastructure.session import build_repository
from src.modules.shared import utcnow_naive

from ..exceptions import DefaultPlanMissingError
from ..model import Plan, Subscription
from ..repositories import PlanRepository, SubscriptionRepository


#: Estados que conceden derechos mientras el periodo siga abierto.
_LIVE_STATUSES = ("active", "trialing")


def is_effective(subscription: Optional[Subscription], now: datetime) -> bool:
    """¿Esta suscripción concede derechos en el instante ``now``?

    Un estado por sí solo no basta; hay que mirar también las fechas:

    - ``active`` / ``trialing``: vigente mientras no venza el periodo. Sin
      ``current_period_end`` no caduca nunca (es el caso del plan por defecto).
      ``trialing`` se comporta exactamente igual que ``active``; lo único que
      cambia es lo que dice la interfaz.
    - ``past_due``: vigente durante la ventana de cortesía. Un impago no corta
      al instante — una tarjeta caducada es mucho más frecuente que un moroso,
      y cortarle la monitorización a alguien porque su banco rechazó un cargo
      el martes es un error caro.
    - ``canceled``: **sigue vigente hasta el final del periodo pagado**.
      Cancelar significa "no se renueva", no "córtame ahora". Confundir las dos
      cosas es quitarle a un cliente lo que ya ha pagado el día que pulsa
      "darme de baja".

    Args:
        subscription: La suscripción, o ``None`` si el usuario no tiene fila.
        now: Instante de referencia, en UTC naive (``utcnow_naive()``).

    Returns:
        True si concede derechos ahora mismo. ``None`` devuelve False: no tener
        suscripción no es tener derechos de pago — es tener los del plan por
        defecto, que resuelve ``resolve_effective_plan``.
    """
    if subscription is None:
        return False

    if subscription.status in _LIVE_STATUSES:
        return (
            subscription.current_period_end is None
            or now < subscription.current_period_end
        )

    if subscription.status == "past_due":
        return subscription.grace_until is not None and now < subscription.grace_until

    if subscription.status == "canceled":
        return (
            subscription.current_period_end is not None
            and now < subscription.current_period_end
        )

    # Estado desconocido: fallo cerrado.
    return False


def resolve_effective_plan(
    user_id: int,
    now: Optional[datetime] = None,
) -> Tuple[Plan, Optional[Subscription]]:
    """Devuelve el plan que concede derechos a un usuario, y su suscripción.

    - Sin fila                          → (plan por defecto, None)
    - Fila no vigente (``is_effective``) → (plan por defecto, suscripción)
    - Fila vigente                       → (plan de la suscripción, suscripción)

    La suscripción se devuelve **aunque no sea vigente y aunque el plan que se
    aplique sea otro**: la interfaz necesita su ``status``, ``graceUntil`` y
    ``currentPeriodEnd`` para poder decir "hay un problema con tu pago, tienes
    hasta el 13" en vez de degradar en silencio.

    Camino de lectura: usa ``build_repository``, no demarca transacción y no
    escribe nada. Devuelve entidades ligadas a la sesión ambiental de la
    petición; convertirlas a dict es cosa del manager.

    Raises:
        DefaultPlanMissingError: si el catálogo no tiene plan por defecto. Es un
            fallo de despliegue (migración sin aplicar), no de la petición.
    """
    now = now or utcnow_naive()

    subscription = build_repository(SubscriptionRepository).get_by_user(user_id)
    if is_effective(subscription, now):
        return subscription.plan, subscription

    default_plan = build_repository(PlanRepository).get_default()
    if default_plan is None:
        raise DefaultPlanMissingError()

    return default_plan, subscription
