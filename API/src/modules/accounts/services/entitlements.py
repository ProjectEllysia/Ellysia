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

from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Tuple

from src.modules.infrastructure.session import build_repository
from src.modules.shared import utcnow_naive

from ..exceptions import DefaultPlanMissingError
from ..model import Plan, Subscription
from ..repositories import PlanLimitRepository, PlanRepository, SubscriptionRepository
from .limits import PERIODS, SCOPE_HOLDER, LimitKey, LimitPeriod


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


@dataclass(frozen=True)
class Entitlement:
    """Lo que un usuario tiene derecho a hacer para **una** clave concreta.

    Attributes:
        limit: Tope. ``None`` es ilimitado; ``0``, no incluido en el plan.
        holder_kind / holder_id: a quién se le carga el consumo. Hoy siempre el
            propio usuario; en la fase 5, la organización cuando sea ella quien
            conceda el derecho (bolsa común).
        source: de dónde viene el derecho — ``"personal"`` (su suscripción
            vigente), ``"default"`` (el plan gratuito) o, desde la fase 5,
            ``"organization"``. No es adorno: la vista "Mi plan" tiene que poder
            decir "ilimitado, cortesía de tu organización", porque de eso
            depende que el usuario entienda qué pierde si se va.
    """

    key: LimitKey
    limit: Optional[int]
    period: LimitPeriod
    holder_kind: str
    holder_id: int
    source: str
    plan_code: str

    @property
    def is_unlimited(self) -> bool:
        return self.limit is None

    @property
    def is_disabled(self) -> bool:
        """El plan no incluye la característica en absoluto."""
        return self.limit == 0


def resolve_entitlement(
    user_id: int,
    key: LimitKey,
    now: Optional[datetime] = None,
) -> Entitlement:
    """Resuelve el tope de ``key`` para ``user_id`` y quién paga su consumo.

    Una fila de ``PlanLimit`` que no existe se lee como ``0``: fallo cerrado, de
    modo que una clave nueva que nadie se acordó de rellenar queda desactivada
    en vez de regalada.

    En esta fase la única fuente es el plan personal, así que el titular del
    contador es siempre el propio usuario. La fase 5 añade aquí el ``max()``
    con los derechos derivados de la organización y, con ellos, la posibilidad
    de que el titular sea la organización.
    """
    now = now or utcnow_naive()
    plan, subscription = resolve_effective_plan(user_id, now)
    effective = is_effective(subscription, now)

    row = build_repository(PlanLimitRepository).get_one(plan.id, key.db_name, SCOPE_HOLDER)

    return Entitlement(
        key=key,
        limit=row.value if row is not None else 0,
        period=PERIODS[key],
        holder_kind="user",
        holder_id=user_id,
        source="personal" if effective else "default",
        plan_code=plan.code,
    )
