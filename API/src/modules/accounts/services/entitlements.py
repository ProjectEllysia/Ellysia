"""
Resolución del plan efectivo de un usuario.

Aquí vive la decisión que sostiene toda la capa comercial: **el plan efectivo
se calcula en cada lectura**, a partir del estado y las fechas de la
suscripción. No hay ningún proceso que "aplique" una degradación y, por tanto,
tampoco ninguno que pueda olvidarse de aplicarla — que es como fallan estos
sistemas en todas partes: el cron nocturno no corre un fin de semana y hay
cuentas disfrutando gratis de un plan caducado sin que nadie se entere.

Hay dos fuentes de derechos que nunca se anulan entre sí: el plan personal y lo
que un usuario recibe por pertenecer a una organización cuyo dueño paga. Gana
el ``max()`` de las dos — ver ``resolve_entitlement`` para el detalle de quién
paga cuando empatan.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Tuple

from src.modules.infrastructure.session import build_repository
from src.modules.shared import utcnow_naive

from ..exceptions import DefaultPlanMissingError
from ..model import Plan, Subscription
from ..repositories import (
    OrganizationMemberRepository,
    OrganizationRepository,
    PlanLimitRepository,
    PlanRepository,
    SubscriptionRepository,
)
from .limits import PERIODS, SCOPE_HOLDER, SCOPE_MEMBER, LimitKey, LimitPeriod


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
        holder_kind / holder_id: a quién se le carga el consumo — el propio
            usuario, o la organización cuando es ella quien concede el
            derecho (bolsa común entre sus miembros).
        source: de dónde viene el derecho — ``"personal"`` (su suscripción
            vigente), ``"default"`` (el plan gratuito) u ``"organization"``.
            No es adorno: la vista "Mi plan" tiene que poder decir
            "ilimitado, cortesía de tu organización", porque de eso depende
            que el usuario entienda qué pierde si se va.
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


def _limit_of(plan_id: int, key: LimitKey, scope: str) -> Optional[int]:
    """Tope declarado por un plan para una clave y un ámbito.

    Una fila que no existe se lee como ``0``: fallo cerrado, de modo que una
    clave nueva que nadie se acordó de rellenar queda desactivada en vez de
    regalada.
    """
    row = build_repository(PlanLimitRepository).get_one(plan_id, key.db_name, scope)
    return row.value if row is not None else 0


def _is_at_least(candidate: Optional[int], reference: Optional[int]) -> bool:
    """``candidate >= reference`` con ``None`` valiendo "ilimitado"."""
    if candidate is None:
        return True
    if reference is None:
        return False
    return candidate >= reference


def resolve_organization_grant(
    user_id: int,
    key: LimitKey,
    now: datetime,
) -> Tuple[Optional[int], Optional[int]]:
    """Derechos que le llegan a ``user_id`` por pertenecer a una organización.

    Returns:
        ``(tope, organization_id)``. ``(0, None)`` si no pertenece a ninguna, o
        si la suscripción del dueño no está vigente o perdió el toggle — que es
        justo lo que pasa cuando el dueño deja de pagar: los miembros
        conservan cuenta, datos y plan personal, y solo dejan de recibir lo
        heredado.
    """
    membership = build_repository(OrganizationMemberRepository).get_by_user(user_id)
    if membership is None:
        return 0, None

    organization = build_repository(OrganizationRepository).get_by_id(membership.organization_id)
    if organization is None:
        return 0, None

    owner_subscription = build_repository(SubscriptionRepository).get_by_user(
        organization.owner_user_id
    )
    if not is_effective(owner_subscription, now) or not owner_subscription.organization_enabled:
        return 0, None

    return _limit_of(owner_subscription.plan_id, key, SCOPE_MEMBER), organization.id


def resolve_entitlement(
    user_id: int,
    key: LimitKey,
    now: Optional[datetime] = None,
) -> Entitlement:
    """Resuelve el tope de ``key`` para ``user_id`` y quién paga su consumo.

    Dos fuentes que **nunca se anulan entre sí**: el plan personal y lo que le
    llega por pertenecer a una organización. Gana el mayor de los dos, con
    ``None`` (ilimitado) por encima de cualquier número.

    Entrar en una organización no cancela ni sustituye el plan personal: un
    empleado sigue siendo Freemium *y además* tiene bóveda de verdad porque su
    empresa paga Gold. Si se compra un Bronze, sube donde Bronze le dé más, y
    al salir de la empresa se lo lleva intacto.

    **Quién paga.** Paga quien concede el tope que gana. Si empatan paga la
    organización, para no gastarle al empleado su cupo personal en algo que su
    empresa ya cubre. Cuando paga la organización, el contador es el suyo — la
    bolsa común que comparten todos sus miembros.
    """
    now = now or utcnow_naive()

    plan, subscription = resolve_effective_plan(user_id, now)
    personal_limit = _limit_of(plan.id, key, SCOPE_HOLDER)
    personal_source = "personal" if is_effective(subscription, now) else "default"

    organization_limit, organization_id = resolve_organization_grant(user_id, key, now)

    if organization_id is not None and _is_at_least(organization_limit, personal_limit):
        return Entitlement(
            key=key,
            limit=organization_limit,
            period=PERIODS[key],
            holder_kind="org",
            holder_id=organization_id,
            source="organization",
            plan_code=plan.code,
        )

    return Entitlement(
        key=key,
        limit=personal_limit,
        period=PERIODS[key],
        holder_kind="user",
        holder_id=user_id,
        source=personal_source,
        plan_code=plan.code,
    )
