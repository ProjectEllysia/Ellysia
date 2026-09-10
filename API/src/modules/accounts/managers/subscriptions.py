"""
Ciclo de vida de una suscripción: el puerto por el que entrará la pasarela.

**Seis operaciones de intención y ni una más.** Ese es todo el vocabulario: si
un evento de una pasarela no encaja en ninguna, la respuesta correcta es
ignorarlo, no añadir una séptima. Aquí no existen las palabras *invoice*,
*checkout session* ni *price id* — el día que se enchufe el cobro, un adaptador
traducirá sus eventos a estas llamadas y este fichero no cambiará.

Hoy quien las mueve es root desde el panel. Son dos clientes del mismo puerto,
no dos caminos, y por eso la máquina de estados se puede probar entera sin
pasarela.

Lo que **no** hace ninguna de las seis: escribir en ``UserAttribute``,
cambiar ``User.role``, crear o borrar una ``Organization``, tocar
``UsageCounter`` o borrar datos de nadie. Un pago escribe ``Subscription``, y se
acabó.
"""

import logging
from datetime import datetime
from typing import Optional

from src.modules.infrastructure import UnitOfWork
from src.modules.infrastructure.session import build_repository
from src.modules.shared import utcnow_naive
from src.modules.shared._exceptions import ValidationError

from ..exceptions import PlanNotFoundError, SubscriptionNotFoundError
from ..model import Subscription
from ..repositories import PlanRepository, SubscriptionRepository

logger = logging.getLogger(__name__)


#: Marca imposible de superar hacia atrás, para la primera comparación.
_NEVER = datetime.min


class SubscriptionManager:
    """Las seis operaciones que mueven una suscripción."""

    # --------------------------------------------------------------- altas

    def activate(
        self,
        user_id: int,
        plan_code: str,
        *,
        organization_enabled: bool = False,
        period_end: Optional[datetime] = None,
        external_refs: Optional[dict] = None,
        actor_id: Optional[int] = None,
        event_at: Optional[datetime] = None,
    ) -> dict:
        """Alta, renovación o cambio de plan. El caso de uso del "pago correcto".

        Es **idempotente por construcción**: escribe un estado absoluto, nunca
        un delta, así que aplicarla dos veces con el mismo evento deja lo mismo.

        Subir de plan es inmediato y **no resetea los contadores**: 40 gastados
        de 100 pasan a ser 40 de 400. Bajar también es inmediato y no devuelve
        nada; si ya se gastó por encima del tope nuevo, esa clave entra en modo
        excedido — solo lectura hasta volver por debajo, nunca borrado.

        Args:
            period_end: Fin de la vigencia. ``None`` = sin caducidad, que es el
                caso del plan por defecto.
            event_at: Marca del evento de la pasarela, para descartar los
                viejos y los repetidos.
        """
        plan = build_repository(PlanRepository).get_by_code(plan_code)
        if plan is None:
            raise PlanNotFoundError(plan_code)

        now = utcnow_naive()
        with UnitOfWork() as uow:
            repo = SubscriptionRepository(uow)
            subscription = repo.get_by_user(user_id)

            if subscription is None:
                subscription = Subscription(user_id=user_id, plan_id=plan.id, started_at=now)
                uow.session.add(subscription)
            elif self._is_stale(subscription, event_at):
                return self._serialize(subscription)

            subscription.plan_id = plan.id
            subscription.status = "active"
            subscription.organization_enabled = organization_enabled
            subscription.current_period_start = now
            subscription.current_period_end = period_end
            subscription.cancel_at_period_end = False
            subscription.grace_until = None
            subscription.assigned_by_user_id = actor_id
            self._apply_external(subscription, external_refs, event_at)
            uow.session.flush()

            logger.info(f"Suscripcion activada | user={user_id} plan={plan_code}")
            return self._serialize(subscription)

    def start_trial(
        self,
        user_id: int,
        plan_code: str,
        *,
        ends_at: datetime,
        actor_id: Optional[int] = None,
    ) -> dict:
        """Arranca un periodo de prueba.

        ``trialing`` concede exactamente lo mismo que ``active``; lo único que
        cambia es lo que dice la interfaz y que su final llama a ``expire()`` y
        no a ``mark_past_due()`` — nadie ha dejado de pagar nada.
        """
        payload = self.activate(user_id, plan_code, period_end=ends_at, actor_id=actor_id)
        with UnitOfWork() as uow:
            repo = SubscriptionRepository(uow)
            subscription = repo.get_by_user(user_id)
            subscription.status = "trialing"
            repo.update(subscription)
            payload["status"] = "trialing"

        logger.info(f"Trial iniciado | user={user_id} plan={plan_code} hasta={ends_at}")
        return payload

    # ------------------------------------------------------------- impago

    def mark_past_due(
        self,
        user_id: int,
        *,
        grace_until: datetime,
        event_at: Optional[datetime] = None,
    ) -> dict:
        """Impago. **No degrada nada todavía**: abre la ventana de cortesía.

        Una tarjeta caducada es mucho más frecuente que un moroso, y cortarle
        la monitorización a alguien porque su banco rechazó un cargo el martes
        es un error caro. Durante la cortesía el plan sigue vigente, con aviso.
        """
        return self._transition(
            user_id, event_at,
            status="past_due",
            grace_until=grace_until,
            log=f"Impago registrado | user={user_id} cortesia_hasta={grace_until}",
        )

    def resume(self, user_id: int, *, event_at: Optional[datetime] = None) -> dict:
        """Deshace un impago tras cobrar, o una cancelación pendiente."""
        return self._transition(
            user_id, event_at,
            status="active",
            grace_until=None,
            cancel_at_period_end=False,
            log=f"Suscripcion reanudada | user={user_id}",
        )

    # -------------------------------------------------------------- bajas

    def cancel(
        self,
        user_id: int,
        *,
        immediate: bool = False,
        actor_id: Optional[int] = None,
        event_at: Optional[datetime] = None,
    ) -> dict:
        """Baja. **Cancelar no corta**: corta caducar.

        Por defecto la suscripción sigue vigente hasta el final del periodo ya
        pagado — es lo que el cliente ha comprado, y quitárselo el día que
        pulsa "darme de baja" es el tipo de error del que uno se entera por
        Twitter.

        ``immediate=True`` es para devoluciones y contracargos: ahí no queda
        periodo que respetar.
        """
        extra = {"current_period_end": utcnow_naive()} if immediate else {}
        return self._transition(
            user_id, event_at,
            status="canceled",
            cancel_at_period_end=not immediate,
            assigned_by_user_id=actor_id,
            log=f"Suscripcion cancelada | user={user_id} inmediata={immediate}",
            **extra,
        )

    def expire(self, user_id: int, *, event_at: Optional[datetime] = None) -> dict:
        """Fin de vigencia: la cuenta vuelve al plan por defecto.

        Es la única operación que corta de verdad. Ojo: no hace falta llamarla
        para que alguien pierda un plan caducado — la vigencia se calcula al
        leer (``is_effective``). Esto solo deja el estado escrito de forma
        legible para el panel.
        """
        return self._transition(
            user_id, event_at,
            status="canceled",
            current_period_end=utcnow_naive(),
            cancel_at_period_end=False,
            grace_until=None,
            log=f"Suscripcion caducada | user={user_id}",
        )

    # -------------------------------------------------------- despachador

    def apply(
        self,
        *,
        operation: str,
        user_id: int,
        actor_id: Optional[int] = None,
        plan_code: Optional[str] = None,
        organization_enabled: bool = False,
        period_end: Optional[datetime] = None,
        grace_until: Optional[datetime] = None,
        immediate: bool = False,
    ) -> dict:
        """Ejecuta una de las seis por su nombre.

        Existe para que el panel de root (y manyana el adaptador de la pasarela)
        tengan una sola puerta, en vez de un ``if/elif`` por operación repetido
        en cada cliente. Cada rama exige sus argumentos: pedir ``mark_past_due``
        sin ``graceUntil`` es un 400, no una cortesía de cero segundos.
        """
        if operation == "activate":
            self._require(plan_code, "planCode", operation)
            return self.activate(
                user_id, plan_code,
                organization_enabled=organization_enabled,
                period_end=period_end, actor_id=actor_id,
            )

        if operation == "start_trial":
            self._require(plan_code, "planCode", operation)
            self._require(period_end, "periodEnd", operation)
            return self.start_trial(user_id, plan_code, ends_at=period_end, actor_id=actor_id)

        if operation == "mark_past_due":
            self._require(grace_until, "graceUntil", operation)
            return self.mark_past_due(user_id, grace_until=grace_until)

        if operation == "cancel":
            return self.cancel(user_id, immediate=immediate, actor_id=actor_id)

        if operation == "resume":
            return self.resume(user_id)

        return self.expire(user_id)

    @staticmethod
    def _require(value, name: str, operation: str) -> None:
        if value in (None, ""):
            raise ValidationError(
                field=name,
                message=f"La operacion '{operation}' necesita '{name}'",
                value=None,
            )

    # ----------------------------------------------------------- internos

    def _transition(
        self,
        user_id: int,
        event_at: Optional[datetime],
        *,
        log: str,
        **values,
    ) -> dict:
        with UnitOfWork() as uow:
            repo = SubscriptionRepository(uow)
            subscription = repo.get_by_user(user_id)
            if subscription is None:
                raise SubscriptionNotFoundError(user_id)
            if self._is_stale(subscription, event_at):
                return self._serialize(subscription)

            for field, value in values.items():
                setattr(subscription, field, value)
            self._apply_external(subscription, None, event_at)
            repo.update(subscription)

            logger.info(log)
            return self._serialize(subscription)

    @staticmethod
    def _is_stale(subscription: Subscription, event_at: Optional[datetime]) -> bool:
        """¿Este evento es más viejo que el último aplicado?

        Toda pasarela reintenta y toda pasarela entrega desordenado. Sin esto,
        una renovación que llega después de un impago dejaría la suscripción
        marcada como impagada para siempre. Un evento viejo o repetido se
        ignora: no es un error.
        """
        if event_at is None:
            return False
        return event_at <= (subscription.external_event_at or _NEVER)

    @staticmethod
    def _apply_external(
        subscription: Subscription,
        external_refs: Optional[dict],
        event_at: Optional[datetime],
    ) -> None:
        if external_refs:
            subscription.external_customer_ref = external_refs.get("customer")
            subscription.external_subscription_ref = external_refs.get("subscription")
        if event_at is not None:
            subscription.external_event_at = event_at
        subscription.updated_at = utcnow_naive()

    @staticmethod
    def _serialize(subscription: Subscription) -> dict:
        return subscription.to_dict()
