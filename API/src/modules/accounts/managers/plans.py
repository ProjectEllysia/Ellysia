"""
Lógica de negocio de la capa comercial.

En esta fase solo hay lectura: el catálogo de planes y el plan efectivo de
quien pregunta. Quien mueve suscripciones (``SubscriptionManager``, con las
seis operaciones del ciclo de vida) y quien cuenta el consumo
(``QuotaManager``) llegan en fases posteriores.
"""

import logging
from typing import Optional

from src.modules.infrastructure import UnitOfWork
from src.modules.infrastructure.session import build_repository
from src.modules.shared import utcnow_naive

from ..exceptions import (
    PlanCodeTakenError,
    PlanInUseError,
    PlanNotFoundError,
    UnknownLimitKeyError,
)
from ..model import Plan, PlanLimit, Subscription
from ..repositories import PlanLimitRepository, PlanRepository
from ..services.entitlements import is_effective, resolve_effective_plan
from ..services.limits import PERIODS, SCOPE_HOLDER, SCOPE_MEMBER, SCOPES, LimitKey
from ..services.quotas import QuotaManager

logger = logging.getLogger(__name__)


class PlanManager:
    """Consulta del catálogo y del plan efectivo de un usuario."""

    def list_public_plans(self) -> list[dict]:
        """Catálogo público, ordenado de menor a mayor ``rank``.

        Cada plan trae sus topes agrupados por ámbito, que es como los pinta la
        tabla de precios: ``holder`` es lo que se lleva quien contrata y
        ``member`` lo que se lleva cada empleado suyo.
        """
        plan_repository = build_repository(PlanRepository)
        limit_repository = build_repository(PlanLimitRepository)

        plans = []
        for plan in plan_repository.get_public():
            payload = plan.to_dict()
            payload["limits"] = self._group_limits_by_scope(
                limit_repository.get_by_plan(plan.id)
            )
            plans.append(payload)
        return plans

    def get_effective_plan(self, user_id: int) -> dict:
        """Plan que rige ahora mismo para ``user_id``, con su estado de vigencia.

        Se devuelven a la vez el plan aplicado y el estado de la suscripción
        **aunque no coincidan**: un usuario con Gold caducado recibe los topes
        de Freemium, pero la interfaz necesita saber que su Gold venció el día 1
        para poder explicárselo en vez de degradarlo en silencio.

        Los topes van sin contadores de consumo: eso es del motor de cuotas.
        """
        # Un solo instante para las dos preguntas: si se leyera el reloj dos
        # veces, una suscripción que vence justo ahora podría salir vigente en
        # una y caducada en la otra.
        now = utcnow_naive()
        plan, subscription = resolve_effective_plan(user_id, now)
        effective = is_effective(subscription, now)

        limit_repository = build_repository(PlanLimitRepository)

        return {
            "plan":                plan.to_dict(),
            "source":              "personal" if effective else "default",
            "status":              subscription.status if subscription else None,
            "isEffective":         effective,
            "currentPeriodEnd":    subscription.current_period_end if subscription else None,
            "cancelAtPeriodEnd":   bool(subscription.cancel_at_period_end) if subscription else False,
            "graceUntil":          subscription.grace_until if subscription else None,
            "organizationEnabled": bool(subscription.organization_enabled) if subscription else False,
            "limits":              self._flatten_limits(
                limit_repository.get_by_plan_and_scope(plan.id, SCOPE_HOLDER)
            ),
        }

    def get_usage(self, user_id: int) -> dict:
        """Consumo actual de ``user_id``, clave a clave.

        Solo se informa de las claves que el motor de cuotas sabe medir hoy: el
        resto llega con ``used: null``, que el cliente pinta como "sin datos" en
        vez de como un cero que sería mentira.

        ``exceeded`` marca las claves por encima del tope. Pasa sin que nadie
        haya hecho nada malo — al bajar de plan o al caducar una suscripción,
        unas existencias que eran legales dejan de serlo. Nunca se borra nada:
        la clave entra en solo lectura hasta volver por debajo.
        """
        plan, _ = resolve_effective_plan(user_id)
        quota_manager = QuotaManager()
        usage = {}

        for limit in build_repository(PlanLimitRepository).get_by_plan_and_scope(
            plan.id, SCOPE_HOLDER
        ):
            entry = {"value": limit.value, "period": limit.period,
                     "used": None, "resetsAt": None, "exceeded": False}
            try:
                key = LimitKey(limit.limit_key)
                state = quota_manager.state(user_id, key)
            except (ValueError, NotImplementedError):
                # ValueError: la fila referencia una clave que ya no existe en
                # el enum. NotImplementedError: es de existencias y todavía no
                # tiene contador (llegan en la fase 3). Ninguna de las dos es
                # motivo para tumbar la vista entera.
                usage[limit.limit_key] = entry
                continue

            entry.update({
                "used":     state.used,
                "resetsAt": state.resets_at,
                "exceeded": state.exceeded,
            })
            usage[limit.limit_key] = entry

        return {"planCode": plan.code, "usage": usage}

    # ------------------------------------------------------- gestor (root)

    def create_plan(self, data: dict) -> dict:
        """Alta de un plan en el catálogo.

        Nace **sin topes**: todas sus claves se leen como 0 hasta que alguien
        las rellene. Es el fallo cerrado de siempre — un plan a medio configurar
        no regala nada.
        """
        with UnitOfWork() as uow:
            repo = PlanRepository(uow)
            if repo.get_by_code(data["code"]) is not None:
                raise PlanCodeTakenError(data["code"])

            plan = Plan(**data)
            uow.session.add(plan)
            uow.session.flush()
            payload = plan.to_dict()

        logger.info(f"Plan '{payload['code']}' creado")
        return payload

    def update_plan(self, plan_id: int, data: dict) -> dict:
        """Edita los metadatos de un plan. El ``code`` no se toca.

        Cambiarlo rompería las asignaciones que lo nombran (y, el día de la
        pasarela, la correspondencia con lo que ella tenga guardado). Si hace
        falta otro código, es otro plan.
        """
        with UnitOfWork() as uow:
            repo = PlanRepository(uow)
            plan = repo.get_by_id(plan_id)
            if plan is None:
                raise PlanNotFoundError(plan_id)

            for field, value in data.items():
                setattr(plan, field, value)
            plan.updated_at = utcnow_naive()
            repo.update(plan)
            return plan.to_dict()

    def set_default_plan(self, plan_id: int) -> dict:
        """Marca un plan como el de por defecto, quitándoselo al anterior.

        Los dos cambios van en la misma transacción porque un índice único
        parcial impide que haya dos: quitar primero y poner después no es una
        cortesía, es la única forma de que no falle.
        """
        with UnitOfWork() as uow:
            repo = PlanRepository(uow)
            plan = repo.get_by_id(plan_id)
            if plan is None:
                raise PlanNotFoundError(plan_id)

            current = repo.get_default()
            if current is not None and current.id != plan_id:
                current.is_default = False
                uow.session.flush()

            plan.is_default = True
            plan.updated_at = utcnow_naive()
            repo.update(plan)
            logger.info(f"Plan por defecto: '{plan.code}'")
            return plan.to_dict()

    def replace_limits(self, plan_id: int, limits: list[dict]) -> dict:
        """Reemplaza **todos** los topes de un plan.

        Reemplazar y no parchear: así lo que se ve en el panel es exactamente lo
        que queda guardado, y una clave que se borra de la lista desaparece de
        verdad en vez de quedarse con su valor viejo.

        Cada clave se valida contra ``LimitKey``: una errata crearía una fila
        que nadie consulta y dejaría la característica desactivada en silencio.
        """
        with UnitOfWork() as uow:
            plan = PlanRepository(uow).get_by_id(plan_id)
            if plan is None:
                raise PlanNotFoundError(plan_id)

            rows = [self._validated_limit(plan_id, limit) for limit in limits]

            uow.session.query(PlanLimit).filter(
                PlanLimit.plan_id == plan_id
            ).delete(synchronize_session=False)
            uow.session.add_all(rows)
            uow.session.flush()

            logger.info(f"Topes del plan '{plan.code}' reemplazados ({len(rows)} claves)")
            return {
                "planCode": plan.code,
                "limits": self._group_limits_by_scope(rows),
            }

    def delete_plan(self, plan_id: int) -> None:
        """Borra un plan del catálogo.

        Se niega si alguien lo tiene contratado o si es el de por defecto:
        dejar cuentas apuntando a un plan inexistente convertiría cada lectura
        de sus derechos en un error.
        """
        with UnitOfWork() as uow:
            repo = PlanRepository(uow)
            plan = repo.get_by_id(plan_id)
            if plan is None:
                raise PlanNotFoundError(plan_id)
            if plan.is_default:
                raise PlanInUseError(plan.code, reason="es el plan por defecto")

            live = uow.session.query(Subscription).filter(
                Subscription.plan_id == plan_id
            ).count()
            if live:
                raise PlanInUseError(plan.code, reason=f"lo tienen {live} cuenta(s)")

            repo.delete(plan)
            logger.info(f"Plan '{plan.code}' eliminado")

    @staticmethod
    def _validated_limit(plan_id: int, limit: dict) -> PlanLimit:
        try:
            key = LimitKey(limit["limitKey"])
        except ValueError as exc:
            raise UnknownLimitKeyError(limit["limitKey"]) from exc

        scope = limit.get("scope", SCOPE_HOLDER)
        if scope not in SCOPES:
            raise UnknownLimitKeyError(scope)

        return PlanLimit(
            plan_id=plan_id,
            limit_key=key.db_name,
            scope=scope,
            value=limit.get("value"),
            # El periodo lo manda el catálogo de claves, no el formulario: si lo
            # eligiera quien rellena, un contador mensual podría acabar
            # declarado como existencias.
            period=PERIODS[key].value,
        )

    def get_plan_by_code(self, code: str) -> Optional[Plan]:
        """Búsqueda por código, para quien asigne planes en fases posteriores."""
        return build_repository(PlanRepository).get_by_code(code)

    # ---------------------------------------------------------------- helpers

    @staticmethod
    def _group_limits_by_scope(limits) -> dict:
        """{'holder': {clave: {...}}, 'member': {clave: {...}}}

        Los dos ámbitos aparecen siempre, aunque vengan vacíos: así el cliente
        no tiene que distinguir "sin límites de miembro" de "campo ausente".
        """
        grouped: dict[str, dict] = {SCOPE_HOLDER: {}, SCOPE_MEMBER: {}}
        for limit in limits:
            grouped.setdefault(limit.scope, {})[limit.limit_key] = {
                "value":  limit.value,
                "period": limit.period,
            }
        return grouped

    @staticmethod
    def _flatten_limits(limits) -> dict:
        """{clave: {'value': n|None, 'period': '...'}} para un solo ámbito."""
        return {
            limit.limit_key: {"value": limit.value, "period": limit.period}
            for limit in limits
        }
