"""
Acceso a datos del módulo accounts.

Regla del proyecto, igual que en el resto de módulos: ``Repo(uow)`` para el
camino de escritura (dentro de un ``with UnitOfWork()``) y
``build_repository(Repo)`` para el de lectura.
"""

from typing import List, Optional

from src.modules.infrastructure import BaseRepository

from .model import Plan, PlanLimit, Subscription


class PlanRepository(BaseRepository[Plan]):
    """Acceso a datos del catálogo de planes."""

    _MODEL = Plan

    def get_by_code(self, code: str) -> Optional[Plan]:
        return self.get_by_field("code", code)

    def get_default(self) -> Optional[Plan]:
        """El plan que reciben las cuentas sin suscripción vigente.

        Devuelve ``None`` si el catálogo no se ha sembrado; quien llama decide
        si eso es un ``DefaultPlanMissingError``. Un índice único parcial
        garantiza que no haya dos.
        """
        return (
            self._session.query(Plan)
            .filter(Plan.is_default.is_(True))
            .one_or_none()
        )

    def get_public(self) -> List[Plan]:
        """Catálogo visible en la web, del más barato al más caro."""
        return (
            self._session.query(Plan)
            .filter(Plan.is_public.is_(True))
            .order_by(Plan.rank.asc())
            .all()
        )


class PlanLimitRepository(BaseRepository[PlanLimit]):
    """Acceso a datos de los topes de un plan."""

    _MODEL = PlanLimit

    def get_by_plan(self, plan_id: int) -> List[PlanLimit]:
        return self.get_children("plan_id", plan_id)

    def get_by_plan_and_scope(self, plan_id: int, scope: str) -> List[PlanLimit]:
        return (
            self._session.query(PlanLimit)
            .filter(PlanLimit.plan_id == plan_id, PlanLimit.scope == scope)
            .all()
        )


class SubscriptionRepository(BaseRepository[Subscription]):
    """Acceso a datos de las suscripciones."""

    _MODEL = Subscription

    def get_by_user(self, user_id: int) -> Optional[Subscription]:
        """La suscripción de un usuario, o ``None``.

        ``None`` es un resultado normal y frecuente, no un error: quien no
        tiene fila está en el plan por defecto.
        """
        return self.get_by_field("user_id", user_id)
