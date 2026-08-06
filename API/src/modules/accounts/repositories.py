"""
Acceso a datos del módulo accounts.

Regla del proyecto, igual que en el resto de módulos: ``Repo(uow)`` para el
camino de escritura (dentro de un ``with UnitOfWork()``) y
``build_repository(Repo)`` para el de lectura.
"""

from typing import List, Optional

from src.modules.infrastructure import BaseRepository

from .model import (
    Organization,
    OrganizationInvitation,
    OrganizationMember,
    Plan,
    PlanLimit,
    Subscription,
)


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

    def get_one(self, plan_id: int, limit_key: str, scope: str) -> Optional[PlanLimit]:
        """Un tope concreto, o ``None`` si el plan no lo declara.

        ``None`` no significa "ilimitado": quien llama lo lee como 0 (no
        incluido). Es el fallo cerrado del catálogo.
        """
        return (
            self._session.query(PlanLimit)
            .filter(
                PlanLimit.plan_id == plan_id,
                PlanLimit.limit_key == limit_key,
                PlanLimit.scope == scope,
            )
            .one_or_none()
        )


class OrganizationRepository(BaseRepository[Organization]):
    """Acceso a datos de las organizaciones."""

    _MODEL = Organization

    def get_by_owner(self, user_id: int) -> Optional[Organization]:
        return self.get_by_field("owner_user_id", user_id)

    def get_by_slug(self, slug: str) -> Optional[Organization]:
        return self.get_by_field("slug", slug)

    def slug_exists(self, slug: str) -> bool:
        return self.exists("slug", slug)


class OrganizationMemberRepository(BaseRepository[OrganizationMember]):
    """Acceso a datos de la pertenencia a una organización."""

    _MODEL = OrganizationMember

    def get_by_user(self, user_id: int) -> Optional[OrganizationMember]:
        """La pertenencia de un usuario, o ``None``.

        Devuelve una y no una lista porque ``user_id`` es ``UNIQUE``: un
        usuario pertenece a lo sumo a una organización, y lo impone la base de
        datos.
        """
        return self.get_by_field("user_id", user_id)

    def get_by_organization(self, organization_id: int) -> List[OrganizationMember]:
        return (
            self._session.query(OrganizationMember)
            .filter(OrganizationMember.organization_id == organization_id)
            .order_by(OrganizationMember.joined_at.asc())
            .all()
        )

    def user_ids_of(self, organization_id: int) -> List[int]:
        """Ids de los miembros. Es lo que necesitan los contadores de la bolsa
        común, que suman las existencias de todos."""
        rows = (
            self._session.query(OrganizationMember.user_id)
            .filter(OrganizationMember.organization_id == organization_id)
            .all()
        )
        return [row[0] for row in rows]

    def count_members(self, organization_id: int) -> int:
        return (
            self._session.query(OrganizationMember)
            .filter(OrganizationMember.organization_id == organization_id)
            .count()
        )


class OrganizationInvitationRepository(BaseRepository[OrganizationInvitation]):
    """Acceso a datos de las invitaciones."""

    _MODEL = OrganizationInvitation

    def get_by_token_hash(self, token_hash: str) -> Optional[OrganizationInvitation]:
        return self.get_by_field("token_hash", token_hash)

    def get_by_organization(self, organization_id: int) -> List[OrganizationInvitation]:
        return (
            self._session.query(OrganizationInvitation)
            .filter(OrganizationInvitation.organization_id == organization_id)
            .order_by(OrganizationInvitation.created_at.desc())
            .all()
        )

    def get_pending_for_email(self, organization_id: int, email: str) -> Optional[OrganizationInvitation]:
        return (
            self._session.query(OrganizationInvitation)
            .filter(
                OrganizationInvitation.organization_id == organization_id,
                OrganizationInvitation.email == email,
                OrganizationInvitation.status == "pending",
            )
            .first()
        )

    def count_pending(self, organization_id: int) -> int:
        """Invitaciones sin responder.

        Cuentan para el tope de miembros: si no, se invitaría a 300 personas
        con un plan de 20 y el tope no serviría de nada.
        """
        return (
            self._session.query(OrganizationInvitation)
            .filter(
                OrganizationInvitation.organization_id == organization_id,
                OrganizationInvitation.status == "pending",
            )
            .count()
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
