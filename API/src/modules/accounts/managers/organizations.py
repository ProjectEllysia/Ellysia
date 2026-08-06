"""
Gestión de organizaciones: un titular paga, sus miembros heredan derechos.

Lo que una organización comparte es **plan y factura**, nunca datos. Aquí no
hay ni una consulta a bóvedas, escaneos o análisis, y no debe haberla: Acheron
es zero-knowledge (el servidor solo ve cifrado) e Iris analiza correo personal.
El dueño ve la lista de miembros y el consumo agregado, y nada más.
"""

import logging
import re
from typing import Optional

from src.modules.infrastructure import UnitOfWork
from src.modules.infrastructure.session import build_repository, get_db_session
from src.modules.shared import utcnow_naive

from ..exceptions import (
    AlreadyInOrganizationError,
    CannotRemoveOwnerError,
    NotInOrganizationError,
    OrganizationAlreadyExistsError,
    OrganizationNotAllowedError,
)
from ..model import Organization, OrganizationMember
from ..repositories import (
    OrganizationMemberRepository,
    OrganizationRepository,
    SubscriptionRepository,
)
from ..services.entitlements import is_effective
from ..services.limits import LimitKey
from ..services.ownership import get_owned_organization
from ..services.quotas import QuotaManager

logger = logging.getLogger(__name__)


def _slugify(name: str) -> str:
    """Nombre legible en una URL. Sin pretensiones: minúsculas, guiones y ya."""
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower().strip()).strip("-")
    return slug or "organizacion"


class OrganizationManager:
    """Alta, consulta y bajas de una organización."""

    # ------------------------------------------------------------------ alta

    def create(self, user_id: int, name: str) -> dict:
        """Crea la organización de ``user_id``, que queda como su dueño.

        El dueño entra como miembro de la suya (``member_role='owner'``): así
        el recuento de miembros y la resolución de derechos no necesitan un
        caso especial, y el propio dueño consume de la bolsa común.

        Raises:
            OrganizationAlreadyExistsError: ya es dueño de una (409).
            AlreadyInOrganizationError: pertenece a la de otro (409).
            OrganizationNotAllowedError: su plan no trae el toggle (402).
        """
        self._assert_can_own_organization(user_id)

        if build_repository(OrganizationRepository).get_by_owner(user_id) is not None:
            raise OrganizationAlreadyExistsError()
        if build_repository(OrganizationMemberRepository).get_by_user(user_id) is not None:
            raise AlreadyInOrganizationError()

        # El tope de miembros del plan es la otra mitad del control: el toggle
        # dice "puedes tener organización" y esta clave dice "de cuánta gente".
        QuotaManager().consume(user_id, LimitKey.ORGANIZATION_MEMBERS)

        with UnitOfWork() as uow:
            organization = Organization(
                name=name.strip(),
                slug=self._unique_slug(uow, _slugify(name)),
                owner_user_id=user_id,
            )
            uow.session.add(organization)
            uow.session.flush()

            uow.session.add(OrganizationMember(
                organization_id=organization.id,
                user_id=user_id,
                member_role="owner",
            ))
            uow.session.flush()
            result = self._serialize(organization, members=1)

        logger.info(f"Organizacion '{result['slug']}' creada por el usuario {user_id}")
        return result

    def rename(self, organization_id: int, user_id: int, name: str) -> dict:
        """Cambia el nombre visible. El ``slug`` no se toca: ya está en enlaces."""
        get_owned_organization(user_id, organization_id)
        with UnitOfWork() as uow:
            organization = OrganizationRepository(uow).get_by_id(organization_id)
            organization.name = name.strip()
            organization.updated_at = utcnow_naive()
            uow.session.flush()
            return self._serialize(
                organization,
                members=OrganizationMemberRepository(uow).count_members(organization_id),
            )

    # -------------------------------------------------------------- consulta

    def get_mine(self, user_id: int) -> Optional[dict]:
        """La organización del usuario, sea dueño o miembro. ``None`` si ninguna."""
        membership = build_repository(OrganizationMemberRepository).get_by_user(user_id)
        if membership is None:
            return None

        organization = build_repository(OrganizationRepository).get_by_id(
            membership.organization_id
        )
        if organization is None:
            return None

        payload = self._serialize(
            organization,
            members=build_repository(OrganizationMemberRepository).count_members(organization.id),
        )
        payload["myRole"] = membership.member_role
        payload["isOwner"] = organization.owner_user_id == user_id
        return payload

    def list_members(self, organization_id: int, user_id: int) -> list[dict]:
        """Miembros de la organización, con lo justo para identificarlos.

        Datos de identidad y nada más: ni sus escaneos, ni sus análisis, ni el
        contenido de sus bóvedas. Eso no lo ve el dueño (§8.4 del diseño), y no
        es una carencia — es la garantía que se vende.
        """
        get_owned_organization(user_id, organization_id)

        # Import diferido: ``users`` acaba importando ``features``, que importa
        # este módulo. Al nivel de módulo sería un ciclo.
        from src.modules.users.model import User

        rows = (
            get_db_session()
            .query(OrganizationMember, User)
            .join(User, User.id == OrganizationMember.user_id)
            .filter(OrganizationMember.organization_id == organization_id)
            .order_by(OrganizationMember.joined_at.asc())
            .all()
        )
        return [
            {
                "userId":   member.user_id,
                "username": user.username,
                "email":    user.email,
                "fullName": f"{user.first_name} {user.last_name}".strip(),
                "role":     member.member_role,
                "joinedAt": member.joined_at,
            }
            for member, user in rows
        ]

    # ----------------------------------------------------------------- bajas

    def remove_member(self, organization_id: int, owner_user_id: int, member_user_id: int) -> None:
        """El dueño expulsa a un miembro.

        No se borra ni un dato del expulsado: conserva cuenta, bóveda, escaneos
        y su plan personal. Lo único que pierde son los derechos heredados, y
        lo que quede por encima de su plan personal entra en modo excedido —
        solo lectura hasta bajar del tope, nunca borrado.
        """
        organization = get_owned_organization(owner_user_id, organization_id)
        if member_user_id == organization.owner_user_id:
            raise CannotRemoveOwnerError()

        self._delete_membership(organization_id, member_user_id)
        logger.info(f"Usuario {member_user_id} expulsado de la organizacion {organization_id}")

    def leave(self, user_id: int) -> None:
        """Un miembro se sale por su cuenta. Mismas reglas que la expulsión."""
        membership = build_repository(OrganizationMemberRepository).get_by_user(user_id)
        if membership is None:
            raise NotInOrganizationError()
        if membership.member_role == "owner":
            raise CannotRemoveOwnerError()

        self._delete_membership(membership.organization_id, user_id)
        logger.info(f"Usuario {user_id} salio de la organizacion {membership.organization_id}")

    # ------------------------------------------------------------- internos

    @staticmethod
    def _assert_can_own_organization(user_id: int) -> None:
        """El toggle de organización, que es lo único que el plan sí "concede".

        No es un atributo ABAC a propósito: los atributos los escribe una
        persona y esto lo escribe el cobro (§5.1).
        """
        subscription = build_repository(SubscriptionRepository).get_by_user(user_id)
        if not is_effective(subscription, utcnow_naive()) or not subscription.organization_enabled:
            raise OrganizationNotAllowedError()

    @staticmethod
    def _unique_slug(uow: UnitOfWork, base: str) -> str:
        """``base``, o ``base-2``, ``base-3``… El slug es único en la tabla."""
        repo = OrganizationRepository(uow)
        if not repo.slug_exists(base):
            return base
        suffix = 2
        while repo.slug_exists(f"{base}-{suffix}"):
            suffix += 1
        return f"{base}-{suffix}"

    @staticmethod
    def _delete_membership(organization_id: int, user_id: int) -> None:
        with UnitOfWork() as uow:
            member_repo = OrganizationMemberRepository(uow)
            membership = member_repo.get_by_user(user_id)
            if membership is None or membership.organization_id != organization_id:
                raise NotInOrganizationError()
            member_repo.delete(membership)

    @staticmethod
    def _serialize(organization: Organization, members: int) -> dict:
        return {
            "id":          organization.id,
            "name":        organization.name,
            "slug":        organization.slug,
            "ownerUserId": organization.owner_user_id,
            "memberCount": members,
            "createdAt":   organization.created_at,
        }
