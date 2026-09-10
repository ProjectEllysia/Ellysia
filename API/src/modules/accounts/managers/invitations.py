"""
Invitaciones a una organización.

Dos caminos, y la diferencia entre ellos es de consentimiento:

- **El correo ya tiene cuenta en Ellysia** → invitación pendiente y un enlace.
  Hasta que acepta no cambia absolutamente nada: ni organización, ni plan, ni
  derechos. Un tercero no puede cambiarle a alguien su contexto sin permiso.
- **El correo no tiene cuenta** → se crea, con contraseña aleatoria, y entra
  directa. Aquí no hay consentimiento que pedir porque no había nadie a quien
  pedírselo; el dueño de la organización responde por esa dirección.

Aceptar una invitación **nunca cambia el plan personal** de quien acepta. Los
derechos de la organización se suman a los suyos por ``max()``; si tenía un
Bronze pagado, sigue teniéndolo, y se lo lleva intacto si algún día se va.
"""

import logging
import secrets
from datetime import timedelta
from typing import Optional

import src.modules.system.config_reading as CR
from src.modules.infrastructure import UnitOfWork
from src.modules.infrastructure.session import build_repository
from src.modules.shared import utcnow_naive
from src.modules.tools.herald import EmailMessage, build_mailer, render_email

from ..exceptions import (
    AlreadyInOrganizationError,
    InvitationInvalidError,
    OrganizationNotAllowedError,
)
from ..model import OrganizationInvitation, OrganizationMember
from ..repositories import (
    OrganizationInvitationRepository,
    OrganizationMemberRepository,
    SubscriptionRepository,
)
from ..services.entitlements import is_effective
from ..services.limits import LimitKey
from ..services.ownership import get_owned_organization
from ..services.quotas import QuotaManager

logger = logging.getLogger(__name__)


class InvitationManager:
    """Emisión, aceptación y revocación de invitaciones."""

    # ------------------------------------------------------------- emisión

    def invite(self, organization_id: int, owner_user_id: int, email: str) -> dict:
        """Invita a ``email`` a la organización.

        Raises:
            OrganizationNotAllowedError: la suscripción del dueño no está
                vigente o perdió el toggle. Mientras no paga no puede crecer
                — lo que ya tiene sigue en pie, pero no suma gente.
            AlreadyInOrganizationError: esa persona ya está en una organización.
            QuotaExceededError: se alcanzó el tope de miembros del plan.
        """
        organization = get_owned_organization(owner_user_id, organization_id)
        self._assert_owner_can_grow(organization.owner_user_id)

        email = email.strip().lower()
        existing_user = self._find_user_by_email(email)

        if existing_user is not None:
            self._assert_not_in_an_organization(existing_user["id"])

        # El tope cuenta miembros MÁS invitaciones pendientes: si solo contara
        # miembros, se invitaría a 300 personas con un plan de 20 y bastaría con
        # que fueran aceptando.
        QuotaManager().consume(owner_user_id, LimitKey.ORGANIZATION_MEMBERS)

        if existing_user is None:
            return self._invite_new_account(organization, owner_user_id, email)
        return self._invite_existing_account(organization, owner_user_id, email, existing_user)

    def list_invitations(self, organization_id: int, owner_user_id: int) -> list[dict]:
        get_owned_organization(owner_user_id, organization_id)
        repo = build_repository(OrganizationInvitationRepository)
        return [self._serialize(invitation) for invitation in repo.get_by_organization(organization_id)]

    def revoke(self, invitation_id: int, owner_user_id: int) -> None:
        """Retira una invitación sin responder. El enlace deja de valer."""
        with UnitOfWork() as uow:
            repo = OrganizationInvitationRepository(uow)
            invitation = repo.get_by_id(invitation_id)
            if invitation is None:
                raise InvitationInvalidError()
            get_owned_organization(owner_user_id, invitation.organization_id)

            # El hash se queda: la columna es NOT NULL y no hace falta borrarlo
            # para invalidar el enlace — accept() exige status == 'pending', que
            # es la única puerta.
            invitation.status = "revoked"
            repo.update(invitation)

    # ---------------------------------------------------------- aceptación

    def accept(self, token: str) -> dict:
        """Acepta una invitación y crea la pertenencia.

        Público: el token es la única identidad, igual que en el quiz de Aegis
        o en la verificación de correo. Quien pulsa el enlace puede no tener la
        sesión abierta.

        Lo que **no** hace: tocar el plan personal de quien acepta. Los derechos
        de la organización se resuelven al leer, sumándose por ``max()``.
        """
        from src.modules.users.services.secrets import hash_opaque_token

        with UnitOfWork() as uow:
            repo = OrganizationInvitationRepository(uow)
            invitation = repo.get_by_token_hash(hash_opaque_token(token))

            if invitation is None or invitation.status != "pending":
                raise InvitationInvalidError()
            if utcnow_naive() >= invitation.expires_at:
                invitation.status = "expired"
                repo.update(invitation)
                raise InvitationInvalidError()

            user = self._find_user_by_email(invitation.email)
            if user is None:
                raise InvitationInvalidError()
            self._assert_not_in_an_organization(user["id"])

            uow.session.add(OrganizationMember(
                organization_id=invitation.organization_id,
                user_id=user["id"],
                member_role="member",
                invited_by_user_id=invitation.invited_by_user_id,
            ))
            invitation.status = "accepted"
            invitation.accepted_at = utcnow_naive()
            repo.update(invitation)
            uow.session.flush()

            logger.info(
                f"Usuario {user['id']} acepto la invitacion a la organizacion "
                f"{invitation.organization_id}"
            )
            return {"organizationId": invitation.organization_id, "userId": user["id"]}

    # ------------------------------------------------------------ internos

    def _invite_existing_account(
        self, organization, owner_user_id: int, email: str, user: dict,
    ) -> dict:
        """Cuenta existente: invitación pendiente. No cambia nada hasta aceptar."""
        from src.modules.users.services.secrets import generate_opaque_token, hash_opaque_token

        token = generate_opaque_token()
        ttl_hours = CR.registration_config().invitation_ttl_hours

        with UnitOfWork() as uow:
            invitation = OrganizationInvitation(
                organization_id=organization.id,
                email=email,
                token_hash=hash_opaque_token(token),
                status="pending",
                invited_by_user_id=owner_user_id,
                expires_at=utcnow_naive() + timedelta(hours=ttl_hours),
            )
            uow.session.add(invitation)
            uow.session.flush()
            payload = self._serialize(invitation)

        self._send_invitation_email(email, user["first_name"], organization.name, token, ttl_hours)
        logger.info(f"Invitacion enviada a {email} para la organizacion {organization.id}")
        return payload

    def _invite_new_account(self, organization, owner_user_id: int, email: str) -> dict:
        """Sin cuenta: se crea y entra directa.

        El correo se da por verificado: responde de él quien invita. Y la
        contraseña es aleatoria, con ``must_change_password`` puesto, porque ha
        viajado por correo y no sirve como secreto a largo plazo.
        """
        from src.modules.users.managers import UserManager
        from src.modules.users.services.secrets import hash_opaque_token

        password = secrets.token_urlsafe(12)
        username = self._available_username(email)

        user = UserManager().sign_in_user(
            username=username,
            email=email,
            first_name=email.split("@")[0],
            last_name="",
            password=password,
            email_verified=True,
        )

        from src.modules.users.repositories import UserRepository

        with UnitOfWork() as uow:
            repo = UserRepository(uow)
            created = repo.get_by_id(user.id)
            created.must_change_password = True
            repo.update(created)

            uow.session.add(OrganizationMember(
                organization_id=organization.id,
                user_id=user.id,
                member_role="member",
                invited_by_user_id=owner_user_id,
            ))
            invitation = OrganizationInvitation(
                organization_id=organization.id,
                email=email,
                # No hay enlace que emitir: la cuenta ya está dentro. Se guarda
                # un hash irrepetible solo porque la columna es NOT NULL y
                # UNIQUE; no corresponde a ningún token vivo.
                token_hash=hash_opaque_token(secrets.token_urlsafe(32)),
                status="accepted",
                invited_by_user_id=owner_user_id,
                created_user_id=user.id,
                expires_at=utcnow_naive(),
                accepted_at=utcnow_naive(),
            )
            uow.session.add(invitation)
            uow.session.flush()
            payload = self._serialize(invitation)

        self._send_credentials_email(email, organization.name, username, password)
        logger.info(f"Cuenta creada por invitacion para {email} (organizacion {organization.id})")
        return payload

    @staticmethod
    def _assert_owner_can_grow(owner_user_id: int) -> None:
        subscription = build_repository(SubscriptionRepository).get_by_user(owner_user_id)
        if not is_effective(subscription, utcnow_naive()) or not subscription.organization_enabled:
            raise OrganizationNotAllowedError()

    @staticmethod
    def _assert_not_in_an_organization(user_id: int) -> None:
        if build_repository(OrganizationMemberRepository).get_by_user(user_id) is not None:
            raise AlreadyInOrganizationError()

    @staticmethod
    def _find_user_by_email(email: str) -> Optional[dict]:
        """Datos planos del usuario con ese correo, o ``None``.

        Se devuelve un dict y no la entidad: fuera del UnitOfWork quedaría
        desligada de su sesión.
        """
        from src.modules.users.repositories import UserRepository

        found = build_repository(UserRepository).get_by_field("email", email)
        if found is None:
            return None
        return {"id": found.id, "first_name": found.first_name, "username": found.username}

    @staticmethod
    def _available_username(email: str) -> str:
        """Un nombre de usuario libre a partir del correo."""
        from src.modules.users.repositories import UserRepository

        base = "".join(char for char in email.split("@")[0].lower() if char.isalnum()) or "usuario"
        repo = build_repository(UserRepository)
        if not repo.username_exists(base):
            return base
        suffix = 2
        while repo.username_exists(f"{base}{suffix}"):
            suffix += 1
        return f"{base}{suffix}"

    @staticmethod
    def _send_invitation_email(
        email: str, name: str, organization_name: str, token: str, ttl_hours: int,
    ) -> None:
        accept_url = f"{CR.general_config().public_url}/invitacion?token={token}"
        try:
            html, text = render_email(
                "org_invitation",
                recipient_name=name,
                organization_name=organization_name,
                accept_url=accept_url,
                ttl_hours=ttl_hours,
            )
            build_mailer("accounts").send(EmailMessage(
                to=email, to_name=name,
                subject=f"Te han invitado a {organization_name} en Ellysia",
                html_body=html, text_body=text,
            ))
        except Exception as exc:  # pylint: disable=broad-except
            logger.error(f"No se pudo enviar la invitacion a {email}: {exc}")

    @staticmethod
    def _send_credentials_email(
        email: str, organization_name: str, username: str, password: str,
    ) -> None:
        login_url = f"{CR.general_config().public_url}/login"
        try:
            html, text = render_email(
                "org_credentials",
                organization_name=organization_name,
                username=username,
                password=password,
                login_url=login_url,
            )
            build_mailer("accounts").send(EmailMessage(
                to=email,
                subject=f"Tu cuenta en Ellysia ({organization_name})",
                html_body=html, text_body=text,
            ))
        except Exception as exc:  # pylint: disable=broad-except
            logger.error(f"No se pudieron enviar las credenciales a {email}: {exc}")

    @staticmethod
    def _serialize(invitation: OrganizationInvitation) -> dict:
        return {
            "id":             invitation.id,
            "email":          invitation.email,
            "status":         invitation.status,
            "createdAt":      invitation.created_at,
            "expiresAt":      invitation.expires_at,
            "acceptedAt":     invitation.accepted_at,
            "createdUserId":  invitation.created_user_id,
        }
