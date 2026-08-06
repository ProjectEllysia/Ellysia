"""
Endpoints del catálogo de planes.

Dos rutas en esta fase, ninguna de ellas gateada por ABAC:

- ``GET /plans`` es **público** — es la tabla de precios de la web, la ve quien
  todavía no tiene cuenta.
- ``GET /plans/me`` solo pide sesión: consultar tu propio plan no es una
  capacidad que un administrador conceda o retire.

El gestor del catálogo (alta y edición de planes) llega en una fase posterior y
va con ``require_role(Role.ROOT)``, no con atributos.
"""

import logging

from flask_smorest import Blueprint as SmorestBlueprint

from src.modules.shared import handle_exceptions, limiter
from src.modules.shared.schemas import ErrorSchema, SuccessMessageSchema
from src.modules.users import require_oauth_token, get_current_user

from .exceptions import AccountsError, NotInOrganizationError
from .managers import InvitationManager, OrganizationManager, PlanManager
from .services.ownership import require_organization_owner
from .schemas import (
    EffectivePlanResponseSchema,
    OrganizationCreateRequestSchema,
    OrganizationMemberListSchema,
    InvitationAcceptRequestSchema,
    InvitationAcceptResponseSchema,
    InvitationCreateRequestSchema,
    InvitationListSchema,
    InvitationSchema,
    OrganizationSchema,
    PlanCatalogResponseSchema,
    UsageResponseSchema,
)


plans_blp = SmorestBlueprint(
    "plans", __name__,
    description="Catalogo de planes y plan efectivo de cada cuenta",
)
logger = logging.getLogger(__name__)


@plans_blp.get("")
@plans_blp.response(200, PlanCatalogResponseSchema, description="Public plan catalog")
@limiter.limit("120 per hour")
@handle_exceptions(default_exception=AccountsError, logger=logger)
def list_plans():
    """Listar el catalogo publico de planes con sus limites"""
    return {"plans": PlanManager().list_public_plans()}


@plans_blp.get("/me")
@plans_blp.response(200, EffectivePlanResponseSchema, description="Effective plan")
@plans_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@limiter.limit("300 per hour")
@require_oauth_token
@handle_exceptions(default_exception=AccountsError, logger=logger)
def get_my_plan():
    """Consultar el plan efectivo del usuario autenticado y su vigencia"""
    return PlanManager().get_effective_plan(get_current_user().id)


@plans_blp.get("/me/usage")
@plans_blp.response(200, UsageResponseSchema, description="Current usage per limit key")
@plans_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@limiter.limit("300 per hour")
@require_oauth_token
@handle_exceptions(default_exception=AccountsError, logger=logger)
def get_my_usage():
    """Consultar el consumo actual del usuario autenticado, clave a clave"""
    return PlanManager().get_usage(get_current_user().id)


# =========================================================================
# ORGANIZACIONES
# =========================================================================

organizations_blp = SmorestBlueprint(
    "organizations", __name__,
    description="Organizaciones: un titular paga y sus miembros heredan derechos",
)


@organizations_blp.post("")
@organizations_blp.arguments(OrganizationCreateRequestSchema)
@organizations_blp.response(201, OrganizationSchema, description="Organization created")
@organizations_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@organizations_blp.alt_response(402, schema=ErrorSchema, description="Plan has no organization addon")
@organizations_blp.alt_response(409, schema=ErrorSchema, description="Already owns or belongs to one")
@limiter.limit("10 per hour")
@require_oauth_token
@handle_exceptions(default_exception=AccountsError, logger=logger)
def create_organization(data):
    """Crear la organizacion del usuario autenticado, que queda como duenyo"""
    organization = OrganizationManager().create(get_current_user().id, data["name"])
    logger.info(f"Organizacion creada: {organization['slug']}")
    return organization, 201


@organizations_blp.get("/mine")
@organizations_blp.response(200, OrganizationSchema, description="The user's organization")
@organizations_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@organizations_blp.alt_response(404, schema=ErrorSchema, description="Not in any organization")
@limiter.limit("120 per hour")
@require_oauth_token
@handle_exceptions(default_exception=AccountsError, logger=logger)
def get_my_organization():
    """La organizacion del usuario, sea duenyo o miembro"""
    organization = OrganizationManager().get_mine(get_current_user().id)
    if organization is None:
        raise NotInOrganizationError()
    return organization


@organizations_blp.put("/<int:organization_id>")
@organizations_blp.arguments(OrganizationCreateRequestSchema)
@organizations_blp.response(200, OrganizationSchema, description="Organization renamed")
@organizations_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@organizations_blp.alt_response(404, schema=ErrorSchema, description="Not found or not yours")
@limiter.limit("20 per hour")
@require_oauth_token
@require_organization_owner
@handle_exceptions(default_exception=AccountsError, logger=logger)
def rename_organization(data, organization_id: int):
    """Cambiar el nombre visible de la organizacion"""
    return OrganizationManager().rename(organization_id, get_current_user().id, data["name"])


@organizations_blp.get("/<int:organization_id>/members")
@organizations_blp.response(200, OrganizationMemberListSchema, description="Members")
@organizations_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@organizations_blp.alt_response(404, schema=ErrorSchema, description="Not found or not yours")
@limiter.limit("120 per hour")
@require_oauth_token
@require_organization_owner
@handle_exceptions(default_exception=AccountsError, logger=logger)
def list_organization_members(organization_id: int):
    """Listar los miembros: identidad y nada mas, nunca sus datos"""
    members = OrganizationManager().list_members(organization_id, get_current_user().id)
    return {"members": members}


@organizations_blp.delete("/<int:organization_id>/members/<int:member_user_id>")
@organizations_blp.response(200, SuccessMessageSchema, description="Member removed")
@organizations_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@organizations_blp.alt_response(404, schema=ErrorSchema, description="Not found or not yours")
@organizations_blp.alt_response(409, schema=ErrorSchema, description="Cannot remove the owner")
@limiter.limit("60 per hour")
@require_oauth_token
@require_organization_owner
@handle_exceptions(default_exception=AccountsError, logger=logger)
def remove_organization_member(organization_id: int, member_user_id: int):
    """Expulsar a un miembro. No se borra ni un dato suyo."""
    OrganizationManager().remove_member(organization_id, get_current_user().id, member_user_id)
    return {"message": "Miembro expulsado de la organizacion"}


@organizations_blp.delete("/mine")
@organizations_blp.response(200, SuccessMessageSchema, description="Left the organization")
@organizations_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@organizations_blp.alt_response(404, schema=ErrorSchema, description="Not in any organization")
@organizations_blp.alt_response(409, schema=ErrorSchema, description="The owner cannot leave")
@limiter.limit("10 per hour")
@require_oauth_token
@handle_exceptions(default_exception=AccountsError, logger=logger)
def leave_my_organization():
    """Salir de la organizacion. Conservas cuenta, datos y plan personal."""
    OrganizationManager().leave(get_current_user().id)
    return {"message": "Has salido de la organizacion"}


@organizations_blp.post("/<int:organization_id>/invitations")
@organizations_blp.arguments(InvitationCreateRequestSchema)
@organizations_blp.response(201, InvitationSchema, description="Invitation sent")
@organizations_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@organizations_blp.alt_response(402, schema=ErrorSchema, description="Subscription not current, or member cap reached")
@organizations_blp.alt_response(404, schema=ErrorSchema, description="Not found or not yours")
@organizations_blp.alt_response(409, schema=ErrorSchema, description="Already in an organization")
@limiter.limit("60 per hour")
@require_oauth_token
@require_organization_owner
@handle_exceptions(default_exception=AccountsError, logger=logger)
def invite_to_organization(data, organization_id: int):
    """Invitar a alguien. Si ya tiene cuenta se le pide permiso; si no, se le crea."""
    invitation = InvitationManager().invite(
        organization_id, get_current_user().id, data["email"],
    )
    return invitation, 201


@organizations_blp.get("/<int:organization_id>/invitations")
@organizations_blp.response(200, InvitationListSchema, description="Invitations")
@organizations_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@organizations_blp.alt_response(404, schema=ErrorSchema, description="Not found or not yours")
@limiter.limit("120 per hour")
@require_oauth_token
@require_organization_owner
@handle_exceptions(default_exception=AccountsError, logger=logger)
def list_organization_invitations(organization_id: int):
    """Listar las invitaciones de la organizacion"""
    invitations = InvitationManager().list_invitations(organization_id, get_current_user().id)
    return {"invitations": invitations}


@organizations_blp.delete("/invitations/<int:invitation_id>")
@organizations_blp.response(200, SuccessMessageSchema, description="Invitation revoked")
@organizations_blp.alt_response(400, schema=ErrorSchema, description="Unknown invitation")
@organizations_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@organizations_blp.alt_response(404, schema=ErrorSchema, description="Not yours")
@limiter.limit("60 per hour")
@require_oauth_token
@handle_exceptions(default_exception=AccountsError, logger=logger)
def revoke_organization_invitation(invitation_id: int):
    """Retirar una invitacion sin responder"""
    InvitationManager().revoke(invitation_id, get_current_user().id)
    return {"message": "Invitacion revocada"}


@organizations_blp.post("/invitations/accept")
@organizations_blp.arguments(InvitationAcceptRequestSchema)
@organizations_blp.response(200, InvitationAcceptResponseSchema, description="Invitation accepted")
@organizations_blp.alt_response(400, schema=ErrorSchema, description="Invalid or expired invitation")
@organizations_blp.alt_response(409, schema=ErrorSchema, description="Already in an organization")
@limiter.limit("20 per hour")
@handle_exceptions(default_exception=AccountsError, logger=logger)
def accept_organization_invitation(data):
    """Aceptar una invitacion.

    Publico: el token es la unica identidad, igual que en la verificacion de
    correo. Aceptar NO cambia el plan personal de quien acepta — los derechos de
    la organizacion se suman a los suyos.
    """
    result = InvitationManager().accept(data["token"])
    return {
        "message": "Te has unido a la organizacion. Tu plan personal no cambia.",
        "organizationId": result["organizationId"],
    }
