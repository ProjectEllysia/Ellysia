"""
Endpoints de planes, organizaciones y suscripciones.

Cuatro grupos de rutas, ninguna gateada por ABAC:

- ``GET /plans`` es **público** — es la tabla de precios de la web, la ve quien
  todavía no tiene cuenta. ``GET /plans/me`` y ``/me/usage`` solo piden sesión:
  consultar tu propio plan y tu consumo no es una capacidad que un
  administrador conceda o retire.
- ``/organizations/*`` cubre la creación, la gestión de miembros y las
  invitaciones. Cada ruta que actúa sobre una organización concreta exige
  además ``require_organization_owner``.
- ``/plans/subscriptions/<user_id>`` es el ciclo de vida de una suscripción —
  el mismo puerto que usará la pasarela de pago el día que se enchufe, hoy
  operado a mano por root.
- El resto (``/plans/all``, ``/plans/limit-keys``, alta/edición/borrado de
  planes y sus límites) es el gestor del catálogo. Va con
  ``require_role(Role.ROOT)``, no con atributos.
"""

import logging

from flask_smorest import Blueprint as SmorestBlueprint

from src.modules.infrastructure.session import build_repository
from src.modules.shared import handle_exceptions, limiter
from src.modules.shared.schemas import ErrorSchema, SuccessMessageSchema
from src.modules.users import require_oauth_token, require_role, get_current_user
# Role no está entre lo que re-exporta el paquete users, y pedírselo al paquete
# durante su propia inicialización rompe el ciclo. El submódulo sí está cargado.
from src.modules.users.services.permissions import Role

from .exceptions import AccountsError
from .managers import (
    InvitationManager,
    OrganizationManager,
    PlanManager,
    SubscriptionManager,
)
from .repositories import SubscriptionRepository
from .services.limits import PERIODS, LimitKey
from .services.ownership import require_organization_owner
from .schemas import (
    LimitCatalogResponseSchema,
    PlanLimitsResponseSchema,
    PlanLimitsWriteSchema,
    PlanSummarySchema,
    PlanUpdateSchema,
    PlanWriteSchema,
    SubscriptionOperationSchema,
    SubscriptionStateSchema,
    SubscriptionSchema,
    EffectivePlanResponseSchema,
    OrganizationCreateRequestSchema,
    MyOrganizationResponseSchema,
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
@organizations_blp.response(200, MyOrganizationResponseSchema, description="Membership state")
@organizations_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@limiter.limit("120 per hour")
@require_oauth_token
@handle_exceptions(default_exception=AccountsError, logger=logger)
def get_my_organization():
    """La organizacion del usuario, sea duenyo o miembro. null si no tiene.

    200 y no 404: no pertenecer a ninguna es un estado normal, no un recurso
    que falte. Ademas lo pregunta cada carga de sesion, y un 404 llenaba de
    rojo la consola del navegador a la mayoria de las cuentas.
    """
    return {"organization": OrganizationManager().get_mine(get_current_user().id)}


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


# =========================================================================
# CICLO DE VIDA (root) — el mismo puerto que usara la pasarela
# =========================================================================


@plans_blp.get("/subscriptions/<int:user_id>")
@plans_blp.response(200, SubscriptionStateSchema, description="Subscription state")
@plans_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@plans_blp.alt_response(403, schema=ErrorSchema, description="Insufficient role")
@limiter.limit("120 per hour")
@require_oauth_token
@require_role(Role.ROOT)
@handle_exceptions(default_exception=AccountsError, logger=logger)
def get_user_subscription(user_id: int):
    """Consultar la suscripcion de un usuario. null si no tiene ninguna.

    El gestor pregunta esto nada mas elegir una cuenta, y no tener suscripcion
    es lo normal — significa que esta en el plan por defecto.
    """
    subscription = build_repository(SubscriptionRepository).get_by_user(user_id)
    return {"subscription": subscription.to_dict() if subscription else None}


@plans_blp.put("/subscriptions/<int:user_id>")
@plans_blp.arguments(SubscriptionOperationSchema)
@plans_blp.response(200, SubscriptionSchema, description="Operation applied")
@plans_blp.alt_response(400, schema=ErrorSchema, description="Missing argument for the operation")
@plans_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@plans_blp.alt_response(403, schema=ErrorSchema, description="Insufficient role")
@plans_blp.alt_response(404, schema=ErrorSchema, description="Unknown plan or subscription")
@limiter.limit("60 per hour")
@require_oauth_token
@require_role(Role.ROOT)
@handle_exceptions(default_exception=AccountsError, logger=logger)
def move_user_subscription(data, user_id: int):
    """Mover la suscripcion de un usuario por una de las seis operaciones

    Es el driver manual del mismo puerto que usara la pasarela: lo que aqui
    hace root, manyana lo hara un adaptador de webhooks traduciendo eventos.
    """
    result = SubscriptionManager().apply(
        operation=data["operation"],
        user_id=user_id,
        actor_id=get_current_user().id,
        plan_code=data.get("planCode"),
        organization_enabled=data.get("organizationEnabled", False),
        period_end=data.get("periodEnd"),
        grace_until=data.get("graceUntil"),
        immediate=data.get("immediate", False),
    )
    logger.info(f"Operacion '{data['operation']}' aplicada sobre la suscripcion de {user_id}")
    return result


# =========================================================================
# GESTOR DEL CATALOGO (root)
# =========================================================================


@plans_blp.get("/all")
@plans_blp.response(200, PlanCatalogResponseSchema, description="Every plan, hidden ones included")
@plans_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@plans_blp.alt_response(403, schema=ErrorSchema, description="Insufficient role")
@limiter.limit("120 per hour")
@require_oauth_token
@require_role(Role.ROOT)
@handle_exceptions(default_exception=AccountsError, logger=logger)
def list_all_plans():
    """Catalogo completo para el gestor, con los planes ocultos incluidos

    GET /plans filtra por isPublic, que es lo que debe ver la tabla de precios;
    un gestor que no los enseña no deja gestionarlos.
    """
    return {"plans": PlanManager().list_all_plans()}


@plans_blp.get("/limit-keys")
@plans_blp.response(200, LimitCatalogResponseSchema, description="Available limit keys")
@plans_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@plans_blp.alt_response(403, schema=ErrorSchema, description="Insufficient role")
@limiter.limit("120 per hour")
@require_oauth_token
@require_role(Role.ROOT)
@handle_exceptions(default_exception=AccountsError, logger=logger)
def list_limit_keys():
    """Claves medibles que existen, con su periodicidad

    El panel las ofrece en un desplegable en vez de dejar escribirlas: una
    errata crearia una fila que nadie consulta y dejaria la caracteristica
    desactivada en silencio.
    """
    return {"keys": [{"key": key.value, "period": PERIODS[key].value} for key in LimitKey]}


@plans_blp.post("")
@plans_blp.arguments(PlanWriteSchema)
@plans_blp.response(201, PlanSummarySchema, description="Plan created")
@plans_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@plans_blp.alt_response(403, schema=ErrorSchema, description="Insufficient role")
@plans_blp.alt_response(409, schema=ErrorSchema, description="Code already taken")
@limiter.limit("30 per hour")
@require_oauth_token
@require_role(Role.ROOT)
@handle_exceptions(default_exception=AccountsError, logger=logger)
def create_plan(data):
    """Crear un plan. Nace sin topes: sus claves valen 0 hasta rellenarlas."""
    return PlanManager().create_plan(data), 201


@plans_blp.put("/<int:plan_id>")
@plans_blp.arguments(PlanUpdateSchema)
@plans_blp.response(200, PlanSummarySchema, description="Plan updated")
@plans_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@plans_blp.alt_response(403, schema=ErrorSchema, description="Insufficient role")
@plans_blp.alt_response(404, schema=ErrorSchema, description="Unknown plan")
@limiter.limit("60 per hour")
@require_oauth_token
@require_role(Role.ROOT)
@handle_exceptions(default_exception=AccountsError, logger=logger)
def update_plan(data, plan_id: int):
    """Editar los metadatos de un plan"""
    return PlanManager().update_plan(plan_id, data)


@plans_blp.put("/<int:plan_id>/default")
@plans_blp.response(200, PlanSummarySchema, description="Default plan set")
@plans_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@plans_blp.alt_response(403, schema=ErrorSchema, description="Insufficient role")
@plans_blp.alt_response(404, schema=ErrorSchema, description="Unknown plan")
@limiter.limit("20 per hour")
@require_oauth_token
@require_role(Role.ROOT)
@handle_exceptions(default_exception=AccountsError, logger=logger)
def set_default_plan(plan_id: int):
    """Marcar el plan que reciben las cuentas sin suscripcion vigente"""
    return PlanManager().set_default_plan(plan_id)


@plans_blp.put("/<int:plan_id>/limits")
@plans_blp.arguments(PlanLimitsWriteSchema)
@plans_blp.response(200, PlanLimitsResponseSchema, description="Limits replaced")
@plans_blp.alt_response(400, schema=ErrorSchema, description="Unknown limit key")
@plans_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@plans_blp.alt_response(403, schema=ErrorSchema, description="Insufficient role")
@plans_blp.alt_response(404, schema=ErrorSchema, description="Unknown plan")
@limiter.limit("60 per hour")
@require_oauth_token
@require_role(Role.ROOT)
@handle_exceptions(default_exception=AccountsError, logger=logger)
def replace_plan_limits(data, plan_id: int):
    """Reemplazar TODOS los topes de un plan

    Reemplazar y no parchear: lo que se ve en el panel es exactamente lo que
    queda guardado, y una clave que se quita desaparece de verdad.
    """
    return PlanManager().replace_limits(plan_id, data["limits"])


@plans_blp.delete("/<int:plan_id>")
@plans_blp.response(200, SuccessMessageSchema, description="Plan deleted")
@plans_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@plans_blp.alt_response(403, schema=ErrorSchema, description="Insufficient role")
@plans_blp.alt_response(404, schema=ErrorSchema, description="Unknown plan")
@plans_blp.alt_response(409, schema=ErrorSchema, description="Plan in use or default")
@limiter.limit("20 per hour")
@require_oauth_token
@require_role(Role.ROOT)
@handle_exceptions(default_exception=AccountsError, logger=logger)
def delete_plan(plan_id: int):
    """Borrar un plan. Se niega si alguien lo tiene o si es el de por defecto."""
    PlanManager().delete_plan(plan_id)
    return {"message": "Plan eliminado"}
