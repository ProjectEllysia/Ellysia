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
from src.modules.shared.schemas import ErrorSchema
from src.modules.users import require_oauth_token, get_current_user

from .exceptions import AccountsError
from .managers import PlanManager
from .schemas import EffectivePlanResponseSchema, PlanCatalogResponseSchema


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
