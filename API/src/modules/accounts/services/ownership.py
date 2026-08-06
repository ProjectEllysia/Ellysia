"""
Propiedad de una organización, resuelta contra la base de datos.

Ser dueño de una organización **no es un rol** de la plataforma, y por eso esto
es un decorador con ámbito y no una entrada en ``Role``:

- ``Role`` es una escalera lineal (``rank()``), y un dueño de organización no
  encaja en ningún peldaño: no manda sobre nadie ajeno a su organización y
  sigue sin poder tocar ``/system``.
- La propiedad tiene **ámbito**: no se es "un dueño", se es el dueño de una
  organización concreta. Una columna en ``User`` no puede expresar de cuál.
- Habría que revocarlo al cancelar el plan o al traspasar la organización — la
  misma podredumbre que evitamos al decidir que el pago no escribe identidad.
- Ya está en los datos: ``Organization.owner_user_id``.
"""

from functools import wraps

from flask import request

from src.modules.infrastructure.session import build_repository

from ..exceptions import OrganizationNotFoundError
from ..repositories import OrganizationRepository


def get_owned_organization(user_id: int, organization_id: int):
    """La organización, si ``user_id`` es su dueño.

    Raises:
        OrganizationNotFoundError: si no existe **o** si es de otro. El mismo
            error en los dos casos, con el criterio de ``assert_owned``: dos
            respuestas distintas permitirían enumerar organizaciones ajenas.
    """
    organization = build_repository(OrganizationRepository).get_by_id(organization_id)
    if organization is None or organization.owner_user_id != user_id:
        raise OrganizationNotFoundError(organization_id)
    return organization


def require_organization_owner(view):
    """Exige que el usuario autenticado sea dueño de la organización de la ruta.

    Se usa DESPUÉS de ``@require_oauth_token``, y espera un parámetro
    ``organization_id`` en la ruta. Resuelve la propiedad contra la base de
    datos en cada llamada: no viaja en el JWT ni en ninguna columna de ``User``,
    porque un traspaso o una expulsión tienen que surtir efecto en la siguiente
    petición y no cuando caduque el token.
    """

    @wraps(view)
    def decorated(*args, **kwargs):
        organization_id = kwargs.get("organization_id")
        user_id = getattr(request, "current_user_id", None)
        if user_id is None or organization_id is None:
            raise OrganizationNotFoundError(organization_id or 0)

        get_owned_organization(user_id, organization_id)
        return view(*args, **kwargs)

    return decorated
