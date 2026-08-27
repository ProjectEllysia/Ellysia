"""
AegisOrgProfileManager — perfil de organización (D3 en
plans/deuda-tecnica-y-calidad.md).

Los valores estables de generación (empresa, contacto, tono, tamaño,
jurisdicción, productos vigilados): devolverlos con defaults si el usuario
aún no guardó ninguno, y crearlos/actualizarlos (upsert).
"""

from __future__ import annotations

import logging
from typing import Any

from src.modules.shared import WhiteLabelLevel
from src.modules.users import User
from src.modules.infrastructure import UnitOfWork
from src.modules.infrastructure.session import build_repository

from ..model import AegisOrgProfile
from ..repositories import AegisOrgProfileRepository


logger = logging.getLogger(__name__)


# Defaults del perfil de organización cuando el usuario aún no ha guardado
# ninguno — mismos valores por defecto que AegisTweaksSchema para que el
# formulario de generación arranque igual con o sin perfil guardado.
_ORG_PROFILE_DEFAULTS: dict[str, Any] = {
    "company": "",
    "mentionContact": "",
    "tone": "profesional",
    "companySize": "",
    "jurisdiction": "",
    "language": "es",
    "sector": "",
    "workModel": "",
    "employeeCount": None,
    "trackedProducts": [],
    "useHygeiaInventory": True,
    "whiteLabelLevel": WhiteLabelLevel.NONE.value,
    "brandLogo": "",
}


class AegisOrgProfileManager:
    """
    Gestiona el perfil de organización de Aegis: los valores estables de
    generación (empresa, contacto, tono, tamaño, jurisdicción, productos
    vigilados) que se guardan una vez y se precargan en cada generación,
    en vez de reintroducirse cada vez.
    """

    def __init__(self, user: User) -> None:
        self.user = user

    @staticmethod
    def search_products(term: str, limit: int = 20) -> list[dict]:
        """Busca productos vigilables en el índice CPE del espejo local de NVD.

        Sustituye al catálogo fijo de 19 marcas que vivía en
        ``SecOpsConfig.json``: la lista sale de la base de conocimiento, se
        refresca sola con el sync nocturno y solo ofrece productos que de
        verdad tienen algún CVE registrado.
        """
        from src.modules.features.themis.managers import KbQueryManager

        return [
            {"vendor": product.vendor, "product": product.product, "displayName": product.display_name}
            for product in KbQueryManager().search_products(term, limit=limit)
        ]

    def get_or_default(self) -> dict:
        """Devuelve el perfil guardado, o los defaults si aún no existe.

        Añade ``hygeiaInventoryAvailable``, que no es un campo del perfil sino
        del entorno: le dice al frontend si tiene sentido pintar el
        interruptor de "deducir los productos de mis agentes". Sin agentes que
        hayan reportado inventario, el control no se muestra y la preferencia
        guardada (activada por defecto) queda latente hasta que haya alguno.
        """
        repo = build_repository(AegisOrgProfileRepository)
        profile = repo.get_by_user_id(self.user.id)
        result = dict(_ORG_PROFILE_DEFAULTS) if profile is None else profile.to_dict()
        result["hygeiaInventoryAvailable"] = self._hygeia_inventory_available()
        return result

    def _hygeia_inventory_available(self) -> bool:
        try:
            from src.modules.features.hygeia.managers import HygeiaAssetManager

            return HygeiaAssetManager.has_inventory(self.user.id)
        except Exception as exc:
            logger.warning(f"No se pudo comprobar el inventario de Hygeia: {exc}")
            return False

    def upsert(self, data: dict) -> dict:
        """Crea o actualiza el perfil de organización del usuario actual."""
        with UnitOfWork() as uow:
            repo = AegisOrgProfileRepository(uow)
            profile = repo.get_by_user_id(self.user.id)
            if profile is None:
                profile = AegisOrgProfile(user_id=self.user.id)

            profile.company = data["company"]
            profile.contact_email = data["mentionContact"]
            profile.tone = data["tone"]
            profile.company_size = data["companySize"]
            profile.jurisdiction = data["jurisdiction"]
            profile.language = data["language"]
            profile.sector = data["sector"]
            profile.work_model = data["workModel"]
            profile.employee_count = data["employeeCount"]
            profile.tracked_products = data["trackedProducts"]
            profile.use_hygeia_inventory = data["useHygeiaInventory"]
            profile.white_label_level = data["whiteLabelLevel"]
            profile.brand_logo = data["brandLogo"] or None

            saved = repo.save(profile)
            return saved.to_dict()
