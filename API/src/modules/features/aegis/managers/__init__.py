"""
Managers del módulo Aegis (concienciación en ciberseguridad).

- ``AegisManager`` (``pills.py``): generación de píldoras.
- ``AegisOrgProfileManager`` (``org_profile.py``): perfil de organización.
- ``CampaignManager`` (``campaigns.py``): listas de distribución, campañas
  y el quiz público.

D3 en ``plans/deuda-tecnica-y-calidad.md``: este paquete sustituye al
antiguo ``managers.py`` de 42 KB, cuyo docstring justificaba tener los tres
"en este único fichero por convención" — pero la convención del proyecto,
desde que Themis pasó a paquete, es la contraria. Las tres
responsabilidades no se solapan: ``CampaignManager`` no toca la generación
con IA y ``AegisManager`` no sabe nada de herald ni de tokens de quiz.

Este ``__init__.py`` reexporta los nombres públicos para que
``from ...aegis.managers import X`` siga funcionando sin cambios — incluida
la resolución por atributo de módulo que hace RQ al despicklear los
entry points ya encolados (``AegisManager.execute_aegis_generation``,
``CampaignManager.execute_campaign_send``).
"""

from .pills import AegisManager
from .org_profile import AegisOrgProfileManager
from .campaigns import CampaignManager

__all__ = [
    "AegisManager",
    "AegisOrgProfileManager",
    "CampaignManager",
]
