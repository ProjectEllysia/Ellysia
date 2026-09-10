"""Catálogo de claves medibles de la plataforma.

Una **clave de límite** nombra algo que un plan puede topar: escaneos de Lybra
al mes, bóvedas de Acheron, miembros de una organización. Es el vocabulario
compartido entre la tabla ``PlanLimit`` (lo que un plan concede) y el motor de
cuotas (lo que se ha consumido).

Aquí solo vive la **declaración**: qué se mide y con qué periodicidad. El motor
que cuenta y corta vive aparte, en ``QuotaManager`` (``services/quotas.py``),
que importa este catálogo en vez de duplicarlo.

Disciplina, la misma que ``AttributeType``: el valor del enum es lo que se
guarda en base de datos, así que renombrar un miembro no basta — habría que
migrar las filas de ``PlanLimit`` y ``UsageCounter`` que lo referencian.
"""

from datetime import date, datetime
from enum import Enum
from typing import Callable, Optional

from src.modules.shared import utcnow_naive


class LimitPeriod(str, Enum):
    """Cómo se cuenta una clave.

    - ``MONTH`` / ``DAY``: **consumo**. Hay contador (``UsageCounter``), sube y
      no baja, y se reinicia solo al cambiar de periodo.
    - ``STOCK``: **existencias**. No hay contador: se cuenta la tabla real. Un
      contador de existencias se desincroniza en el primer borrado, y la base
      de datos ya sabe la respuesta.
    - ``TIER``: **nivel**. Ni se consume ni se cuenta: el ``value`` de la fila
      *es* el escalón que concede el plan (0 = ninguno, n = escalón n,
      ``NULL`` = el más alto). Se lee con ``resolve_entitlement(...).limit`` y
      no pasa por ``consume()``: no hay nada que gastar, solo un techo que
      respetar.
    """

    MONTH = "month"
    DAY = "day"
    STOCK = "stock"
    TIER = "tier"


class LimitKey(Enum):
    """Todo lo que un plan puede topar."""

    THEMIS_LYBRA_SCANS      = "themis.lybra.scans"
    THEMIS_THIRDPARTY_SCANS = "themis.thirdparty.scans"
    THEMIS_SCHEDULED        = "themis.scheduled"
    THEMIS_REPORTS_AI       = "themis.reports.ai"

    AEGIS_PILLS       = "aegis.pills"
    AEGIS_CAMPAIGNS   = "aegis.campaigns"
    AEGIS_RECIPIENTS  = "aegis.recipients"
    AEGIS_WHITE_LABEL = "aegis.white_label"

    IRIS_ANALYSES            = "iris.analyses"
    IRIS_AI_SUMMARIES        = "iris.ai_summaries"
    IRIS_MAILBOX_CONNECTIONS = "iris.mailbox.connections"

    ACHERON_VAULTS = "acheron.vaults"
    ACHERON_ITEMS  = "acheron.items"

    HYGEIA_ASSETS = "hygeia.assets"

    AI_REQUESTS = "ai.requests"

    ORGANIZATION_MEMBERS = "organization.members"

    @property
    def db_name(self) -> str:
        """Valor tal y como se guarda en ``PlanLimit.limit_key``."""
        return self.value  # type: ignore[return-value]


#: Periodicidad de cada clave. Va en un mapa aparte y no como segundo valor del
#: enum para que ``LimitKey("themis.lybra.scans")`` siga funcionando: el enum
#: tiene que poder construirse desde el string que hay en base de datos.
PERIODS: dict[LimitKey, LimitPeriod] = {
    LimitKey.THEMIS_LYBRA_SCANS:      LimitPeriod.MONTH,
    LimitKey.THEMIS_THIRDPARTY_SCANS: LimitPeriod.MONTH,
    LimitKey.THEMIS_SCHEDULED:        LimitPeriod.STOCK,
    LimitKey.THEMIS_REPORTS_AI:       LimitPeriod.MONTH,

    LimitKey.AEGIS_PILLS:      LimitPeriod.MONTH,
    LimitKey.AEGIS_CAMPAIGNS:  LimitPeriod.MONTH,
    LimitKey.AEGIS_RECIPIENTS: LimitPeriod.STOCK,
    # Nivel, no cantidad: hasta dónde puede llegar el white-labeling de sus
    # campañas. Ver WhiteLabelLevel.from_allowance.
    LimitKey.AEGIS_WHITE_LABEL: LimitPeriod.TIER,

    LimitKey.IRIS_ANALYSES:            LimitPeriod.MONTH,
    LimitKey.IRIS_AI_SUMMARIES:        LimitPeriod.MONTH,
    LimitKey.IRIS_MAILBOX_CONNECTIONS: LimitPeriod.STOCK,

    LimitKey.ACHERON_VAULTS: LimitPeriod.STOCK,
    LimitKey.ACHERON_ITEMS:  LimitPeriod.STOCK,

    LimitKey.HYGEIA_ASSETS: LimitPeriod.STOCK,

    # Techo agregado que se consume A LA VEZ que la clave concreta: protege el
    # coste de la IA aunque un plan sea generoso módulo a módulo.
    LimitKey.AI_REQUESTS: LimitPeriod.MONTH,

    LimitKey.ORGANIZATION_MEMBERS: LimitPeriod.STOCK,
}


# =========================================================================
# CONTADORES DE EXISTENCIAS
# =========================================================================

def _count_hygeia_assets(session, user_ids: list[int]) -> int:
    """Activos monitorizados vivos de un conjunto de usuarios.

    Import diferido a propósito: ``accounts`` no puede importar ``features`` en
    tiempo de módulo — los módulos de features importan el motor de cuotas y se
    formaría un ciclo.
    """
    from src.modules.features.hygeia.model import MonitoredAsset

    return (
        session.query(MonitoredAsset)
        .filter(MonitoredAsset.user_id.in_(user_ids))
        .count()
    )


def _count_themis_scheduled(session, user_ids: list[int]) -> int:
    """Escaneos programados **activos**.

    Los revocados siguen en la tabla como histórico y no ocupan hueco: lo que
    consume recursos es lo que va a volver a dispararse.
    """
    from src.modules.features.themis.model import ProgramedScan

    return (
        session.query(ProgramedScan)
        .filter(
            ProgramedScan.user_id.in_(user_ids),
            ProgramedScan.is_active.is_(True),
        )
        .count()
    )


def _count_aegis_recipients(session, user_ids: list[int]) -> int:
    """Destinatarios en todas las listas de distribución del usuario."""
    from src.modules.features.aegis.model import DistributionList, Recipient

    return (
        session.query(Recipient)
        .join(DistributionList, Recipient.list_id == DistributionList.id)
        .filter(DistributionList.user_id.in_(user_ids))
        .count()
    )


def _count_iris_mailbox_connections(session, user_ids: list[int]) -> int:
    from src.modules.features.iris.model import IrisMailboxConnection

    return (
        session.query(IrisMailboxConnection)
        .filter(IrisMailboxConnection.user_id.in_(user_ids))
        .count()
    )


def _count_acheron_vaults(session, user_ids: list[int]) -> int:
    from src.modules.features.acheron.model import Vault

    return session.query(Vault).filter(Vault.user_id.in_(user_ids)).count()


def _count_acheron_items(session, user_ids: list[int]) -> int:
    """Secretos guardados, contados a través de la bóveda que los contiene.

    ``Storable`` no tiene ``user_id``: el dueño lo pone la bóveda.
    """
    from src.modules.features.acheron.model import Storable, Vault

    return (
        session.query(Storable)
        .join(Vault, Storable.vault_id == Vault.id)
        .filter(Vault.user_id.in_(user_ids))
        .count()
    )


def _count_organization_members(session, user_ids: list[int]) -> int:
    """Miembros de la organización más sus invitaciones sin responder.

    Las pendientes cuentan a propósito: si no, se invitaría a 300 personas con
    un plan de 20 y el tope no serviría de nada — bastaría con que fueran
    aceptando.

    ``user_ids`` llega con el dueño, que es de quien se resuelve el tope; la
    organización se busca por él.
    """
    from ..model import Organization, OrganizationInvitation, OrganizationMember

    organization = (
        session.query(Organization)
        .filter(Organization.owner_user_id.in_(user_ids))
        .one_or_none()
    )
    if organization is None:
        return 0

    members = (
        session.query(OrganizationMember)
        .filter(OrganizationMember.organization_id == organization.id)
        .count()
    )
    pending = (
        session.query(OrganizationInvitation)
        .filter(
            OrganizationInvitation.organization_id == organization.id,
            OrganizationInvitation.status == "pending",
        )
        .count()
    )
    return members + pending


#: Cómo se cuenta lo ya existente para cada clave de tipo ``stock``.
#:
#: Las claves de existencias NO llevan contador propio: se cuenta la tabla real.
#: Un contador de existencias se desincroniza en el primer borrado, y la base de
#: datos ya sabe la respuesta.
#:
#: Recibe una lista de ``user_ids`` y no uno solo porque la bolsa de una
#: organización suma la de todos sus miembros: cuando el titular es la
#: organización, la lista trae los ids de todos ellos; cuando es un usuario
#: suelto, trae solo el suyo.
#:
#: Pedir una clave que no esté aquí es un error de programación, no del usuario,
#: y ``QuotaManager`` lo dice como tal en vez de responder un 402.
STOCK_COUNTERS: dict[LimitKey, Callable[..., int]] = {
    LimitKey.HYGEIA_ASSETS:            _count_hygeia_assets,
    LimitKey.THEMIS_SCHEDULED:         _count_themis_scheduled,
    LimitKey.AEGIS_RECIPIENTS:         _count_aegis_recipients,
    LimitKey.IRIS_MAILBOX_CONNECTIONS: _count_iris_mailbox_connections,
    LimitKey.ACHERON_VAULTS:           _count_acheron_vaults,
    LimitKey.ACHERON_ITEMS:            _count_acheron_items,
    LimitKey.ORGANIZATION_MEMBERS:     _count_organization_members,
}


def period_start_for(period: LimitPeriod, moment: Optional[datetime] = None) -> Optional[date]:
    """Primer día del periodo en curso, en UTC.

    Es la cuarta parte de la clave primaria de ``UsageCounter``: al cambiar de
    periodo cambia este valor y nace una fila nueva con ``used = 0``. Por eso no
    hace falta ningún proceso que reinicie contadores.

    Devuelve ``None`` para las existencias, que no tienen periodo.
    """
    moment = moment or utcnow_naive()
    if period is LimitPeriod.MONTH:
        return date(moment.year, moment.month, 1)
    if period is LimitPeriod.DAY:
        return moment.date()
    return None


def next_period_start(period: LimitPeriod, moment: Optional[datetime] = None) -> Optional[date]:
    """Cuándo se reinicia el contador. Es el ``resetsAt`` que ve el cliente."""
    current = period_start_for(period, moment)
    if current is None:
        return None
    if period is LimitPeriod.DAY:
        return date.fromordinal(current.toordinal() + 1)
    # Mensual: el día 1 del mes siguiente.
    return date(current.year + 1, 1, 1) if current.month == 12 else date(current.year, current.month + 1, 1)


#: Ámbitos posibles de una fila de ``PlanLimit``.
SCOPE_HOLDER = "holder"
"""Lo que obtiene quien contrata el plan."""

SCOPE_MEMBER = "member"
"""Lo que obtiene cada miembro de su organización, por el hecho de serlo."""

SCOPES: tuple[str, ...] = (SCOPE_HOLDER, SCOPE_MEMBER)
