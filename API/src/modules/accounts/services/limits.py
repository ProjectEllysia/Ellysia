"""Catálogo de claves medibles de la plataforma.

Una **clave de límite** nombra algo que un plan puede topar: escaneos de Lybra
al mes, bóvedas de Acheron, miembros de una organización. Es el vocabulario
compartido entre la tabla ``PlanLimit`` (lo que un plan concede) y el motor de
cuotas (lo que se ha consumido).

Aquí solo vive la **declaración**: qué se mide y con qué periodicidad. El motor
que cuenta y corta —``LimitSpec``, los contadores de existencias y el
``QuotaManager``— llega con la fase 2; hasta entonces nadie consume nada.

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
    """

    MONTH = "month"
    DAY = "day"
    STOCK = "stock"


class LimitKey(Enum):
    """Todo lo que un plan puede topar."""

    THEMIS_LYBRA_SCANS      = "themis.lybra.scans"
    THEMIS_THIRDPARTY_SCANS = "themis.thirdparty.scans"
    THEMIS_SCHEDULED        = "themis.scheduled"
    THEMIS_REPORTS_AI       = "themis.reports.ai"

    AEGIS_PILLS      = "aegis.pills"
    AEGIS_CAMPAIGNS  = "aegis.campaigns"
    AEGIS_RECIPIENTS = "aegis.recipients"

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


#: Cómo se cuenta lo ya existente para cada clave de tipo ``stock``.
#:
#: Las claves de existencias NO llevan contador propio: se cuenta la tabla real.
#: Un contador de existencias se desincroniza en el primer borrado, y la base de
#: datos ya sabe la respuesta.
#:
#: Recibe una lista de ``user_ids`` y no uno solo porque la bolsa de una
#: organización suma la de todos sus miembros (fase 5). Hoy la lista siempre
#: tiene un elemento.
#:
#: Solo están las claves que la fase 2 hace cumplir. Pedir una que no esté es un
#: error de programación, no del usuario, y ``QuotaManager`` lo dice como tal.
STOCK_COUNTERS: dict[LimitKey, Callable[..., int]] = {
    LimitKey.HYGEIA_ASSETS: _count_hygeia_assets,
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
