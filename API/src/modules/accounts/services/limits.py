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

from enum import Enum


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


#: Ámbitos posibles de una fila de ``PlanLimit``.
SCOPE_HOLDER = "holder"
"""Lo que obtiene quien contrata el plan."""

SCOPE_MEMBER = "member"
"""Lo que obtiene cada miembro de su organización, por el hecho de serlo."""

SCOPES: tuple[str, ...] = (SCOPE_HOLDER, SCOPE_MEMBER)
