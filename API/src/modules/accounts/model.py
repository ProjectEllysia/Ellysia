"""
Modelos de la capa comercial: catálogo de planes, suscripciones y organizaciones.

Diseño completo en ``plans/feature/general/planes-y-organizaciones.md``. Tres
grupos de tablas:

- **Catálogo**: ``Plan`` y ``PlanLimit`` — qué se vende y cuánto incluye.
- **Titularidad**: ``Subscription`` — quién tiene qué y hasta cuándo.
- **Organización**: ``Organization``, ``OrganizationMember`` y
  ``OrganizationInvitation`` — un titular paga, sus miembros heredan derechos.
  Nacen aquí pero no se usan hasta la fase 5.

Más ``UsageCounter``, el contador de consumo que estrena la fase 2.

Nota de alcance: una organización comparte **plan y factura**, nunca datos. No
hay ninguna relación de aquí hacia bóvedas, escaneos o análisis, y los filtros
``user_id`` del resto de módulos se quedan como están.
"""

from sqlalchemy import (
    Boolean,
    Column,
    Date,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    text,
)
from sqlalchemy.orm import relationship

from src.modules.shared import Base, utcnow_naive


# =========================================================================
# CATÁLOGO
# =========================================================================

class Plan(Base):
    """
    Un plan comercial del catálogo.

    Los precios existen para **pintar la tabla de precios**, no para cobrar:
    Ellysia no calcula dinero en ningún momento. Cuando entre la pasarela, el
    importe lo calcula ella y aquí solo llega "esta cuenta tiene derecho a este
    plan hasta esta fecha".

    Attributes:
        code: Identificador estable ("freemium", "bronze"...). Es lo que usan
            las llamadas de asignación, no el id numérico.
        rank: Orden ascendente para la tabla de precios.
        is_public: Si aparece en el catálogo público. Permite planes a medida.
        is_default: El que recibe quien no tiene suscripción vigente. Hay
            exactamente uno, y lo impone la base de datos (ver __table_args__).
    """

    __tablename__ = "Plan"

    id                    = Column(Integer,     primary_key=True, autoincrement=True)
    code                  = Column(String(32),  nullable=False, unique=True, index=True)
    name                  = Column(String(64),  nullable=False)
    tagline               = Column(String(160), nullable=True)
    rank                  = Column(Integer,     nullable=False, default=0)
    monthly_price_cents   = Column(Integer,     nullable=False, default=0)
    org_addon_price_cents = Column(Integer,     nullable=False, default=0)
    currency              = Column(String(3),   nullable=False, default="EUR")
    is_public             = Column(Boolean,     nullable=False, default=True)
    is_default            = Column(Boolean,     nullable=False, default=False)
    created_at            = Column(DateTime,    nullable=False, default=utcnow_naive)
    updated_at            = Column(DateTime,    nullable=False, default=utcnow_naive,
                                                onupdate=utcnow_naive)

    limits = relationship(
        "PlanLimit", back_populates="plan",
        cascade="all, delete-orphan", lazy="selectin",
    )

    __table_args__ = (
        # "Exactamente un plan por defecto", impuesto por la base de datos y no
        # por una comprobación en Python. Es un índice PARCIAL: solo indexa las
        # filas con is_default=True, así que admite N planes en False y a lo
        # sumo uno en True. Un UniqueConstraint a secas no valdría — prohibiría
        # tener dos planes que NO son el de por defecto.
        Index(
            "ux_plan_single_default", "is_default", unique=True,
            postgresql_where=text("is_default"),
            sqlite_where=text("is_default"),
        ),
    )

    def to_dict(self) -> dict:
        """Vista pública del plan. Los límites los compone el manager, que es
        quien decide qué ámbito (holder/member) toca devolver."""
        return {
            "id":                 self.id,
            "code":               self.code,
            "name":               self.name,
            "tagline":            self.tagline,
            "rank":               self.rank,
            "monthlyPriceCents":  self.monthly_price_cents,
            "orgAddonPriceCents": self.org_addon_price_cents,
            "currency":           self.currency,
            "isPublic":           self.is_public,
            "isDefault":          self.is_default,
        }

    def __repr__(self) -> str:
        return f"<Plan id={self.id} code='{self.code}' rank={self.rank}>"


class PlanLimit(Base):
    """
    Un tope de un plan para una clave medible.

    Es la tabla que rellena el equipo: añadir una herramienta medible nueva es
    un INSERT, no una migración de esquema.

    El significado de ``value`` no es el habitual y conviene tenerlo presente:

    - ``NULL`` → ilimitado.
    - ``0``    → no incluido en el plan (corta con 402).
    - ``n``    → tope n.

    Y una fila **ausente** se lee como ``0``. El fallo es cerrado a propósito:
    una clave nueva que nadie se acuerde de rellenar queda desactivada, no
    regalada.

    Attributes:
        scope: "holder" (lo que obtiene quien contrata) o "member" (lo que
            obtiene cada miembro de su organización). Ver services.limits.
        period: "month", "day" o "stock". Se guarda aquí, y no solo en el mapa
            PERIODS del código, para que una fila de base de datos se pueda
            interpretar sin cargar la aplicación.
    """

    __tablename__ = "PlanLimit"

    plan_id   = Column(Integer,    ForeignKey("Plan.id", ondelete="CASCADE"), primary_key=True)
    limit_key = Column(String(64), primary_key=True)
    scope     = Column(String(8),  primary_key=True)
    value     = Column(Integer,    nullable=True)
    period    = Column(String(8),  nullable=False)

    plan = relationship("Plan", back_populates="limits")

    def to_dict(self) -> dict:
        return {
            "limitKey": self.limit_key,
            "scope":    self.scope,
            "value":    self.value,
            "period":   self.period,
        }

    def __repr__(self) -> str:
        return f"<PlanLimit plan={self.plan_id} key='{self.limit_key}' scope='{self.scope}' value={self.value}>"


# =========================================================================
# TITULARIDAD
# =========================================================================

class Subscription(Base):
    """
    La suscripción de un usuario a un plan.

    **No todos los usuarios tienen fila.** Su ausencia significa "plan por
    defecto", igual que una suscripción caducada: el camino de respaldo hace
    falta de todos modos, así que crear la fila en el alta sería un segundo
    mecanismo para el mismo resultado — y un sitio más donde olvidarse.

    Es la **única** tabla que escribe un cobro. Un pago no toca nunca
    ``UserAttribute`` (el impago borraría permisos concedidos a mano), ni
    ``User.role``, ni ``Organization``, ni ``UsageCounter``.

    Attributes:
        status: "trialing", "active", "past_due" o "canceled". Quien decide si
            concede derechos no es el estado por sí solo sino
            ``services.entitlements.is_effective``, que además mira las fechas.
        organization_enabled: El toggle de organización, ortogonal al plan —
            se puede aplicar a cualquiera. El tope de miembros lo da la clave
            "organization.members" del plan.
        cancel_at_period_end: Cancelada pero vigente hasta current_period_end.
            Cancelar NO corta: corta caducar.
        grace_until: Ventana de cortesía tras un impago. Una tarjeta caducada
            es mucho más frecuente que un moroso.
        external_event_at: Marca del último evento de pasarela aplicado. Toda
            pasarela reintenta y entrega desordenado; con esta columna se
            descarta lo viejo y lo repetido.
        assigned_by_user_id: Quién la movió a mano. NULL = la movió la pasarela.
    """

    __tablename__ = "Subscription"

    id                        = Column(Integer,    primary_key=True, autoincrement=True)
    user_id                   = Column(Integer,    ForeignKey("User.id", ondelete="CASCADE"),
                                                   nullable=False, unique=True)
    plan_id                   = Column(Integer,    ForeignKey("Plan.id"), nullable=False)
    status                    = Column(String(16), nullable=False, default="active")
    organization_enabled      = Column(Boolean,    nullable=False, default=False)
    started_at                = Column(DateTime,   nullable=False, default=utcnow_naive)
    current_period_start      = Column(DateTime,   nullable=True)
    current_period_end        = Column(DateTime,   nullable=True)
    cancel_at_period_end      = Column(Boolean,    nullable=False, default=False)
    grace_until               = Column(DateTime,   nullable=True)
    external_customer_ref     = Column(String(64), nullable=True)
    external_subscription_ref = Column(String(64), nullable=True, index=True)
    external_event_at         = Column(DateTime,   nullable=True)
    assigned_by_user_id       = Column(Integer,    ForeignKey("User.id"), nullable=True)
    created_at                = Column(DateTime,   nullable=False, default=utcnow_naive)
    updated_at                = Column(DateTime,   nullable=False, default=utcnow_naive,
                                                   onupdate=utcnow_naive)

    # Sin relación hacia User: hay dos FKs hacia él (el titular y quien la
    # asignó) y declararla obligaría a desambiguar con foreign_keys= para algo
    # que nadie recorre — el usuario siempre se conoce antes que su suscripción.
    plan = relationship("Plan", lazy="joined")

    def to_dict(self) -> dict:
        return {
            "id":                   self.id,
            "userId":               self.user_id,
            "planId":               self.plan_id,
            "status":               self.status,
            "organizationEnabled":  self.organization_enabled,
            "startedAt":            self.started_at,
            "currentPeriodStart":   self.current_period_start,
            "currentPeriodEnd":     self.current_period_end,
            "cancelAtPeriodEnd":    self.cancel_at_period_end,
            "graceUntil":           self.grace_until,
        }

    def __repr__(self) -> str:
        return f"<Subscription user={self.user_id} plan={self.plan_id} status='{self.status}'>"


# =========================================================================
# ORGANIZACIÓN — creadas aquí, en uso desde la fase 5
# =========================================================================

class Organization(Base):
    """
    Un grupo de usuarios que comparte el plan de su dueño.

    Comparte plan y factura, **no datos**: no hay ninguna relación desde aquí
    hacia bóvedas, escaneos o análisis, y nunca debe haberla. Acheron es
    zero-knowledge (el servidor solo ve cifrado) e Iris analiza correo personal.

    La regla tiene desde 2026-08 **una excepción, y solo una**: el informe de
    inventario de Hygeia (``POST /hygeia/inventory/report`` con
    ``scope="organization"``) lista los activos de todos los miembros. Se
    abrió porque un parque de servidores es dato corporativo, no personal —
    justo lo que una organización necesita ver junto para auditarse—, a
    diferencia de una bóveda de contraseñas o de un buzón de correo.

    Sigue sin haber relación en el modelo: el informe resuelve los miembros por
    la superficie pública de ``OrganizationManager`` y consulta Hygeia con esos
    ids. Y solo lo puede pedir el **dueño**, porque hoy no hay rol intermedio
    entre ``owner`` y ``member``.

    Antes de abrir la segunda excepción conviene tener una razón igual de
    concreta: la frase de arriba sigue siendo la regla, no una recomendación.
    """

    __tablename__ = "Organization"

    id            = Column(Integer,     primary_key=True, autoincrement=True)
    name          = Column(String(128), nullable=False)
    slug          = Column(String(64),  nullable=False, unique=True, index=True)
    owner_user_id = Column(Integer,     ForeignKey("User.id"), nullable=False, unique=True)
    created_at    = Column(DateTime,    nullable=False, default=utcnow_naive)
    updated_at    = Column(DateTime,    nullable=False, default=utcnow_naive,
                                        onupdate=utcnow_naive)

    def __repr__(self) -> str:
        return f"<Organization id={self.id} slug='{self.slug}' owner={self.owner_user_id}>"


class OrganizationMember(Base):
    """
    Pertenencia de un usuario a una organización.

    El dueño es miembro de la suya con ``member_role='owner'``: así la
    resolución de derechos y el recuento de miembros no necesitan un caso
    especial.

    Ser dueño **no es un rol** de la plataforma, es esta fila. Un rol es una
    escalera lineal y la propiedad tiene ámbito: no se es "un dueño", se es el
    dueño de una organización concreta.
    """

    __tablename__ = "OrganizationMember"

    organization_id    = Column(Integer,    ForeignKey("Organization.id", ondelete="CASCADE"),
                                            primary_key=True)
    # unique=True además de formar parte de la PK: un usuario pertenece a lo
    # sumo a UNA organización, y lo impone Postgres, no un if en Python.
    user_id            = Column(Integer,    ForeignKey("User.id", ondelete="CASCADE"),
                                            primary_key=True, unique=True)
    member_role        = Column(String(16), nullable=False, default="member")
    invited_by_user_id = Column(Integer,    ForeignKey("User.id"), nullable=True)
    joined_at          = Column(DateTime,   nullable=False, default=utcnow_naive)

    def __repr__(self) -> str:
        return f"<OrganizationMember org={self.organization_id} user={self.user_id} role='{self.member_role}'>"


class OrganizationInvitation(Base):
    """
    Invitación a formar parte de una organización.

    ``email`` puede no corresponder todavía a ningún ``User``: si no existe, la
    invitación creará la cuenta; si existe, no cambia nada hasta que acepte.

    Se guarda el **hash** del token, nunca el token, con el mismo criterio que
    ``MFARecoveryCode``.
    """

    __tablename__ = "OrganizationInvitation"

    id                 = Column(Integer,     primary_key=True, autoincrement=True)
    organization_id    = Column(Integer,     ForeignKey("Organization.id", ondelete="CASCADE"),
                                             nullable=False, index=True)
    email              = Column(String(128), nullable=False)
    token_hash         = Column(String(128), nullable=False, unique=True, index=True)
    status             = Column(String(16),  nullable=False, default="pending")
    invited_by_user_id = Column(Integer,     ForeignKey("User.id"), nullable=False)
    created_user_id    = Column(Integer,     ForeignKey("User.id"), nullable=True)
    expires_at         = Column(DateTime,    nullable=False)
    created_at         = Column(DateTime,    nullable=False, default=utcnow_naive)
    accepted_at        = Column(DateTime,    nullable=True)

    def __repr__(self) -> str:
        return f"<OrganizationInvitation id={self.id} org={self.organization_id} status='{self.status}'>"


# =========================================================================
# CONSUMO — creada aquí, en uso desde la fase 2
# =========================================================================

class UsageCounter(Base):
    """
    Consumo acumulado de una clave en un periodo.

    Solo para las claves de consumo (``month`` / ``day``). Las de existencias
    (``stock``) no tienen contador: se cuenta la tabla real, porque un contador
    de existencias se desincroniza en el primer borrado.

    No hay proceso de reseteo: al cambiar el periodo cambia ``period_start`` y
    nace una fila nueva.

    Attributes:
        holder_kind: "user" u "org" — a quién se le carga el consumo. Lo que
            cubre el plan de la organización va a la bolsa común; lo que solo
            cubre el plan personal, al contador del usuario.
        holder_id: Sin ForeignKey a propósito: apunta a ``User`` o a
            ``Organization`` según ``holder_kind``.
        period_start: Primer día del periodo, en UTC.
    """

    __tablename__ = "UsageCounter"

    holder_kind  = Column(String(8),  primary_key=True)
    holder_id    = Column(Integer,    primary_key=True)
    limit_key    = Column(String(64), primary_key=True)
    period_start = Column(Date,       primary_key=True)
    used         = Column(Integer,    nullable=False, default=0)

    def __repr__(self) -> str:
        return (
            f"<UsageCounter {self.holder_kind}={self.holder_id} "
            f"key='{self.limit_key}' period={self.period_start} used={self.used}>"
        )
