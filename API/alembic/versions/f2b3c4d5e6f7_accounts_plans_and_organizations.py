"""accounts: catalogo de planes, suscripciones y organizaciones

Crea las siete tablas del modulo accounts y siembra los cuatro planes
comerciales de partida.

El catalogo va embebido aqui como literal y NO se lee de ningun modulo vivo ni
de SecOpsConfig.json: una migracion tiene que seguir dando el mismo resultado
dentro de un anyo, cuando los precios y los topes se editen desde el panel de
root y el fichero de origen diga otra cosa. Si los numeros de partida cambian,
va una migracion nueva, no una edicion de esta.

Ninguna de las siete tablas necesita server_default: nacen vacias, asi que no
hay filas existentes que rellenar y bastan los default= de Python.

Revision ID: f2b3c4d5e6f7
Revises: f1a2b3c4d5e6
Create Date: 2026-08-06 11:00:00.000000

"""
from datetime import datetime, timezone
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision: str = "f2b3c4d5e6f7"
down_revision: Union[str, Sequence[str], None] = "f1a2b3c4d5e6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# ---------------------------------------------------------------------------
# Catalogo comercial de partida (§11 del documento de disenyo), congelado.
# ---------------------------------------------------------------------------

#: (code, name, tagline, rank, monthly_cents, org_addon_cents, is_public, is_default)
_PLANS: tuple[tuple, ...] = (
    ("freemium", "Freemium", "Prueba Ellysia sin coste ni tarjeta",            0,     0,      0, True, True),
    ("bronze",   "Bronze",   "Para quien se defiende solo",                    1,  2900,   2000, True, False),
    ("silver",   "Silver",   "Para un equipo pequenyo con activos que cuidar", 2,  7900,   5000, True, False),
    ("gold",     "Gold",     "Para un responsable de seguridad y su gente",    3, 19900,  12000, True, False),
)

#: Topes del ambito "holder": lo que se lleva quien contrata el plan.
#: limit_key -> (period, {code_de_plan: valor})
#: None = ilimitado · 0 = no incluido.
#: Las 15 claves aparecen para los 4 planes a proposito: una fila ausente se
#: leeria como 0 y desactivaria la caracteristica en silencio.
_HOLDER_LIMITS: dict[str, tuple[str, dict[str, int | None]]] = {
    "themis.lybra.scans":       ("month", {"freemium":  3, "bronze":  25, "silver":  100, "gold":   400}),
    "themis.thirdparty.scans":  ("month", {"freemium":  0, "bronze":  10, "silver":   50, "gold":   200}),
    "themis.scheduled":         ("stock", {"freemium":  0, "bronze":   3, "silver":   15, "gold":    50}),
    "themis.reports.ai":        ("month", {"freemium":  1, "bronze":  10, "silver":   40, "gold":   150}),
    "aegis.pills":              ("month", {"freemium":  2, "bronze":  15, "silver":   60, "gold":   200}),
    "aegis.campaigns":          ("month", {"freemium":  0, "bronze":   2, "silver":   10, "gold":    40}),
    "aegis.recipients":         ("stock", {"freemium":  0, "bronze": 100, "silver":  500, "gold":  2000}),
    "iris.analyses":            ("month", {"freemium": 10, "bronze": 100, "silver":  500, "gold":  None}),
    "iris.ai_summaries":        ("month", {"freemium":  2, "bronze":  25, "silver":  100, "gold":   400}),
    "iris.mailbox.connections": ("stock", {"freemium":  0, "bronze":   1, "silver":    3, "gold":    10}),
    "acheron.vaults":           ("stock", {"freemium":  1, "bronze":   3, "silver":   10, "gold":  None}),
    "acheron.items":            ("stock", {"freemium": 25, "bronze": 250, "silver": 1000, "gold":  None}),
    "hygeia.assets":            ("stock", {"freemium":  1, "bronze":  10, "silver":   40, "gold":   150}),
    "ai.requests":              ("month", {"freemium":  5, "bronze":  60, "silver":  250, "gold":   900}),
    "organization.members":     ("stock", {"freemium":  0, "bronze":  20, "silver":   50, "gold":   100}),
}

#: Topes del ambito "member": lo que se lleva cada empleado por pertenecer a la
#: organizacion, ADEMAS de su propio plan personal (los derechos se suman por
#: max(), nunca se sustituyen).
#:
#: Aqui solo van las claves con valor: lo que no aparece vale 0. Un empleado no
#: lanza pentestings ni campanyas de concienciacion por su cuenta — eso es del
#: responsable de seguridad. Freemium no aparece porque no admite organizacion.
_MEMBER_LIMITS: dict[str, tuple[str, dict[str, int | None]]] = {
    "acheron.vaults":           ("stock", {"bronze":   3, "silver":    5, "gold": None}),
    "acheron.items":            ("stock", {"bronze": 250, "silver": 1000, "gold": None}),
    "iris.analyses":            ("month", {"bronze":  50, "silver":  200, "gold": None}),
    "iris.ai_summaries":        ("month", {"bronze":  10, "silver":   40, "gold":  100}),
    "iris.mailbox.connections": ("stock", {"bronze":   1, "silver":    2, "gold":    3}),
    "hygeia.assets":            ("stock", {"bronze":   2, "silver":    5, "gold":   10}),
}


def upgrade() -> None:
    """Crea las siete tablas y siembra el catalogo."""
    op.create_table(
        "Plan",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("code", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("tagline", sa.String(length=160), nullable=True),
        sa.Column("rank", sa.Integer(), nullable=False),
        sa.Column("monthly_price_cents", sa.Integer(), nullable=False),
        sa.Column("org_addon_price_cents", sa.Integer(), nullable=False),
        sa.Column("currency", sa.String(length=3), nullable=False),
        sa.Column("is_public", sa.Boolean(), nullable=False),
        sa.Column("is_default", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    # Indice UNICO, no constraint + indice aparte: es lo que emite el modelo
    # para una columna con unique=True + index=True, y las dos formas tienen
    # que coincidir o un futuro `alembic check` marcara deriva.
    op.create_index("ix_Plan_code", "Plan", ["code"], unique=True)
    # Indice unico PARCIAL: solo indexa las filas con is_default=True, de modo
    # que admite N planes en False y a lo sumo uno en True. Un UniqueConstraint
    # a secas prohibiria tener dos planes que NO son el de por defecto.
    op.create_index(
        "ux_plan_single_default", "Plan", ["is_default"], unique=True,
        postgresql_where=sa.text("is_default"),
        sqlite_where=sa.text("is_default"),
    )

    op.create_table(
        "PlanLimit",
        sa.Column("plan_id", sa.Integer(), nullable=False),
        sa.Column("limit_key", sa.String(length=64), nullable=False),
        sa.Column("scope", sa.String(length=8), nullable=False),
        sa.Column("value", sa.Integer(), nullable=True),
        sa.Column("period", sa.String(length=8), nullable=False),
        sa.ForeignKeyConstraint(["plan_id"], ["Plan.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("plan_id", "limit_key", "scope"),
    )

    op.create_table(
        "Subscription",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("plan_id", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("organization_enabled", sa.Boolean(), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=False),
        sa.Column("current_period_start", sa.DateTime(), nullable=True),
        sa.Column("current_period_end", sa.DateTime(), nullable=True),
        sa.Column("cancel_at_period_end", sa.Boolean(), nullable=False),
        sa.Column("grace_until", sa.DateTime(), nullable=True),
        sa.Column("external_customer_ref", sa.String(length=64), nullable=True),
        sa.Column("external_subscription_ref", sa.String(length=64), nullable=True),
        sa.Column("external_event_at", sa.DateTime(), nullable=True),
        sa.Column("assigned_by_user_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["User.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["plan_id"], ["Plan.id"]),
        sa.ForeignKeyConstraint(["assigned_by_user_id"], ["User.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id"),
    )
    op.create_index(
        "ix_Subscription_external_subscription_ref", "Subscription",
        ["external_subscription_ref"], unique=False,
    )

    op.create_table(
        "Organization",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("slug", sa.String(length=64), nullable=False),
        sa.Column("owner_user_id", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["owner_user_id"], ["User.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("owner_user_id"),
    )
    op.create_index("ix_Organization_slug", "Organization", ["slug"], unique=True)

    op.create_table(
        "OrganizationMember",
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("member_role", sa.String(length=16), nullable=False),
        sa.Column("invited_by_user_id", sa.Integer(), nullable=True),
        sa.Column("joined_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["Organization.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["User.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["invited_by_user_id"], ["User.id"]),
        sa.PrimaryKeyConstraint("organization_id", "user_id"),
        # Ademas de la PK: un usuario pertenece a lo sumo a UNA organizacion.
        sa.UniqueConstraint("user_id"),
    )

    op.create_table(
        "OrganizationInvitation",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("organization_id", sa.Integer(), nullable=False),
        sa.Column("email", sa.String(length=128), nullable=False),
        sa.Column("token_hash", sa.String(length=128), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("invited_by_user_id", sa.Integer(), nullable=False),
        sa.Column("created_user_id", sa.Integer(), nullable=True),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("accepted_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["organization_id"], ["Organization.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["invited_by_user_id"], ["User.id"]),
        sa.ForeignKeyConstraint(["created_user_id"], ["User.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_OrganizationInvitation_organization_id", "OrganizationInvitation",
        ["organization_id"], unique=False,
    )
    op.create_index(
        "ix_OrganizationInvitation_token_hash", "OrganizationInvitation",
        ["token_hash"], unique=True,
    )

    op.create_table(
        "UsageCounter",
        sa.Column("holder_kind", sa.String(length=8), nullable=False),
        # Sin ForeignKey a proposito: apunta a User o a Organization segun
        # holder_kind.
        sa.Column("holder_id", sa.Integer(), nullable=False),
        sa.Column("limit_key", sa.String(length=64), nullable=False),
        sa.Column("period_start", sa.Date(), nullable=False),
        sa.Column("used", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("holder_kind", "holder_id", "limit_key", "period_start"),
    )

    # En modo offline (``alembic upgrade --sql``) no hay conexion que consultar
    # ni ids que recuperar, asi que se emite solo el DDL.
    if op.get_context().as_sql:
        return

    _seed_catalog()


def _seed_catalog() -> None:
    """Inserta los cuatro planes y sus topes.

    Hace falta recuperar los ids generados para poder escribir PlanLimit, asi
    que va en dos pasos: INSERT de planes, SELECT de (id, code), INSERT de
    limites.
    """
    connection = op.get_bind()

    plans_table = sa.table(
        "Plan",
        sa.column("code", sa.String),
        sa.column("name", sa.String),
        sa.column("tagline", sa.String),
        sa.column("rank", sa.Integer),
        sa.column("monthly_price_cents", sa.Integer),
        sa.column("org_addon_price_cents", sa.Integer),
        sa.column("currency", sa.String),
        sa.column("is_public", sa.Boolean),
        sa.column("is_default", sa.Boolean),
        sa.column("created_at", sa.DateTime),
        sa.column("updated_at", sa.DateTime),
    )
    limits_table = sa.table(
        "PlanLimit",
        sa.column("plan_id", sa.Integer),
        sa.column("limit_key", sa.String),
        sa.column("scope", sa.String),
        sa.column("value", sa.Integer),
        sa.column("period", sa.String),
    )

    # Un datetime de Python, no sa.func.now(): estas fechas viajan como valores
    # de un executemany, y una funcion SQL en esa posicion no se renderiza como
    # tal. Naive-UTC, como todas las fechas del esquema.
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    connection.execute(
        plans_table.insert(),
        [
            {
                "code": code, "name": name, "tagline": tagline, "rank": rank,
                "monthly_price_cents": monthly, "org_addon_price_cents": addon,
                "currency": "EUR", "is_public": is_public, "is_default": is_default,
                "created_at": now, "updated_at": now,
            }
            for code, name, tagline, rank, monthly, addon, is_public, is_default in _PLANS
        ],
    )

    plan_ids = {
        row.code: row.id
        for row in connection.execute(
            sa.select(sa.column("id"), sa.column("code")).select_from(sa.table("Plan"))
        )
    }

    rows = []
    for scope, table in (("holder", _HOLDER_LIMITS), ("member", _MEMBER_LIMITS)):
        for limit_key, (period, values_by_plan) in table.items():
            for code, value in values_by_plan.items():
                rows.append({
                    "plan_id":   plan_ids[code],
                    "limit_key": limit_key,
                    "scope":     scope,
                    "value":     value,
                    "period":    period,
                })

    connection.execute(limits_table.insert(), rows)


def downgrade() -> None:
    """Elimina las siete tablas. Se lleva por delante el catalogo entero."""
    op.drop_table("UsageCounter")
    op.drop_index("ix_OrganizationInvitation_token_hash", table_name="OrganizationInvitation")
    op.drop_index("ix_OrganizationInvitation_organization_id", table_name="OrganizationInvitation")
    op.drop_table("OrganizationInvitation")
    op.drop_table("OrganizationMember")
    op.drop_index("ix_Organization_slug", table_name="Organization")
    op.drop_table("Organization")
    op.drop_index("ix_Subscription_external_subscription_ref", table_name="Subscription")
    op.drop_table("Subscription")
    op.drop_table("PlanLimit")
    op.drop_index("ux_plan_single_default", table_name="Plan")
    op.drop_index("ix_Plan_code", table_name="Plan")
    op.drop_table("Plan")
