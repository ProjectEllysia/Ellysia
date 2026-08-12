"""hygeia: etiquetas de activos (HygeiaTag + AssetTag)

Hygeia listaba los activos como una tira plana ordenada por fecha de alta.
Con media docena de agentes eso basta; con treinta no hay forma de agrupar
"los de produccion", "los que dan la cara a Internet" o "los que puedo apagar
sin avisar a nadie". La columna ``labels`` (JSONB) prometia eso y nunca lo
cumplio: se acepta en el alta, se serializa, y ningun endpoint la escribe ni
ninguna consulta la lee. Se deja donde esta, intacta; esto no la sustituye ni
la migra, la ignora.

``HygeiaTag`` es una etiqueta de verdad: una entidad compartida entre activos.
Hay dos clases y comparten tabla (herencia *single-table*, discriminada por
``tag_type``), porque desde el punto de vista de un activo son la misma cosa,
un nombre y un color que se le cuelgan. Lo unico que las distingue es de
quien son:

  - ``system``: catalogo comun. ``user_id`` es NULL, todo el mundo las ve y
    nadie las crea ni las borra. Son las 12 filas que siembra esta revision.
  - ``user``: repositorio personal. ``user_id`` es obligatorio y solo su
    dueño la ve, la asigna y la borra.

El ``CheckConstraint`` impone esa regla en la base de datos y no solo en el
manager: ni una migracion torcida ni un INSERT a mano pueden dejar una
etiqueta personal huerfana ni una de sistema con dueño.

Los dos ``ondelete="CASCADE"`` de ``AssetTag`` son la garantia que pide el
producto: borrar una etiqueta borra sus asociaciones, **nunca los activos**
que la llevaban.

La siembra va aqui y no en ``_init_db()`` porque ``_init_db()`` es destructivo
y no se puede ejecutar en un entorno con datos: el catalogo tiene que llegar
por ``alembic upgrade head``. Las instalaciones nuevas lo reciben igual, ya
que ``_init_db()`` ejecuta las migraciones.

Revision ID: b7c8d9e0f1a2
Revises: a6b7c8d9e0f1
Create Date: 2026-08-12 00:00:00.000000

"""
from datetime import datetime, timezone
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "b7c8d9e0f1a2"
down_revision: Union[str, Sequence[str], None] = "a6b7c8d9e0f1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Catalogo comun, en cuatro ejes: entorno, rol, criticidad/exposicion y
# ubicacion. El color se comparte dentro de cada eje para que una tira de
# badges se lea de un vistazo sin tener que descifrar doce tonos distintos.
# No hay "Windows" ni "Linux": eso ya es ``MonitoredAsset.os``.
_SYSTEM_TAGS = [
    ("Producción",           "red"),
    ("Preproducción",        "amber"),
    ("Desarrollo",           "blue"),
    ("Servidor web",         "violet"),
    ("Base de datos",        "violet"),
    ("Workstation",          "violet"),
    ("Crítico",              "red"),
    ("Expuesto a Internet",  "pink"),
    ("Cloud",                "teal"),
    ("On-premise",           "teal"),
    ("Contenedor",           "green"),
    ("Backup",               "slate"),
]


def upgrade() -> None:
    """Upgrade schema."""
    hygeia_tag = op.create_table(
        "HygeiaTag",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("name", sa.String(length=48), nullable=False),
        sa.Column("color", sa.String(length=16), nullable=False, server_default="slate"),
        sa.Column("tag_type", sa.String(length=16), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["User.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        # Un usuario no repite nombre. Las de sistema quedan fuera (en Postgres
        # los NULL son distintos entre si) y no hace falta mas: su unico
        # escritor es esta migracion.
        sa.UniqueConstraint("user_id", "name", name="uq_hygeiatag_user_name"),
        sa.CheckConstraint(
            "(tag_type = 'system' AND user_id IS NULL) OR "
            "(tag_type = 'user' AND user_id IS NOT NULL)",
            name="ck_hygeiatag_owner",
        ),
    )
    op.create_index("ix_hygeiatag_user", "HygeiaTag", ["user_id"])

    op.create_table(
        "AssetTag",
        sa.Column("asset_id", sa.Integer(), nullable=False),
        sa.Column("tag_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["MonitoredAsset.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tag_id"], ["HygeiaTag.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("asset_id", "tag_id"),
    )

    # `created_at` va como valor de Python y no como `sa.func.now()`: los
    # valores de `bulk_insert` viajan como parametros bindeados, y una funcion
    # SQL ahi se enviaria como literal en vez de ejecutarse.
    seeded_at = datetime.now(timezone.utc).replace(tzinfo=None)
    op.bulk_insert(
        hygeia_tag,
        [
            {
                "name": name,
                "color": color,
                "tag_type": "system",
                "user_id": None,
                "created_at": seeded_at,
            }
            for name, color in _SYSTEM_TAGS
        ],
    )


def downgrade() -> None:
    """Downgrade schema."""
    # Primero las asociaciones: sus FK apuntan a la tabla de etiquetas.
    op.drop_table("AssetTag")
    op.drop_index("ix_hygeiatag_user", table_name="HygeiaTag")
    op.drop_table("HygeiaTag")
