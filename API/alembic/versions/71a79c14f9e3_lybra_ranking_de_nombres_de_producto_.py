"""lybra: ranking de nombres de producto sin resolver

Revision ID: 71a79c14f9e3
Revises: 8b44c3d0a5b1
Create Date: 2026-09-03 20:11:09.142082

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '71a79c14f9e3'
down_revision: Union[str, Sequence[str], None] = '8b44c3d0a5b1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema.

    Un nombre por fila y por origen, con su contador. Es el documento de
    trabajo del feed curado de alias: cada línea es un alias que merece la pena
    escribir, ordenado por cuánto duele no tenerlo.

    La tabla nace vacía y se llena sola con el primer escaneo. No hay backfill
    posible ni deseable: los hallazgos antiguos guardan que la resolución falló
    (`Finding.cpe_resolved`) pero no **con qué** nombre, que es justo lo que
    faltaba.

    El único constraint que importa es el de unicidad por `(normalized_name,
    origin)`: sin él, cada escaneo insertaría filas nuevas en vez de sumar al
    contador, y el ranking mediría cuántas veces se ha escaneado en lugar de
    cuánto falla cada nombre.
    """
    op.create_table(
        "UnresolvedProduct",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("normalized_name", sa.String(length=255), nullable=False),
        sa.Column("origin", sa.String(length=32), nullable=False),
        sa.Column("occurrences", sa.Integer(), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("normalized_name", "origin", name="unique_unresolved_product"),
    )
    op.create_index(op.f("ix_UnresolvedProduct_normalized_name"), "UnresolvedProduct",
                    ["normalized_name"], unique=False)


def downgrade() -> None:
    """Downgrade schema.

    Se pierde el ranking, que es observabilidad: ningún hallazgo ni ningún dato
    de la KB depende de esta tabla. Se vuelve a llenar sola en cuanto se
    reinstale, escaneo a escaneo.
    """
    op.drop_index(op.f("ix_UnresolvedProduct_normalized_name"), table_name="UnresolvedProduct")
    op.drop_table("UnresolvedProduct")
