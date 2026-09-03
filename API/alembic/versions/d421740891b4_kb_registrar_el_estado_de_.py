"""kb: registrar el estado de sincronizacion por fuente

Revision ID: d421740891b4
Revises: c7e1a9f4b2d8
Create Date: 2026-09-03 19:11:39.703210

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd421740891b4'
down_revision: Union[str, Sequence[str], None] = 'c7e1a9f4b2d8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema.

    Una fila por fuente de la KB (NVD, KEV, EPSS) con cuándo se intentó
    sincronizar por última vez, cuándo funcionó, cuántas filas escribió y qué
    error dio si falló.

    Sin esto, una sincronización rota es invisible: los escaneos siguen
    saliendo en verde contra un catálogo congelado porque el motor no tiene
    forma de saber que dejó de aprender. La tabla nace vacía y se rellena en la
    primera sincronización de cada fuente; hasta entonces, "nunca sincronizada"
    es la respuesta correcta y no un hueco.

    ``source`` es único porque esto es un estado, no un historial: una fila por
    fuente, sobrescrita en cada intento. El historial vive en los logs.
    """
    op.create_table(
        "KbSyncStatus",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("last_attempt_at", sa.DateTime(), nullable=True),
        sa.Column("last_success_at", sa.DateTime(), nullable=True),
        sa.Column("rows_upserted", sa.Integer(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_KbSyncStatus_source"), "KbSyncStatus", ["source"], unique=True)


def downgrade() -> None:
    """Downgrade schema.

    Se pierde el registro de sincronizaciones, que es observabilidad y no
    datos: la KB en sí —CVEs, KEV, EPSS— no se toca, y la siguiente subida
    vuelve a empezar a registrar desde cero.
    """
    op.drop_index(op.f("ix_KbSyncStatus_source"), table_name="KbSyncStatus")
    op.drop_table("KbSyncStatus")
