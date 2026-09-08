"""hygeia: sistema y rol de virtualización del host

Revision ID: c8b1d4e6f9a2
Revises: f4a2b8c1d9e3
Create Date: 2026-09-08 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c8b1d4e6f9a2'
down_revision: Union[str, Sequence[str], None] = 'f4a2b8c1d9e3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema.

    Dos columnas nullable, sin ``server_default``: un activo dado de alta
    antes de esta migración (o un agente que aún no reporte estos campos)
    no tiene forma legítima de rellenarlas — no es lo mismo "no se sabe" que
    "no es una máquina virtual", así que ``NULL`` es el único valor honesto
    para el histórico.
    """
    op.add_column(
        "MonitoredAsset",
        sa.Column("virtualization_system", sa.String(length=32), nullable=True),
    )
    op.add_column(
        "MonitoredAsset",
        sa.Column("virtualization_role", sa.String(length=32), nullable=True),
    )


def downgrade() -> None:
    """Downgrade schema.

    Se pierde la distinción entre "no hay sensores" y "es una máquina
    virtual" para el mensaje de potencia; ningún otro dato de
    ``MonitoredAsset`` se ve afectado.
    """
    op.drop_column("MonitoredAsset", "virtualization_role")
    op.drop_column("MonitoredAsset", "virtualization_system")
