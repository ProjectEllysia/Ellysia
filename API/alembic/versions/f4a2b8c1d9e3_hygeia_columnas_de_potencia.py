"""hygeia: columnas de potencia en AssetSnapshot

Revision ID: f4a2b8c1d9e3
Revises: c3a7d1e94b52
Create Date: 2026-09-08 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f4a2b8c1d9e3'
down_revision: Union[str, Sequence[str], None] = 'c3a7d1e94b52'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema.

    Tres columnas nullable, sin ``server_default``: un default de cero
    reescribiría el histórico afirmando que todos los heartbeats anteriores
    midieron 0 W, que es exactamente la mentira que este proyecto entero
    intenta evitar. Las filas anteriores a esta migración se quedan a
    ``NULL`` en las tres, y el gráfico simplemente empieza la traza donde
    hay datos — el mismo comportamiento que ya tienen el resto de columnas
    desnormalizadas de ``AssetSnapshot``.

    ``power_source`` a 64 caracteres para coincidir con la validación del
    schema de ingesta, de modo que un valor que el schema acepta no pueda
    fallar al insertarse.
    """
    op.add_column(
        "AssetSnapshot",
        sa.Column("power_watts", sa.Float(), nullable=True),
    )
    op.add_column(
        "AssetSnapshot",
        sa.Column("power_estimated", sa.Boolean(), nullable=True),
    )
    op.add_column(
        "AssetSnapshot",
        sa.Column("power_source", sa.String(length=64), nullable=True),
    )


def downgrade() -> None:
    """Downgrade schema.

    Se pierde el histórico de potencia ya persistido; ningún otro dato de
    ``AssetSnapshot`` se ve afectado.
    """
    op.drop_column("AssetSnapshot", "power_source")
    op.drop_column("AssetSnapshot", "power_estimated")
    op.drop_column("AssetSnapshot", "power_watts")
