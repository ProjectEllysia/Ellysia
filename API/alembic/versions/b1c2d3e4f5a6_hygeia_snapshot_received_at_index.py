"""hygeia: índice (asset_id, received_at) para la serie temporal

Revision ID: b1c2d3e4f5a6
Revises: 34bd93a18579
Create Date: 2026-07-21 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'b1c2d3e4f5a6'
down_revision: Union[str, Sequence[str], None] = '34bd93a18579'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema.

    La serie temporal de un activo pasa a ordenarse y podarse por
    ``received_at`` (reloj del servidor) en lugar de ``collected_at`` (reloj
    del agente). Sin este índice, el ``ORDER BY ... DESC LIMIT`` de
    ``get_series`` ordenaría la partición entera del activo — hasta 30 días
    de heartbeats — en cada carga del gráfico.

    ``ix_snapshot_asset_time`` se conserva: la columna ``collected_at`` sigue
    existiendo y expuesta, y eliminar un índice no es responsabilidad de un
    cambio que solo añade una ruta de acceso.
    """
    op.create_index(
        'ix_snapshot_asset_received', 'AssetSnapshot', ['asset_id', 'received_at'],
        unique=False,
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('ix_snapshot_asset_received', table_name='AssetSnapshot')
