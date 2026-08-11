"""hygeia: columnas desnormalizadas de snapshot + kernel/uptime del activo

Revision ID: c2d3e4f5a6b7
Revises: b1c2d3e4f5a6
Create Date: 2026-07-21 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'c2d3e4f5a6b7'
down_revision: Union[str, Sequence[str], None] = 'b1c2d3e4f5a6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema.

    Desnormaliza a columnas propias las métricas escalares por snapshot que
    hasta ahora solo vivían dentro del JSONB ``metrics``, para poder servir
    la serie temporal sin abrirlo. Y recupera ``kernel``/``uptimeSec`` del
    bloque ``host`` del contrato de ingesta, que se validaban y se
    descartaban.

    Todas nullable y sin ``server_default``: ``NULL`` significa "no
    reportado", que es distinto de ``0``, y así no hay reescritura de tabla.
    Sin backfill — las filas históricas se quedan a ``NULL`` y cada traza
    del gráfico empieza donde hay datos.

    ``net_rx_bps``/``net_tx_bps`` son BigInteger a propósito: 10 GbE son
    1,25e9 B/s, ya al borde de int32.
    """
    op.add_column('AssetSnapshot', sa.Column('swap_pct', sa.Float(), nullable=True))
    op.add_column('AssetSnapshot', sa.Column('load1', sa.Float(), nullable=True))
    op.add_column('AssetSnapshot', sa.Column('disk_max_pct', sa.Float(), nullable=True))
    op.add_column('AssetSnapshot', sa.Column('disk_max_mount', sa.String(length=256), nullable=True))
    op.add_column('AssetSnapshot', sa.Column('net_rx_bps', sa.BigInteger(), nullable=True))
    op.add_column('AssetSnapshot', sa.Column('net_tx_bps', sa.BigInteger(), nullable=True))

    op.add_column('MonitoredAsset', sa.Column('kernel', sa.String(length=128), nullable=True))
    op.add_column('MonitoredAsset', sa.Column('uptime_sec', sa.Integer(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('MonitoredAsset', 'uptime_sec')
    op.drop_column('MonitoredAsset', 'kernel')

    op.drop_column('AssetSnapshot', 'net_tx_bps')
    op.drop_column('AssetSnapshot', 'net_rx_bps')
    op.drop_column('AssetSnapshot', 'disk_max_mount')
    op.drop_column('AssetSnapshot', 'disk_max_pct')
    op.drop_column('AssetSnapshot', 'load1')
    op.drop_column('AssetSnapshot', 'swap_pct')
