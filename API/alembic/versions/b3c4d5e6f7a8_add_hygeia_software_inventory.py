"""hygeia: inventario de software del activo (contrato de ingesta v1.0)

Revision ID: b3c4d5e6f7a8
Revises: e1f2a3b4c5d6
Create Date: 2026-07-25 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'b3c4d5e6f7a8'
down_revision: Union[str, Sequence[str], None] = 'e1f2a3b4c5d6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema.

    Añade el inventario de software (``inventory``) del contrato de ingesta
    v1.0: campo opcional a nivel de ``Payload``, presente solo tras un
    escaneo del agente (cadencia independiente, típicamente cada 6h). Sin
    "delta": cada escaneo trae el estado completo, así que se persiste como
    un único JSONB por activo que se reemplaza entero en cada ingesta con
    inventario, en vez de una tabla por aplicación.

    Ambas columnas nullable y sin ``server_default``: ``NULL`` en
    ``inventory`` significa "nunca ha escaneado" (agente antiguo, o primer
    heartbeat aún no procesado), distinto de una lista vacía (escaneó y no
    encontró software — stub de Linux/macOS, o host realmente vacío).
    """
    op.add_column('MonitoredAsset', sa.Column('inventory', postgresql.JSONB(), nullable=True))
    op.add_column('MonitoredAsset', sa.Column('inventory_collected_at', sa.DateTime(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('MonitoredAsset', 'inventory_collected_at')
    op.drop_column('MonitoredAsset', 'inventory')
