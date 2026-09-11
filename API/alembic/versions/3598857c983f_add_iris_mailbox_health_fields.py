"""iris: IrisMailboxConnection.last_success_at/last_sync_duration_ms/messages_discovered_total (M10)

Un administrador no podía distinguir "no hay correo nuevo" de "Iris está
atascado" sin leer los logs del servidor: ``last_sync_at`` se actualizaba
igual tanto si el sync terminaba limpio como si dejaba mensajes atascados
por cuota o por un fallo. Estas tres columnas, junto con contar en vivo las
tablas ``IrisMailboxInbox``/``IrisAnalysis`` (ver el nuevo endpoint
``GET /iris/mailbox/connections/<id>/health``), dan la observabilidad que
faltaba sin necesidad de mirar logs.

Revision ID: 3598857c983f
Revises: ce173ee66b76
Create Date: 2026-09-09 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '3598857c983f'
down_revision: Union[str, Sequence[str], None] = 'ce173ee66b76'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('IrisMailboxConnection', sa.Column('last_success_at', sa.DateTime(), nullable=True))
    op.add_column('IrisMailboxConnection', sa.Column('last_sync_duration_ms', sa.Integer(), nullable=True))
    op.add_column(
        'IrisMailboxConnection',
        sa.Column('messages_discovered_total', sa.Integer(), nullable=False, server_default='0'),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('IrisMailboxConnection', 'messages_discovered_total')
    op.drop_column('IrisMailboxConnection', 'last_sync_duration_ms')
    op.drop_column('IrisMailboxConnection', 'last_success_at')
