"""iris: IrisNotificationPreference + IrisMailboxConnection.stuck_alert_sent_at (M08)

La única respuesta de Iris era un correo por cada veredicto Phishing, sin
manera de agrupar el ruido no crítico en un resumen diario, silenciarlo
temporalmente, ni avisar de una conexión que necesita reautorización o
lleva atascada un tiempo. Esta migración añade la tabla de preferencias
(una fila por usuario, creada perezosamente) y la columna que evita
reavisar en cada sondeo de una misma conexión atascada.

Revision ID: 32f0181bf6d7
Revises: 3598857c983f
Create Date: 2026-09-09 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '32f0181bf6d7'
down_revision: Union[str, Sequence[str], None] = '3598857c983f'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('IrisMailboxConnection', sa.Column('stuck_alert_sent_at', sa.DateTime(), nullable=True))

    op.create_table(
        'IrisNotificationPreference',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('digest_enabled', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('muted_until', sa.DateTime(), nullable=True),
        sa.Column('notify_reauth_required', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('notify_sync_stuck', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('digest_last_sent_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['User.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('user_id'),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table('IrisNotificationPreference')
    op.drop_column('IrisMailboxConnection', 'stuck_alert_sent_at')
