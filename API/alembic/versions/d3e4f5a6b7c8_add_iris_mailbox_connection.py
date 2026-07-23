"""iris: IrisMailboxConnection + IrisAnalysis.connection_id/source_message_uid

Fase 3 del conector de buzón de Iris
(plans/feature/iris/iris-mailbox-connector.md). IrisMailboxConnection guarda
una cuenta de correo externa (Gmail/Microsoft 365) conectada por un usuario
para ingesta automática -- el refresh token se persiste cifrado
(shared._crypto, purpose="iris_mailbox"), nunca en claro. IrisAnalysis gana
dos columnas opcionales (NULL para el flujo manual existente, que no cambia)
para saber de qué conexión/mensaje vino un análisis automático, con una
UNIQUE constraint que da idempotencia gratis ante reintentos del sync.

Revision ID: d3e4f5a6b7c8
Revises: c2d3e4f5a6b7
Create Date: 2026-07-22 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd3e4f5a6b7c8'
down_revision: Union[str, Sequence[str], None] = 'c2d3e4f5a6b7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'IrisMailboxConnection',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('provider', sa.String(length=20), nullable=False),
        sa.Column('account_email', sa.String(length=320), nullable=False),
        sa.Column('scopes', sa.String(length=512), nullable=False),
        sa.Column('refresh_token_enc', sa.Text(), nullable=False),
        sa.Column('access_token_enc', sa.Text(), nullable=True),
        sa.Column('access_token_expires_at', sa.DateTime(), nullable=True),
        sa.Column('folder', sa.String(length=255), nullable=True),
        sa.Column('full_message_mode', sa.Boolean(), nullable=False),
        sa.Column('sync_cursor', sa.String(length=255), nullable=True),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('ingested_today', sa.Integer(), nullable=False),
        sa.Column('ingested_reset_date', sa.Date(), nullable=True),
        sa.Column('last_sync_at', sa.DateTime(), nullable=True),
        sa.Column('last_error', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['User.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('user_id', 'provider', 'account_email',
                             name='uq_iris_mailbox_connection_user_provider_email'),
    )

    op.add_column('IrisAnalysis', sa.Column('connection_id', sa.Integer(), nullable=True))
    op.add_column('IrisAnalysis', sa.Column('source_message_uid', sa.String(length=255), nullable=True))
    op.create_foreign_key(
        'fk_iris_analysis_connection_id', 'IrisAnalysis', 'IrisMailboxConnection',
        ['connection_id'], ['id'],
    )
    op.create_unique_constraint(
        'uq_iris_analysis_connection_source_message', 'IrisAnalysis',
        ['connection_id', 'source_message_uid'],
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_constraint('uq_iris_analysis_connection_source_message', 'IrisAnalysis', type_='unique')
    op.drop_constraint('fk_iris_analysis_connection_id', 'IrisAnalysis', type_='foreignkey')
    op.drop_column('IrisAnalysis', 'source_message_uid')
    op.drop_column('IrisAnalysis', 'connection_id')
    op.drop_table('IrisMailboxConnection')
