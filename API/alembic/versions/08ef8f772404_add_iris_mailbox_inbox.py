"""iris: IrisMailboxInbox (B01 -- checkpoint de ingesta por mensaje)

``IrisMailboxManager._finish_sync`` confirmaba el cursor del proveedor
(``sync_cursor``) tanto si el lote de mensajes se ingería entero como si no.
Una cuota agotada o un fallo a mitad de lote perdían en silencio los mensajes
que quedaban sin procesar, porque ni Gmail ni Graph vuelven a devolver un
mensaje una vez el cursor avanza más allá de él.

``IrisMailboxInbox`` es la cola intermedia que resuelve esto: cada mensaje
que devuelve ``list_new`` se encola aquí antes de intentar ingerirlo, y el
cursor del proveedor solo se confirma cuando la cola de la conexión queda
vacía (ver ``IrisMailboxManager._sync_connection``/``_finish_sync``). Una
referencia que agota ``iris.maxInboxAttempts`` pasa a ``status="dead"``
-- visible, pero ya no bloquea el avance del cursor.

Revision ID: 08ef8f772404
Revises: c8b1d4e6f9a2
Create Date: 2026-09-08 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = '08ef8f772404'
down_revision: Union[str, Sequence[str], None] = 'c8b1d4e6f9a2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'IrisMailboxInbox',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('connection_id', sa.Integer(), nullable=False),
        sa.Column('provider_message_id', sa.String(length=255), nullable=False),
        sa.Column('raw_ref', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('attempts', sa.Integer(), nullable=False),
        sa.Column('last_error', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['connection_id'], ['IrisMailboxConnection.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('connection_id', 'provider_message_id',
                             name='uq_iris_mailbox_inbox_connection_message'),
    )
    op.create_index(
        op.f('ix_IrisMailboxInbox_connection_id'), 'IrisMailboxInbox', ['connection_id'],
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_IrisMailboxInbox_connection_id'), table_name='IrisMailboxInbox')
    op.drop_table('IrisMailboxInbox')
