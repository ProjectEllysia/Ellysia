"""system: TaskDispatch outbox table (B08)

``analyze()`` (y cualquier otro create-then-enqueue) hacía commit de su
entidad antes de publicar el job en TaskQueue -- si la API se reiniciaba o
Redis fallaba justo en esa ventana, la fila quedaba en BD sin ningún trabajo
que la fuera a procesar. TaskDispatch persiste la intención de publicar en
la MISMA transacción que la entidad; ``OutboxDispatcher`` (system/taskqueue/
outbox.py) la publica después, con reintento vía barrido periódico y
reconciliación de arranque.

Revision ID: af1b51ec6c76
Revises: b615bd3abb26
Create Date: 2026-09-09 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = 'af1b51ec6c76'
down_revision: Union[str, Sequence[str], None] = 'b615bd3abb26'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'TaskDispatch',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('func_path', sa.String(length=255), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('category', sa.String(length=64), nullable=False),
        sa.Column('args', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('kwargs', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('external_id', sa.String(length=255), nullable=True),
        sa.Column('timeout', sa.Integer(), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('attempts', sa.Integer(), nullable=False),
        sa.Column('last_error', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('dispatched_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        op.f('ix_TaskDispatch_status'), 'TaskDispatch', ['status'],
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_TaskDispatch_status'), table_name='TaskDispatch')
    op.drop_table('TaskDispatch')
