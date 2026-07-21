"""add authorized target register

Revision ID: f63e49b0a231
Revises: e9e894e2791e
Create Date: 2026-07-09 20:43:23.068481

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f63e49b0a231'
down_revision: Union[str, Sequence[str], None] = 'e9e894e2791e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table('AuthorizedTarget',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('target', sa.String(length=64), nullable=False),
    sa.Column('label', sa.String(length=255), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['User.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('user_id', 'target', name='uq_authorizedtarget_user_target')
    )
    op.create_index(op.f('ix_AuthorizedTarget_user_id'), 'AuthorizedTarget', ['user_id'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_AuthorizedTarget_user_id'), table_name='AuthorizedTarget')
    op.drop_table('AuthorizedTarget')
