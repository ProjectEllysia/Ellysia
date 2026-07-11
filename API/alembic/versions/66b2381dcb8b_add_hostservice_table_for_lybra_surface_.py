"""add HostService table for Lybra surface tracking

Revision ID: 66b2381dcb8b
Revises: f63e49b0a231
Create Date: 2026-07-11 10:58:32.035811

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '66b2381dcb8b'
down_revision: Union[str, Sequence[str], None] = 'f63e49b0a231'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema.

    Scoped to HostService only — autogenerate also picked up unrelated
    pre-existing drift (Acheron FK naming, MFA index casing, OpenVAS column
    types) that does not belong in this migration; pruned by hand.
    """
    op.create_table('HostService',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('host_id', sa.Integer(), nullable=False),
    sa.Column('port', sa.Integer(), nullable=False),
    sa.Column('protocol', sa.String(length=8), nullable=False),
    sa.Column('name', sa.String(length=64), nullable=True),
    sa.Column('product', sa.String(length=128), nullable=True),
    sa.Column('version', sa.String(length=64), nullable=True),
    sa.Column('cpe', sa.String(length=255), nullable=True),
    sa.Column('first_seen_at', sa.DateTime(), nullable=False),
    sa.Column('last_seen_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['host_id'], ['Host.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('host_id', 'port', 'protocol', name='uq_host_service_host_port_protocol')
    )
    op.create_index(op.f('ix_HostService_host_id'), 'HostService', ['host_id'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_HostService_host_id'), table_name='HostService')
    op.drop_table('HostService')
