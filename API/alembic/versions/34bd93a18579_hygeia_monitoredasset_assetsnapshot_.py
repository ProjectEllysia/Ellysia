"""hygeia: MonitoredAsset, AssetSnapshot, Anomaly

Revision ID: 34bd93a18579
Revises: 3e6128d45a70
Create Date: 2026-07-20 18:06:17.988806

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '34bd93a18579'
down_revision: Union[str, Sequence[str], None] = '3e6128d45a70'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema.

    Solo las tres tablas nuevas de Hygeia. El autogenerate detectó además
    deriva preexistente y no relacionada (nombres de FK/índices de Acheron,
    un tipo de columna en OpenVASVulnerability) que se ha excluido a mano de
    esta migración: no es responsabilidad de este cambio y no debe mezclarse
    con él (regla del repo: sin cambios destructivos, sin tocar lo existente).
    """
    op.create_table('MonitoredAsset',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('hostname', sa.String(length=255), nullable=False),
    sa.Column('os', sa.String(length=64), nullable=True),
    sa.Column('labels', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('agent_key_id', sa.String(length=32), nullable=False),
    sa.Column('agent_key_hash', sa.String(length=255), nullable=False),
    sa.Column('agent_version', sa.String(length=32), nullable=True),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('last_seen_at', sa.DateTime(), nullable=True),
    sa.Column('heartbeat_interval_sec', sa.Integer(), nullable=True),
    sa.Column('breach_counters', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('thresholds', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['User.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_MonitoredAsset_agent_key_id'), 'MonitoredAsset', ['agent_key_id'], unique=True)
    op.create_table('Anomaly',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('asset_id', sa.Integer(), nullable=False),
    sa.Column('kind', sa.String(length=48), nullable=False),
    sa.Column('severity', sa.String(length=16), nullable=False),
    sa.Column('metric', sa.String(length=64), nullable=True),
    sa.Column('value', sa.Float(), nullable=True),
    sa.Column('threshold', sa.Float(), nullable=True),
    sa.Column('details', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('state', sa.String(length=16), nullable=False),
    sa.Column('opened_at', sa.DateTime(), nullable=False),
    sa.Column('resolved_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['asset_id'], ['MonitoredAsset.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_Anomaly_asset_id'), 'Anomaly', ['asset_id'], unique=False)
    op.create_index(op.f('ix_Anomaly_opened_at'), 'Anomaly', ['opened_at'], unique=False)
    op.create_table('AssetSnapshot',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('asset_id', sa.Integer(), nullable=False),
    sa.Column('collected_at', sa.DateTime(), nullable=False),
    sa.Column('received_at', sa.DateTime(), nullable=False),
    sa.Column('metrics', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('cpu_pct', sa.Float(), nullable=True),
    sa.Column('mem_pct', sa.Float(), nullable=True),
    sa.ForeignKeyConstraint(['asset_id'], ['MonitoredAsset.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_AssetSnapshot_asset_id'), 'AssetSnapshot', ['asset_id'], unique=False)
    op.create_index(op.f('ix_AssetSnapshot_collected_at'), 'AssetSnapshot', ['collected_at'], unique=False)
    op.create_index('ix_snapshot_asset_time', 'AssetSnapshot', ['asset_id', 'collected_at'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('ix_snapshot_asset_time', table_name='AssetSnapshot')
    op.drop_index(op.f('ix_AssetSnapshot_collected_at'), table_name='AssetSnapshot')
    op.drop_index(op.f('ix_AssetSnapshot_asset_id'), table_name='AssetSnapshot')
    op.drop_table('AssetSnapshot')
    op.drop_index(op.f('ix_Anomaly_opened_at'), table_name='Anomaly')
    op.drop_index(op.f('ix_Anomaly_asset_id'), table_name='Anomaly')
    op.drop_table('Anomaly')
    op.drop_index(op.f('ix_MonitoredAsset_agent_key_id'), table_name='MonitoredAsset')
    op.drop_table('MonitoredAsset')
