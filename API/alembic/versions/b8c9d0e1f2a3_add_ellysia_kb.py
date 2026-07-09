"""add Ellysia knowledge base (CveEntry, CpeMatch, KevEntry, EpssScore)

Fase 2 of the Ellysia vulnerability engine: the local mirror of NVD / CISA-KEV /
FIRST-EPSS (the "Ellysia Feed") so version→CVE correlation runs against the local
DB instead of hitting cve.circl.lu per target.

Revision ID: b8c9d0e1f2a3
Revises: a7b8c9d0e1f2
Create Date: 2026-07-05 00:00:01.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = 'b8c9d0e1f2a3'
down_revision: Union[str, Sequence[str], None] = 'a7b8c9d0e1f2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'CveEntry',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('cve_id', sa.String(length=32), nullable=False),
        sa.Column('published', sa.DateTime(), nullable=True),
        sa.Column('last_modified', sa.DateTime(), nullable=True),
        sa.Column('cvss_score', sa.Float(), nullable=True),
        sa.Column('cvss_vector', sa.String(length=255), nullable=True),
        sa.Column('severity', sa.String(length=16), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('cwe_ids', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('source', sa.String(length=16), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_CveEntry_cve_id'), 'CveEntry', ['cve_id'], unique=True)

    op.create_table(
        'CpeMatch',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('cve_id', sa.Integer(), nullable=False),
        sa.Column('vendor', sa.String(length=128), nullable=False),
        sa.Column('product', sa.String(length=128), nullable=False),
        sa.Column('version_start_including', sa.String(length=64), nullable=True),
        sa.Column('version_start_excluding', sa.String(length=64), nullable=True),
        sa.Column('version_end_including', sa.String(length=64), nullable=True),
        sa.Column('version_end_excluding', sa.String(length=64), nullable=True),
        sa.Column('exact_version', sa.String(length=64), nullable=True),
        sa.ForeignKeyConstraint(['cve_id'], ['CveEntry.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_CpeMatch_cve_id'), 'CpeMatch', ['cve_id'], unique=False)
    op.create_index('ix_CpeMatch_vendor_product', 'CpeMatch', ['vendor', 'product'], unique=False)

    op.create_table(
        'KevEntry',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('cve_id', sa.String(length=32), nullable=False),
        sa.Column('date_added', sa.DateTime(), nullable=True),
        sa.Column('due_date', sa.DateTime(), nullable=True),
        sa.Column('known_ransomware', sa.Boolean(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_KevEntry_cve_id'), 'KevEntry', ['cve_id'], unique=True)

    op.create_table(
        'EpssScore',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('cve_id', sa.String(length=32), nullable=False),
        sa.Column('score', sa.Float(), nullable=True),
        sa.Column('percentile', sa.Float(), nullable=True),
        sa.Column('scored_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_EpssScore_cve_id'), 'EpssScore', ['cve_id'], unique=True)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_EpssScore_cve_id'), table_name='EpssScore')
    op.drop_table('EpssScore')
    op.drop_index(op.f('ix_KevEntry_cve_id'), table_name='KevEntry')
    op.drop_table('KevEntry')
    op.drop_index('ix_CpeMatch_vendor_product', table_name='CpeMatch')
    op.drop_index(op.f('ix_CpeMatch_cve_id'), table_name='CpeMatch')
    op.drop_table('CpeMatch')
    op.drop_index(op.f('ix_CveEntry_cve_id'), table_name='CveEntry')
    op.drop_table('CveEntry')
