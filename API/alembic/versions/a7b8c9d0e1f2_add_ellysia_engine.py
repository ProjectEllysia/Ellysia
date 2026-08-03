"""add Ellysia engine (Finding, EllysiaScan) + OpenPort.cpe

Fase 0 of the Ellysia vulnerability engine (see plans/feature/themis/lybra-engine-roadmap.md):

- ``OpenPort.cpe``: stop dropping the CPE Nmap already emits with ``-sV`` so the
  engine can read it for version→CVE correlation in later phases.
- ``EllysiaScan``: polymorphic Scan subtype for the engine; in this phase it
  references the source Nmap scan whose services were analysed.
- ``Finding``: normalized, scanner-independent finding model. Only informational
  "open port" findings are written for now; the detection columns stay empty
  until Fase 1/R.

Revision ID: a7b8c9d0e1f2
Revises: f6a7b8c9d0e1
Create Date: 2026-07-05 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = 'a7b8c9d0e1f2'
down_revision: Union[str, Sequence[str], None] = 'f6a7b8c9d0e1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # 1) Capture the CPE Nmap already parses.
    op.add_column('OpenPort', sa.Column('cpe', sa.String(length=255), nullable=True))

    # 2) Ellysia's polymorphic Scan subtype.
    op.create_table(
        'EllysiaScan',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('source_scan_id', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['id'], ['Scan.id'], ),
        sa.ForeignKeyConstraint(['source_scan_id'], ['Scan.id'], ),
        sa.PrimaryKeyConstraint('id'),
    )

    # 3) Unified, scanner-independent finding model.
    op.create_table(
        'Finding',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('scan_id', sa.Integer(), nullable=False),
        sa.Column('host_id', sa.Integer(), nullable=True),
        sa.Column('title', sa.Text(), nullable=False),
        sa.Column('category', sa.String(length=64), nullable=True),
        sa.Column('port', sa.Integer(), nullable=True),
        sa.Column('service', sa.String(length=128), nullable=True),
        sa.Column('cpe', sa.String(length=255), nullable=True),
        sa.Column('cve_ids', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('cvss_score', sa.Float(), nullable=True),
        sa.Column('cvss_vector', sa.String(length=255), nullable=True),
        sa.Column('epss_score', sa.Float(), nullable=True),
        sa.Column('in_kev', sa.Boolean(), nullable=True),
        sa.Column('exploit_maturity', sa.String(length=16), nullable=True),
        sa.Column('source', sa.String(length=32), nullable=True),
        sa.Column('check_id', sa.String(length=128), nullable=True),
        sa.Column('feed_version', sa.String(length=32), nullable=True),
        sa.Column('dedup_key', sa.String(length=64), nullable=True),
        sa.Column('qod', sa.Integer(), nullable=True),
        sa.Column('confirmed', sa.Boolean(), nullable=True),
        sa.Column('first_seen_at', sa.DateTime(), nullable=True),
        sa.Column('last_seen_at', sa.DateTime(), nullable=True),
        sa.Column('state', sa.String(length=20), nullable=True),
        sa.ForeignKeyConstraint(['scan_id'], ['Scan.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['host_id'], ['Host.id'], ),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_Finding_scan_id'), 'Finding', ['scan_id'], unique=False)
    op.create_index(op.f('ix_Finding_host_id'), 'Finding', ['host_id'], unique=False)
    op.create_index(op.f('ix_Finding_cpe'), 'Finding', ['cpe'], unique=False)
    op.create_index(op.f('ix_Finding_source'), 'Finding', ['source'], unique=False)
    op.create_index(op.f('ix_Finding_dedup_key'), 'Finding', ['dedup_key'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_Finding_dedup_key'), table_name='Finding')
    op.drop_index(op.f('ix_Finding_source'), table_name='Finding')
    op.drop_index(op.f('ix_Finding_cpe'), table_name='Finding')
    op.drop_index(op.f('ix_Finding_host_id'), table_name='Finding')
    op.drop_index(op.f('ix_Finding_scan_id'), table_name='Finding')
    op.drop_table('Finding')
    op.drop_table('EllysiaScan')
    op.drop_column('OpenPort', 'cpe')
