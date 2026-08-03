"""add NucleiScan (Fase U1: Nuclei as a first-class scan type)

Nuclei follows the ``LybraScan`` shape, not the Nmap/Nikto/OpenVAS one: no
result table of its own — every finding it produces lives in the shared
``Finding`` table via ``nuclei_result_to_finding`` (see
``plans/feature/themis/lybra-engine-roadmap.md``, Fase U). This migration only
adds the thin polymorphic subtype; ``Finding`` already exists and needs no
change to accept ``source="nuclei"`` rows.

Revision ID: e2f3a4b5c6d7
Revises: d5e6f7a8b9c0
Create Date: 2026-07-30 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e2f3a4b5c6d7'
down_revision: Union[str, Sequence[str], None] = 'd5e6f7a8b9c0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'NucleiScan',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['id'], ['Scan.id'], ),
        sa.PrimaryKeyConstraint('id'),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table('NucleiScan')
