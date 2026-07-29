"""CpeProductAlias — normalized product-name index derived from CpeMatch (Fase I-b)

Revision ID: e6f7a8b9c0d1
Revises: d5e6f7a8b9c0
Create Date: 2026-07-29 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e6f7a8b9c0d1'
down_revision: Union[str, Sequence[str], None] = 'd5e6f7a8b9c0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema.

    Adds the table the automated CPE-resolution index lives in (Fase I-b,
    paso 2 of the Lybra roadmap's inventory-matching gap): a normalized
    product name -> (vendor, product) mapping, derived wholesale from
    CpeMatch and rebuilt after every NVD sync — never written incrementally.
    Starts empty; ``KbSyncManager.rebuild_cpe_product_index()`` populates it
    on the next sync (or can be run manually right away).
    """
    op.create_table(
        'CpeProductAlias',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('normalized_name', sa.String(length=256), nullable=False),
        sa.Column('vendor', sa.String(length=128), nullable=False),
        sa.Column('product', sa.String(length=128), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        op.f('ix_CpeProductAlias_normalized_name'), 'CpeProductAlias', ['normalized_name'], unique=True,
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_CpeProductAlias_normalized_name'), table_name='CpeProductAlias')
    op.drop_table('CpeProductAlias')
