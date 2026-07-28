"""LybraScan.asset_id — provenance of an inventory-originated scan (Fase I)

Revision ID: d5e6f7a8b9c0
Revises: c4d5e6f7a8b9
Create Date: 2026-07-28 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd5e6f7a8b9c0'
down_revision: Union[str, Sequence[str], None] = 'c4d5e6f7a8b9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema.

    Records which Hygeia ``MonitoredAsset``'s software inventory produced a
    Lybra scan (Fase I), so those scans can be browsed per-agent instead of
    being mixed into the panel-launched feed.

    Deliberately **no ForeignKey**: it is a soft reference, so that Themis's
    schema stays independent of Hygeia's (no module under ``features/``
    depends on another at the database level). Deleting an asset therefore
    cleans up its scans explicitly, in ``HygeiaAssetManager.delete_asset``.

    Additive and nullable: every existing scan keeps ``asset_id = NULL``,
    which is exactly what "launched from the Themis panel" means, so no
    backfill is needed and no existing scan changes behaviour.
    """
    op.add_column('LybraScan', sa.Column('asset_id', sa.Integer(), nullable=True))
    op.create_index(op.f('ix_LybraScan_asset_id'), 'LybraScan', ['asset_id'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_LybraScan_asset_id'), table_name='LybraScan')
    op.drop_column('LybraScan', 'asset_id')
