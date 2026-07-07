"""add EllysiaScan.deep_scan_ids (Fase 6 deep analysis)

Fase 6 of the Ellysia vulnerability engine: "análisis profundo" launches
Nmap/Nikto/OpenVAS as corroborator scans alongside an Ellysia scan. Each stays
an ordinary, independently-tracked Scan; deep_scan_ids just remembers which
ones belong to this Ellysia scan so its results view can merge their Finding
rows in at read time (see EllysiaEngineManager.format_scan / _launch_deep_corroborators).

Revision ID: c9d0e1f2a3b4
Revises: b8c9d0e1f2a3
Create Date: 2026-07-07 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = 'c9d0e1f2a3b4'
down_revision: Union[str, Sequence[str], None] = 'b8c9d0e1f2a3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        'EllysiaScan',
        sa.Column('deep_scan_ids', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('EllysiaScan', 'deep_scan_ids')
