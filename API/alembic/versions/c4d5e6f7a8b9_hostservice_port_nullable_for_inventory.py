"""HostService.port nullable for inventory-origin services (Fase 0.9)

Revision ID: c4d5e6f7a8b9
Revises: b3c4d5e6f7a8
Create Date: 2026-07-28 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c4d5e6f7a8b9'
down_revision: Union[str, Sequence[str], None] = 'b3c4d5e6f7a8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema.

    A Service whose ``origin`` is ``"inventory"`` (Fase 0.9 — an installed
    package, not a listening socket) commonly has no port at all, but surface
    tracking (Fase 5's ``HostService``) required one. The application-level
    identity key already handles the ``NULL`` case (falls back to ``product``
    — see ``LybraEngineManager._surface_key`` and
    ``ScanRepository.upsert_host_service``); this migration only lifts the
    column constraint that was blocking it from being written at all.
    """
    op.alter_column('HostService', 'port', existing_type=sa.Integer(), nullable=True)


def downgrade() -> None:
    """Downgrade schema."""
    op.alter_column('HostService', 'port', existing_type=sa.Integer(), nullable=False)
