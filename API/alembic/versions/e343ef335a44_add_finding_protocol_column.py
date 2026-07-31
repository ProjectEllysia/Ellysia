"""add finding protocol column

Roadmap Lybra §6.3, Ronda 1: añade ``Finding.protocol`` para que
``compute_dedup_key`` distinga un servicio en 161/tcp de otro en 161/udp del
mismo host. Nullable y sin backfill: todo hallazgo anterior a esta ronda es
TCP y no necesita reescribirse.

El autogenerate de esta revisión arrastraba deriva preexistente y ajena a este
cambio (renombrados de índice case-sensitive, recreación de FKs, y el tipo
REAL→Float(3) de ``OpenVASVulnerability`` que varias migraciones anteriores ya
documentan como excluida a mano) — se descarta y se deja solo la columna.

Revision ID: e343ef335a44
Revises: d1e2f3a4b5c6
Create Date: 2026-07-31 20:22:20.394704

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e343ef335a44'
down_revision: Union[str, Sequence[str], None] = 'd1e2f3a4b5c6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('Finding', sa.Column('protocol', sa.String(length=8), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('Finding', 'protocol')
