"""iris: IrisMailboxConnection.sync_started_at/sync_job_id (B02 -- lock de sync)

``IrisMailboxManager`` no exponía si una conexión tenía un sync en curso en
ese momento -- la UI no tenía forma de distinguir "acaba de terminar" de
"está sincronizando ahora mismo" sin adivinarlo. Estas dos columnas se
rellenan al adquirir el lock distribuido de sync (``services/mailbox/locks.py``)
y se limpian al terminar, éxito o error.

Revision ID: 55b8d888d404
Revises: 08ef8f772404
Create Date: 2026-09-08 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '55b8d888d404'
down_revision: Union[str, Sequence[str], None] = '08ef8f772404'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('IrisMailboxConnection', sa.Column('sync_started_at', sa.DateTime(), nullable=True))
    op.add_column('IrisMailboxConnection', sa.Column('sync_job_id', sa.String(length=64), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('IrisMailboxConnection', 'sync_job_id')
    op.drop_column('IrisMailboxConnection', 'sync_started_at')
