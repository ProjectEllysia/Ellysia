"""finding cpe resolved observability

Revision ID: 2d58f913333b
Revises: e6f7a8b9c0d1
Create Date: 2026-07-29 19:43:46.072190

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '2d58f913333b'
down_revision: Union[str, Sequence[str], None] = 'e6f7a8b9c0d1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('Finding', sa.Column('cpe_resolved', sa.Boolean(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('Finding', 'cpe_resolved')
