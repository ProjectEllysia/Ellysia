"""merge white-labeling migration heads

Revision ID: baf6f0e7fd8c
Revises: a1b2c3d4e5f7, b2c3d4e5f6a7
Create Date: 2026-08-27 21:12:52.808729

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'baf6f0e7fd8c'
down_revision: Union[str, Sequence[str], None] = ('a1b2c3d4e5f7', 'b2c3d4e5f6a7')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
