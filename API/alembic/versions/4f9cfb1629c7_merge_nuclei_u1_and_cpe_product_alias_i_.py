"""merge nuclei (U1) and cpe product alias (I-b) heads

Revision ID: 4f9cfb1629c7
Revises: 2d58f913333b, e2f3a4b5c6d7
Create Date: 2026-07-30 17:21:12.001656

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '4f9cfb1629c7'
down_revision: Union[str, Sequence[str], None] = ('2d58f913333b', 'e2f3a4b5c6d7')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
