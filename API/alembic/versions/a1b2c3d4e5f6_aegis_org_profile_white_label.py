"""aegis org profile: white-labeling de las campanyas

Las dos columnas del mixin ``shared.WhiteLabelColumns``. El nivel por defecto
es 'none', que reproduce exactamente el correo de antes: una organizacion que
no toque nada no nota el cambio.

Revision ID: a1b2c3d4e5f6
Revises: e79879ec2b67
Create Date: 2026-08-27

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, Sequence[str], None] = 'e79879ec2b67'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "AegisOrgProfile",
        sa.Column(
            "white_label_level",
            sa.String(length=16),
            nullable=False,
            server_default="none",
        ),
    )
    op.add_column("AegisOrgProfile", sa.Column("brand_logo", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("AegisOrgProfile", "brand_logo")
    op.drop_column("AegisOrgProfile", "white_label_level")
