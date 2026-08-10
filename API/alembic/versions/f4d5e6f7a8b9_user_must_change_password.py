"""users: must_change_password para las altas por invitacion

Una cuenta creada al invitar a alguien a una organizacion nace con una
contrasenya aleatoria que su duenyo no eligio, y tiene que cambiarla en el
primer acceso.

Va en una columna propia y no reutilizando password_changed_at porque el NULL
de esa ya significa otra cosa — "nunca se cambio" — que tambien es cierto de
las cuentas antiguas, y confundir las dos obligaria a molestar a todo el mundo.

Revision ID: f4d5e6f7a8b9
Revises: f3c4d5e6f7a8
Create Date: 2026-08-06 13:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision: str = "f4d5e6f7a8b9"
down_revision: Union[str, Sequence[str], None] = "f3c4d5e6f7a8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # server_default porque la columna es NOT NULL y ya hay filas que rellenar;
    # se retira despues para que el default vivo sea el del modelo.
    op.add_column(
        "User",
        sa.Column("must_change_password", sa.Boolean(), nullable=False,
                  server_default=sa.false()),
    )
    op.alter_column("User", "must_change_password", server_default=None)


def downgrade() -> None:
    op.drop_column("User", "must_change_password")
