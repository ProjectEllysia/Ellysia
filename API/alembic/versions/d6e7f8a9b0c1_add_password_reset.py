"""users: recuperacion de contrasenya por magic link

Dos columnas en User y no una tabla aparte: igual que la verificacion de
correo, solo hay un enlace vivo por usuario y no interesa el historico. Del
token se guarda unicamente el SHA-256; el valor en claro viaja solo dentro del
correo.

``purpose`` en MFAChallenge separa los challenges de login de los de
recuperacion: uno de recuperacion no debe canjearse por tokens en
POST /oauth/mfa/verify ni uno de login disparar el envio del enlace. Las filas
que ya existan quedan como "login", que es lo unico que habia.

Revision ID: d6e7f8a9b0c1
Revises: c8d9e0f1a2b3
Create Date: 2026-08-25 12:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision: str = "d6e7f8a9b0c1"
down_revision: Union[str, Sequence[str], None] = "c8d9e0f1a2b3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("User", sa.Column("password_reset_hash", sa.String(length=128), nullable=True))
    op.add_column("User", sa.Column("password_reset_expires_at", sa.DateTime(), nullable=True))

    op.add_column(
        "MFAChallenge",
        sa.Column("purpose", sa.String(length=32), nullable=False, server_default="login"),
    )


def downgrade() -> None:
    op.drop_column("MFAChallenge", "purpose")
    op.drop_column("User", "password_reset_expires_at")
    op.drop_column("User", "password_reset_hash")
