"""users: verificacion de correo para el alta publica

Tres columnas en User, no una tabla aparte: solo hay un token vivo por usuario
y no interesa el historico.

Las cuentas que ya existian se marcan como VERIFICADAS. Son las que creo un
administrador a mano, y de esas responde quien las creo; dejarlas sin verificar
les cortaria el consumo de la noche a la manyana sin que nadie hubiera hecho
nada. El estado "sin verificar" nace con el alta publica, que es de esta misma
fase.

Revision ID: f3c4d5e6f7a8
Revises: f2b3c4d5e6f7
Create Date: 2026-08-06 12:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision: str = "f3c4d5e6f7a8"
down_revision: Union[str, Sequence[str], None] = "f2b3c4d5e6f7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("User", sa.Column("email_verified_at", sa.DateTime(), nullable=True))
    op.add_column("User", sa.Column("email_verification_hash", sa.String(length=128), nullable=True))
    op.add_column("User", sa.Column("email_verification_expires_at", sa.DateTime(), nullable=True))

    # Todas las cuentas existentes quedan verificadas. CURRENT_TIMESTAMP y no un
    # literal: la fecha exacta da igual, lo que importa es que no sea NULL.
    op.execute('UPDATE "User" SET email_verified_at = CURRENT_TIMESTAMP')


def downgrade() -> None:
    op.drop_column("User", "email_verification_expires_at")
    op.drop_column("User", "email_verification_hash")
    op.drop_column("User", "email_verified_at")
