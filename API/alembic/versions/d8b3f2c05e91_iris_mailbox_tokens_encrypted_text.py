"""iris: renombra los tokens de IrisMailboxConnection a refresh_token/access_token

Segunda mitad de la unificación del cifrado en reposo (la primera fue el
secreto TOTP de MFA, ``c4a1e7b93d20``). Los tokens de OAuth del conector de
buzón se cifraban a mano en seis puntos de ``managers/mailbox.py``; ahora lo
hace el tipo de columna ``EncryptedText`` con el mismo Fernet y el mismo
``purpose="iris_mailbox"``, así que **el contenido de las columnas no
cambia** y esta migración no reescribe ni una fila.

Tampoco cambia el tipo: ambas eran ya ``Text``, que es sobre lo que se apoya
``EncryptedText``. Lo único que cambia es el nombre, y por una razón
concreta: con el tipo nuevo el atributo de Python contiene el token **en
claro**, de modo que un sufijo ``_enc`` describe correctamente la fila pero
miente sobre lo que lee el código que la usa.

Revision ID: d8b3f2c05e91
Revises: c4a1e7b93d20
Create Date: 2026-09-09 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd8b3f2c05e91'
down_revision: Union[str, Sequence[str], None] = 'c4a1e7b93d20'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table('IrisMailboxConnection') as batch_op:
        batch_op.alter_column('refresh_token_enc', new_column_name='refresh_token',
                              existing_type=sa.Text(), existing_nullable=False)
        batch_op.alter_column('access_token_enc', new_column_name='access_token',
                              existing_type=sa.Text(), existing_nullable=True)


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('IrisMailboxConnection') as batch_op:
        batch_op.alter_column('refresh_token', new_column_name='refresh_token_enc',
                              existing_type=sa.Text(), existing_nullable=False)
        batch_op.alter_column('access_token', new_column_name='access_token_enc',
                              existing_type=sa.Text(), existing_nullable=True)
