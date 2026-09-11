"""users: renombra MFATotpCredential.secret_encrypted a totp_secret (EncryptedText)

El secreto TOTP se cifraba a mano, en los cuatro puntos del manager de MFA
que lo leen o lo escriben (``encrypt_totp_secret``/``decrypt_totp_secret``).
Ahora lo cifra el propio tipo de columna, ``EncryptedText``, que aplica el
mismo Fernet con el mismo ``purpose="mfa"`` -- de modo que el contenido de
la columna **no cambia**: lo que hay guardado hoy lo descifra el tipo nuevo
tal cual y esta migración no reescribe ni una fila.

Cambian dos cosas, y las dos son de esquema:

- **El nombre.** Con ``EncryptedText`` el atributo de Python contiene el
  secreto en claro, así que un nombre acabado en ``_encrypted`` describe la
  fila pero miente sobre lo que lee el código. Pasa a ``totp_secret``.
- **El tipo.** ``EncryptedText`` se apoya en ``Text``; la columna era
  ``String(512)``. En PostgreSQL es un ensanchamiento (``varchar`` ->
  ``text``) que no reescribe la tabla.

Revision ID: c4a1e7b93d20
Revises: 3a7f74c514d5
Create Date: 2026-09-09 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c4a1e7b93d20'
down_revision: Union[str, Sequence[str], None] = '3a7f74c514d5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table('MFATotpCredential') as batch_op:
        batch_op.alter_column(
            'secret_encrypted',
            new_column_name='totp_secret',
            existing_type=sa.String(length=512),
            type_=sa.Text(),
            existing_nullable=False,
        )


def downgrade() -> None:
    """Downgrade schema.

    Estrecha la columna de vuelta a ``String(512)``. El ciphertext Fernet de
    un secreto TOTP en Base32 ronda los 150 caracteres, así que cabe de
    sobra; se deja escrito porque un ``text`` -> ``varchar(n)`` sí puede
    fallar en PostgreSQL si alguna fila no entrara.
    """
    with op.batch_alter_table('MFATotpCredential') as batch_op:
        batch_op.alter_column(
            'totp_secret',
            new_column_name='secret_encrypted',
            existing_type=sa.Text(),
            type_=sa.String(length=512),
            existing_nullable=False,
        )
