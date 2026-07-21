"""add password-change detection columns

Añade soporte para detectar que la contraseña cambió durante una sesión activa:
  - User.password_changed_at : marca del último cambio de la contraseña de acceso.
  - Vault.metadata_version   : contador que se incrementa al rotar la contraseña
                               maestra (PATCH /acheron/vault).

Revision ID: a1b2c3d4e5f6
Revises: 819ead62a00a
Create Date: 2026-06-30 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, Sequence[str], None] = '819ead62a00a'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # NULL = la contraseña de acceso nunca se cambió desde que existe la columna.
    op.add_column(
        'User',
        sa.Column('password_changed_at', sa.DateTime(), nullable=True),
    )
    # server_default '1' rellena las filas existentes; los vaults nuevos también
    # arrancan en 1 (la rotación de la maestra lo incrementa).
    op.add_column(
        'Vault',
        sa.Column('metadata_version', sa.Integer(), nullable=False, server_default='1'),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('Vault', 'metadata_version')
    op.drop_column('User', 'password_changed_at')
