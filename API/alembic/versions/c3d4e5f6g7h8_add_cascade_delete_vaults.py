"""add cascade delete to vault relationships

Modifica las foreign keys para agregar CASCADE DELETE:
  - Vault → Storable: al eliminar una Vault, todos sus Storables se eliminan.
  - User → Vault: al eliminar un User, todos sus Vaults (y sus Storables) se eliminan.

Esto permite ejecutar DELETE en la BD sin violar constraints de FK.

Revision ID: c3d4e5f6g7h8
Revises: a1b2c3d4e5f6
Create Date: 2026-07-01 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c3d4e5f6g7h8'
down_revision: Union[str, Sequence[str], None] = 'a1b2c3d4e5f6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Drop existing FK Storable→Vault sin CASCADE
    op.drop_constraint('Storable_vault_id_fkey', 'Storable', type_='foreignkey')

    # Recrear con CASCADE DELETE
    op.create_foreign_key(
        'Storable_vault_id_fkey',
        'Storable',
        'Vault',
        ['vault_id'],
        ['id'],
        ondelete='CASCADE'
    )

    # Drop existing FK Vault→User sin CASCADE
    op.drop_constraint('Vault_user_id_fkey', 'Vault', type_='foreignkey')

    # Recrear con CASCADE DELETE
    op.create_foreign_key(
        'Vault_user_id_fkey',
        'Vault',
        'User',
        ['user_id'],
        ['id'],
        ondelete='CASCADE'
    )

    # Agregar CASCADE DELETE a todas las subclases de Storable
    # Estas son joined-table inheritance, donde cada subclase tiene FK a Storable.id
    subclasses = ['Account', 'CreditCard', 'SecureNote', 'Identity', 'BankAccount', 'WifiNetwork', 'SoftwareLicense']

    for subclass in subclasses:
        op.drop_constraint(f'{subclass}_id_fkey', subclass, type_='foreignkey')
        op.create_foreign_key(
            f'{subclass}_id_fkey',
            subclass,
            'Storable',
            ['id'],
            ['id'],
            ondelete='CASCADE'
        )


def downgrade() -> None:
    """Downgrade schema."""
    # Revertir a FK sin CASCADE
    op.drop_constraint('Storable_vault_id_fkey', 'Storable', type_='foreignkey')

    op.create_foreign_key(
        'Storable_vault_id_fkey',
        'Storable',
        'Vault',
        ['vault_id'],
        ['id']
    )

    op.drop_constraint('Vault_user_id_fkey', 'Vault', type_='foreignkey')

    op.create_foreign_key(
        'Vault_user_id_fkey',
        'Vault',
        'User',
        ['user_id'],
        ['id']
    )

    # Revertir CASCADE en subclases
    subclasses = ['Account', 'CreditCard', 'SecureNote', 'Identity', 'BankAccount', 'WifiNetwork', 'SoftwareLicense']

    for subclass in subclasses:
        op.drop_constraint(f'{subclass}_id_fkey', subclass, type_='foreignkey')
        op.create_foreign_key(
            f'{subclass}_id_fkey',
            subclass,
            'Storable',
            ['id'],
            ['id']
        )
