"""iris: IrisMailboxConnection.folder_display_name/folder_type (B16 -- folder validado por proveedor)

``folder`` seguía siendo texto libre sin validar contra el proveedor: un
valor inválido, demasiado largo o incompatible solo se descubría en el
siguiente sync. Estas dos columnas acompañan a ``folder`` (que ya existía y
pasa a documentarse como el id opaco de la carpeta) con el nombre legible y
el tipo ("system"/"user") que ``MailboxConnector.list_folders()`` devuelve,
capturados en el momento en que ``folder`` se valida y se guarda.

Revision ID: b615bd3abb26
Revises: 55b8d888d404
Create Date: 2026-09-08 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b615bd3abb26'
down_revision: Union[str, Sequence[str], None] = '55b8d888d404'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('IrisMailboxConnection', sa.Column('folder_display_name', sa.String(length=255), nullable=True))
    op.add_column('IrisMailboxConnection', sa.Column('folder_type', sa.String(length=20), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('IrisMailboxConnection', 'folder_type')
    op.drop_column('IrisMailboxConnection', 'folder_display_name')
