"""add vault revision

Añade ``Vault.revision``: el token de concurrencia optimista que se incrementa
en TODA mutación del contenido del vault (upsert completo, rotación de la
maestra y alta/edición/baja de storables). Se expone como ETag en
GET /acheron/vault y los clientes lo devuelven en If-Match; una escritura con
una revisión obsoleta se rechaza con 409 en vez de pisar cambios ajenos.

No sustituye a ``metadata_version``, que conserva su semántica propia (solo se
incrementa al rotar la contraseña maestra, y de ella depende la invalidación
del secreto biométrico del móvil).

Revision ID: d1e2f3a4b5c6
Revises: 4f9cfb1629c7
Create Date: 2026-07-30 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd1e2f3a4b5c6'
down_revision: Union[str, Sequence[str], None] = '4f9cfb1629c7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # server_default '1' rellena los vaults ya existentes; los nuevos también
    # arrancan en 1 y suben con cada mutación.
    op.add_column(
        'Vault',
        sa.Column('revision', sa.Integer(), nullable=False, server_default='1'),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('Vault', 'revision')
