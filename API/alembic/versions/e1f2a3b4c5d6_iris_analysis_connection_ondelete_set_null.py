"""iris: ondelete=SET NULL en IrisAnalysis.connection_id

Sin esto, Postgres aplica RESTRICT por defecto y borrar una
IrisMailboxConnection con analisis asociados falla con un error de
integridad ("Desconectar" roto para el caso de uso real). El historico de
IrisAnalysis se conserva; solo se desvincula la conexion borrada.

Revision ID: e1f2a3b4c5d6
Revises: d3e4f5a6b7c8
Create Date: 2026-07-23 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = 'e1f2a3b4c5d6'
down_revision: Union[str, Sequence[str], None] = 'd3e4f5a6b7c8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.drop_constraint('fk_iris_analysis_connection_id', 'IrisAnalysis', type_='foreignkey')
    op.create_foreign_key(
        'fk_iris_analysis_connection_id', 'IrisAnalysis', 'IrisMailboxConnection',
        ['connection_id'], ['id'], ondelete='SET NULL',
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_constraint('fk_iris_analysis_connection_id', 'IrisAnalysis', type_='foreignkey')
    op.create_foreign_key(
        'fk_iris_analysis_connection_id', 'IrisAnalysis', 'IrisMailboxConnection',
        ['connection_id'], ['id'],
    )
