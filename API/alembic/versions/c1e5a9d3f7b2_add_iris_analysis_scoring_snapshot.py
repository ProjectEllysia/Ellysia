"""iris: snapshot y versión de la política de puntuación de cada análisis

Cambiar umbrales, perfil o pesos cambiaba el significado de todos los
análisis futuros sin dejar rastro de con qué reglas del juego se decidió cada
uno. Estas columnas guardan esa política entera y una marca estable.

Revision ID: c1e5a9d3f7b2
Revises: b9d2f6a8c4e1
Create Date: 2026-09-11 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = 'c1e5a9d3f7b2'
down_revision: Union[str, Sequence[str], None] = 'b9d2f6a8c4e1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('IrisAnalysis', sa.Column('scoring_snapshot',
                                            postgresql.JSONB(astext_type=sa.Text()), nullable=True))
    op.add_column('IrisAnalysis', sa.Column('scoring_version', sa.String(length=64), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('IrisAnalysis', 'scoring_version')
    op.drop_column('IrisAnalysis', 'scoring_snapshot')
