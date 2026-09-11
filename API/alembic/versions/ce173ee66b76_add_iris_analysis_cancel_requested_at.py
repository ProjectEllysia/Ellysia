"""iris: IrisAnalysis.cancel_requested_at (B07 -- transiciones de estado atómicas)

``cancel_analysis()`` señalizaba TaskQueue y escribía ``status="cancelled"``
sin condicionar al estado actual de la fila. Si el worker terminaba el
análisis justo en ese instante, cualquiera de las dos escrituras podía ganar
la carrera, y el resultado final dependía de quién escribiera último en vez
de reflejar la decisión real del usuario o del pipeline.

Esta columna no forma parte de la corrección de la carrera en sí (eso lo
hace ``IrisAnalysisRepository.transition_if_state()``, una transición SQL
condicionada) -- registra que el usuario pidió cancelar, incluso cuando el
worker gana la carrera y el análisis acaba ``finished`` en vez de
``cancelled``. Sin esta columna esa intención se perdía sin dejar rastro.

Revision ID: ce173ee66b76
Revises: af1b51ec6c76
Create Date: 2026-09-09 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'ce173ee66b76'
down_revision: Union[str, Sequence[str], None] = 'af1b51ec6c76'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('IrisAnalysis', sa.Column('cancel_requested_at', sa.DateTime(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('IrisAnalysis', 'cancel_requested_at')
