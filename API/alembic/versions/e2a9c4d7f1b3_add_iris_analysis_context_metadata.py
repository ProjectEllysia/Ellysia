"""iris: contexto ganador de un reenvío (IrisAnalysis + IrisRuleResult)

Un reenvío "reportar phishing" trae dos mensajes —el envoltorio y el original
adjunto— y el motor se queda con el peor veredicto de los dos. Sin guardar
cuál ganó, el informe describía siempre el original aunque el veredicto
viniera del envoltorio. Estas columnas guardan el contexto ganador, por qué
ganó, un resumen del otro, y a qué contexto pertenece cada fila de regla.

Revision ID: e2a9c4d7f1b3
Revises: d8b3f2c05e91
Create Date: 2026-09-11 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = 'e2a9c4d7f1b3'
down_revision: Union[str, Sequence[str], None] = 'd8b3f2c05e91'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('IrisAnalysis', sa.Column('winning_context', sa.String(length=16), nullable=True))
    op.add_column('IrisAnalysis', sa.Column('winning_reason', sa.Text(), nullable=True))
    op.add_column('IrisAnalysis', sa.Column('secondary_context',
                                            postgresql.JSONB(astext_type=sa.Text()), nullable=True))
    op.add_column('IrisRuleResult', sa.Column('context_type', sa.String(length=16), nullable=True))


def downgrade() -> None:
    """Downgrade schema.

    Borra antes las filas de regla del contexto secundario: sin la columna
    ``context_type`` se mezclarían con las del ganador y el informe mostraría
    las reglas de los dos mensajes como si fueran de uno solo.
    """
    op.execute(
        'DELETE FROM "IrisRuleResult" r USING "IrisAnalysis" a '
        'WHERE r.analysis_id = a.id AND a.winning_context IS NOT NULL '
        'AND r.context_type IS NOT NULL AND r.context_type <> a.winning_context'
    )
    op.drop_column('IrisRuleResult', 'context_type')
    op.drop_column('IrisAnalysis', 'secondary_context')
    op.drop_column('IrisAnalysis', 'winning_reason')
    op.drop_column('IrisAnalysis', 'winning_context')
