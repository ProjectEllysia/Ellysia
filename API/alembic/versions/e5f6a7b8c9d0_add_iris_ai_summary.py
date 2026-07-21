"""add IrisAnalysis.ai_summary

Persiste la narrativa ejecutiva generada por IA (IA1, IrisAIWriter):
executive_summary/attacker_intent/recommendations/confidence. Se genera
bajo demanda vía POST /iris/results/<id>/ai-summary (tarea asíncrona en
TaskQueue) y queda NULL hasta que se solicita — o si la generación falla,
ya que IrisManager.execute_ai_summary_generation degrada limpiamente sin
tumbar el análisis cuando no hay backend de IA disponible.

Revision ID: e5f6a7b8c9d0
Revises: d4e5f6a7b8c9
Create Date: 2026-07-03 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB


# revision identifiers, used by Alembic.
revision: str = 'e5f6a7b8c9d0'
down_revision: Union[str, Sequence[str], None] = 'd4e5f6a7b8c9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # NULL = narrativa IA nunca solicitada (o solicitada y fallida).
    op.add_column(
        'IrisAnalysis',
        sa.Column('ai_summary', JSONB(), nullable=True),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('IrisAnalysis', 'ai_summary')
