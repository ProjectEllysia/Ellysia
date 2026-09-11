"""iris: feedback del analista (IrisAnalystFeedback)

Iris no tenía forma de aprender del uso real: nadie podía decir "este
veredicto estaba mal". Esta tabla guarda cada corrección —etiqueta, nota,
autor y fecha— sin tocar nunca el veredicto emitido, que sigue en
IrisAnalysis.

Revision ID: b9d2f6a8c4e1
Revises: a7c3e9f15b28
Create Date: 2026-09-11 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b9d2f6a8c4e1'
down_revision: Union[str, Sequence[str], None] = 'a7c3e9f15b28'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'IrisAnalystFeedback',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('analysis_id', sa.Integer(), nullable=False),
        sa.Column('author_id', sa.Integer(), nullable=False),
        sa.Column('label', sa.String(length=16), nullable=False),
        sa.Column('note', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['analysis_id'], ['IrisAnalysis.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['author_id'], ['User.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_iris_analyst_feedback_analysis_id', 'IrisAnalystFeedback', ['analysis_id'])


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('ix_iris_analyst_feedback_analysis_id', table_name='IrisAnalystFeedback')
    op.drop_table('IrisAnalystFeedback')
