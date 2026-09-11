"""iris: casos de analista (IrisCase, IrisCaseAnalysis, IrisCaseEvent)

Un informe aislado no era trabajo operativo medible. Un caso agrupa uno o
varios análisis —que siguen inmutables— y registra la decisión humana:
estado, prioridad, asignación, etiquetas, notas y una timeline de todo lo que
le pasó, con la razón de cierre.

Revision ID: f6c1a4d8e3b9
Revises: e5b9f3a7c2d8
Create Date: 2026-09-11 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = 'f6c1a4d8e3b9'
down_revision: Union[str, Sequence[str], None] = 'e5b9f3a7c2d8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'IrisCase',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('title', sa.String(length=120), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('priority', sa.String(length=16), nullable=False),
        sa.Column('assignee_id', sa.Integer(), nullable=True),
        sa.Column('tags', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('resolution_reason', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.Column('closed_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['User.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['assignee_id'], ['User.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_iris_case_user_id', 'IrisCase', ['user_id'])
    op.create_index('ix_iris_case_status', 'IrisCase', ['status'])
    op.create_table(
        'IrisCaseAnalysis',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('case_id', sa.Integer(), nullable=False),
        sa.Column('analysis_id', sa.Integer(), nullable=False),
        sa.Column('added_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['case_id'], ['IrisCase.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['analysis_id'], ['IrisAnalysis.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('case_id', 'analysis_id', name='uq_iris_case_analysis_case_analysis'),
    )
    op.create_index('ix_iris_case_analysis_analysis_id', 'IrisCaseAnalysis', ['analysis_id'])
    op.create_table(
        'IrisCaseEvent',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('case_id', sa.Integer(), nullable=False),
        sa.Column('actor_id', sa.Integer(), nullable=True),
        sa.Column('kind', sa.String(length=24), nullable=False),
        sa.Column('detail', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('note', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['case_id'], ['IrisCase.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['actor_id'], ['User.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_iris_case_event_case_id', 'IrisCaseEvent', ['case_id'])


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('ix_iris_case_event_case_id', table_name='IrisCaseEvent')
    op.drop_table('IrisCaseEvent')
    op.drop_index('ix_iris_case_analysis_analysis_id', table_name='IrisCaseAnalysis')
    op.drop_table('IrisCaseAnalysis')
    op.drop_index('ix_iris_case_status', table_name='IrisCase')
    op.drop_index('ix_iris_case_user_id', table_name='IrisCase')
    op.drop_table('IrisCase')
