"""iris: vistas guardadas, etiquetas e índice de IOCs para el triaje

Un analista no podía volver a una cola de trabajo sin reconstruir cada
filtro, etiquetar un análisis ni buscar por un dominio o una IP: el raw se
guarda cifrado y no se puede consultar con SQL. IrisSavedView guarda filtros
con nombre, IrisAnalysisTag etiqueta análisis e IrisIndicator indexa los IOCs
de cada análisis terminado (sobreviven a la purga del raw por retención).

Revision ID: e5b9f3a7c2d8
Revises: d4a8e2f6b1c7
Create Date: 2026-09-11 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = 'e5b9f3a7c2d8'
down_revision: Union[str, Sequence[str], None] = 'd4a8e2f6b1c7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'IrisSavedView',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=60), nullable=False),
        sa.Column('filters', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['User.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('user_id', 'name', name='uq_iris_saved_view_user_name'),
    )
    op.create_table(
        'IrisAnalysisTag',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('analysis_id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=40), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['analysis_id'], ['IrisAnalysis.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('analysis_id', 'name', name='uq_iris_analysis_tag_analysis_name'),
    )
    op.create_index('ix_iris_analysis_tag_name', 'IrisAnalysisTag', ['name'])
    op.create_table(
        'IrisIndicator',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('analysis_id', sa.Integer(), nullable=False),
        sa.Column('kind', sa.String(length=16), nullable=False),
        sa.Column('value', sa.String(length=2048), nullable=False),
        sa.ForeignKeyConstraint(['analysis_id'], ['IrisAnalysis.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_iris_indicator_analysis_id', 'IrisIndicator', ['analysis_id'])
    op.create_index('ix_iris_indicator_value', 'IrisIndicator', ['value'])


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('ix_iris_indicator_value', table_name='IrisIndicator')
    op.drop_index('ix_iris_indicator_analysis_id', table_name='IrisIndicator')
    op.drop_table('IrisIndicator')
    op.drop_index('ix_iris_analysis_tag_name', table_name='IrisAnalysisTag')
    op.drop_table('IrisAnalysisTag')
    op.drop_table('IrisSavedView')
