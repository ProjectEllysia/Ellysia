"""iris: análisis por lotes (IrisBatch, IrisBatchItem) y huella del contenido

Un lote de varios .eml o un ZIP deja constancia de qué pasó con cada mensaje
—creado, repetido, rechazado o fallido— y del análisis que produjo.
IrisAnalysis.content_sha256 es la huella del mensaje analizado: reconoce el
mismo correo enviado otra vez y evita analizarlo y cobrarlo dos veces.

Revision ID: a7d2b5e9f4c0
Revises: f6c1a4d8e3b9
Create Date: 2026-09-11 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a7d2b5e9f4c0'
down_revision: Union[str, Sequence[str], None] = 'f6c1a4d8e3b9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('IrisAnalysis', sa.Column('content_sha256', sa.String(length=64), nullable=True))
    op.create_index('ix_iris_analysis_user_fingerprint', 'IrisAnalysis', ['user_id', 'content_sha256'])
    op.create_table(
        'IrisBatch',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('total', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['User.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_iris_batch_user_id', 'IrisBatch', ['user_id'])
    op.create_table(
        'IrisBatchItem',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('batch_id', sa.Integer(), nullable=False),
        sa.Column('position', sa.Integer(), nullable=False),
        sa.Column('filename', sa.String(length=255), nullable=False),
        sa.Column('status', sa.String(length=16), nullable=False),
        sa.Column('analysis_id', sa.Integer(), nullable=True),
        sa.Column('error', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['batch_id'], ['IrisBatch.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['analysis_id'], ['IrisAnalysis.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_iris_batch_item_batch_id', 'IrisBatchItem', ['batch_id'])


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('ix_iris_batch_item_batch_id', table_name='IrisBatchItem')
    op.drop_table('IrisBatchItem')
    op.drop_index('ix_iris_batch_user_id', table_name='IrisBatch')
    op.drop_table('IrisBatch')
    op.drop_index('ix_iris_analysis_user_fingerprint', table_name='IrisAnalysis')
    op.drop_column('IrisAnalysis', 'content_sha256')
