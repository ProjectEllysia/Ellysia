"""iris: excepciones de confianza por usuario (IrisTrustedSender)

Un falso positivo recurrente solo se podía quitar tocando la configuración
global. Esta tabla guarda excepciones por usuario —remitente o dominio—, con
motivo, caducidad y revocación sin borrado, y ``IrisAnalysis.trust_applied``
deja en cada análisis el rastro de la excepción que se le aplicó.

Revision ID: d4a8e2f6b1c7
Revises: c1e5a9d3f7b2
Create Date: 2026-09-11 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = 'd4a8e2f6b1c7'
down_revision: Union[str, Sequence[str], None] = 'c1e5a9d3f7b2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'IrisTrustedSender',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('kind', sa.String(length=16), nullable=False),
        sa.Column('value', sa.String(length=320), nullable=False),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.Column('revoked_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['User.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_iris_trusted_sender_user_id', 'IrisTrustedSender', ['user_id'])
    op.add_column('IrisAnalysis', sa.Column('trust_applied',
                                            postgresql.JSONB(astext_type=sa.Text()), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('IrisAnalysis', 'trust_applied')
    op.drop_index('ix_iris_trusted_sender_user_id', table_name='IrisTrustedSender')
    op.drop_table('IrisTrustedSender')
