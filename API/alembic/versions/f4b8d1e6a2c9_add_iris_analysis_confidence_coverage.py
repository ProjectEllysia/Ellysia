"""iris: confianza, cobertura e incertidumbre del veredicto

El score de Iris es una escala de riesgo, no una probabilidad, y un análisis
de solo cabeceras no lo señalaba en ningún sitio. Estas columnas guardan una
confianza ordinal (high/medium/low), qué partes del mensaje se inspeccionaron
y los motivos que restan confianza.

Revision ID: f4b8d1e6a2c9
Revises: e2a9c4d7f1b3
Create Date: 2026-09-11 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = 'f4b8d1e6a2c9'
down_revision: Union[str, Sequence[str], None] = 'e2a9c4d7f1b3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('IrisAnalysis', sa.Column('confidence', sa.String(length=16), nullable=True))
    op.add_column('IrisAnalysis', sa.Column('coverage',
                                            postgresql.JSONB(astext_type=sa.Text()), nullable=True))
    op.add_column('IrisAnalysis', sa.Column('uncertainty_reasons',
                                            postgresql.JSONB(astext_type=sa.Text()), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('IrisAnalysis', 'uncertainty_reasons')
    op.drop_column('IrisAnalysis', 'coverage')
    op.drop_column('IrisAnalysis', 'confidence')
