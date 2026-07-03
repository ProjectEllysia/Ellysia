"""add IrisAnalysis.gate_reasons

Persiste las razones legibles de los gates de alta confianza que empeoraron
(o confirmaron) el veredicto de un análisis Iris. Hasta ahora se calculaban
en IrisManager._apply_verdict_gates y se descartaban tras loguearlas; con
esta columna el informe puede explicar POR QUÉ un correo es
Suspicious/Phishing más allá del score numérico.

Revision ID: d4e5f6a7b8c9
Revises: c3d4e5f6g7h8
Create Date: 2026-07-02 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB


# revision identifiers, used by Alembic.
revision: str = 'd4e5f6a7b8c9'
down_revision: Union[str, Sequence[str], None] = 'c3d4e5f6g7h8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # NULL = análisis anterior a esta columna (o sin gates disparados).
    op.add_column(
        'IrisAnalysis',
        sa.Column('gate_reasons', JSONB(), nullable=True),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('IrisAnalysis', 'gate_reasons')
