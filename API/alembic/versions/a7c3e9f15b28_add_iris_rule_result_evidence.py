"""iris: evidencia anclada de cada hallazgo (IrisRuleResult)

Cada regla que penaliza dice ahora dónde está lo que encontró —cabecera y
aparición, rango del cuerpo, parte MIME, adjunto o URL— con un extracto ya
desactivado, o por qué no se puede anclar a un fragmento concreto.

Revision ID: a7c3e9f15b28
Revises: f4b8d1e6a2c9
Create Date: 2026-09-11 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = 'a7c3e9f15b28'
down_revision: Union[str, Sequence[str], None] = 'f4b8d1e6a2c9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('IrisRuleResult', sa.Column('evidence',
                                              postgresql.JSONB(astext_type=sa.Text()), nullable=True))
    op.add_column('IrisRuleResult', sa.Column('evidence_unavailable_reason', sa.Text(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('IrisRuleResult', 'evidence_unavailable_reason')
    op.drop_column('IrisRuleResult', 'evidence')
