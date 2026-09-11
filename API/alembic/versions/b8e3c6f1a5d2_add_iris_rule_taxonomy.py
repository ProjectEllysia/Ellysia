"""iris: taxonomía estable de cada hallazgo (rule_id, severity, mitre_techniques)

El identificador de una regla era su nombre humano, que es lo que se muestra y
lo que se puede traducir o corregir: un hallazgo no se podía reutilizar en el
PDF, la API, un panel o una exportación sin atarse a esa cadena. Cada fila de
IrisRuleResult guarda ahora el id estable de su regla, su severidad (separada
del score) y las técnicas MITRE ATT&CK que le corresponden, tal como estaban
en el catálogo cuando se analizó. Las filas anteriores quedan a NULL.

Revision ID: b8e3c6f1a5d2
Revises: a7d2b5e9f4c0
Create Date: 2026-09-11 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = 'b8e3c6f1a5d2'
down_revision: Union[str, Sequence[str], None] = 'a7d2b5e9f4c0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('IrisRuleResult', sa.Column('rule_id', sa.String(length=64), nullable=True))
    op.add_column('IrisRuleResult', sa.Column('severity', sa.String(length=16), nullable=True))
    op.add_column('IrisRuleResult', sa.Column('mitre_techniques',
                                              postgresql.JSONB(astext_type=sa.Text()), nullable=True))
    op.create_index('ix_iris_rule_result_rule_id', 'IrisRuleResult', ['rule_id'])


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('ix_iris_rule_result_rule_id', table_name='IrisRuleResult')
    op.drop_column('IrisRuleResult', 'mitre_techniques')
    op.drop_column('IrisRuleResult', 'severity')
    op.drop_column('IrisRuleResult', 'rule_id')
