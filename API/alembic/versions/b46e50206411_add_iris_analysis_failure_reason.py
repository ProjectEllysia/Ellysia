"""Motivo terminal de un análisis de Iris fallido (#207)

Revision ID: b46e50206411
Revises: d7e8f9a0b1c2
Create Date: 2026-08-31 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b46e50206411'
down_revision: Union[str, Sequence[str], None] = 'd7e8f9a0b1c2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema.

    Un análisis que acababa en ``failed`` no decía por qué. Las dos causas son
    muy distintas para quien lo mira —el texto enviado no era un correo
    analizable, o el motor se rompió por dentro— y sin distinguirlas el estado
    terminal no es accionable: el usuario no sabe si reintentar o corregir su
    entrada.

    ``failure_code`` guarda esa distinción (``invalid_input`` /
    ``internal_error``) y ``failure_reason`` el mensaje legible que la
    acompaña. Ambas son NULL para cualquier análisis que no haya fallado, así
    que las filas existentes no necesitan relleno.
    """
    op.add_column("IrisAnalysis", sa.Column("failure_code", sa.String(length=32), nullable=True))
    op.add_column("IrisAnalysis", sa.Column("failure_reason", sa.Text(), nullable=True))


def downgrade() -> None:
    """Downgrade schema.

    Se pierden los motivos ya registrados; los análisis fallidos vuelven a
    quedarse en un ``failed`` sin explicación, que es el estado previo.
    """
    op.drop_column("IrisAnalysis", "failure_reason")
    op.drop_column("IrisAnalysis", "failure_code")
