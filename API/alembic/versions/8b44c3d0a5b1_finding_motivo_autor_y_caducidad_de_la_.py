"""finding: motivo autor y caducidad de la decision de estado

Revision ID: 8b44c3d0a5b1
Revises: d421740891b4
Create Date: 2026-09-03 19:34:39.111246

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '8b44c3d0a5b1'
down_revision: Union[str, Sequence[str], None] = 'd421740891b4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema.

    Cuatro columnas que convierten un cambio de estado en una decisión
    trazable: por qué, quién, cuándo y hasta cuándo.

    Todas nulas, y así se quedan para los hallazgos que nadie ha tocado —que
    son la inmensa mayoría—, de modo que no hay backfill ni valor por defecto
    que inventar. Un `accepted` anterior a esta migración se queda sin motivo
    ni autor porque de verdad no los tiene: fingirlos sería peor que el hueco.

    ``state_expires_at`` sólo se rellena para `accepted`. Un falso positivo no
    caduca —el motor no se vuelve a equivocar con el paso del tiempo, sino
    cuando cambia— y eso se detecta comparando `check_id` y `feed_version`, no
    con un reloj.
    """
    op.add_column("Finding", sa.Column("state_reason", sa.Text(), nullable=True))
    op.add_column("Finding", sa.Column("state_set_by", sa.Integer(), nullable=True))
    op.add_column("Finding", sa.Column("state_set_at", sa.DateTime(), nullable=True))
    op.add_column("Finding", sa.Column("state_expires_at", sa.DateTime(), nullable=True))
    op.create_foreign_key(
        "fk_finding_state_set_by_user", "Finding", "User", ["state_set_by"], ["id"],
    )


def downgrade() -> None:
    """Downgrade schema.

    Se pierden los motivos y los autores de las decisiones ya tomadas. El
    estado en sí (`Finding.state`) no se toca, así que un hallazgo marcado como
    falso positivo lo sigue estando; lo que desaparece es el porqué.
    """
    op.drop_constraint("fk_finding_state_set_by_user", "Finding", type_="foreignkey")
    op.drop_column("Finding", "state_expires_at")
    op.drop_column("Finding", "state_set_at")
    op.drop_column("Finding", "state_set_by")
    op.drop_column("Finding", "state_reason")
