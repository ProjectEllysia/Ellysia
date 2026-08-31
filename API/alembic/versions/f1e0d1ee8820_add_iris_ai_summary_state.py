"""Estado del resumen IA de Iris: idempotencia y trazabilidad (#220)

Revision ID: f1e0d1ee8820
Revises: dd19efde1d08
Create Date: 2026-08-31 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f1e0d1ee8820'
down_revision: Union[str, Sequence[str], None] = 'dd19efde1d08'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema.

    El resumen ejecutivo de IA solo tenía dónde guardar su resultado
    (``ai_summary``), no su estado. Sin estado no hay forma de saber si ya hay
    una generación en curso, así que dos peticiones seguidas consumían cuota
    dos veces y encolaban dos trabajos para el mismo análisis.

    ``ai_summary_status`` es la pieza que hace idempotente la operación: el
    manager reclama la fila con una transición condicional, y quien pierde la
    carrera no cobra ni encola. ``ai_summary_job_id`` permite relacionar la
    fila con su trabajo en la cola.

    ``ai_summary_model`` y ``ai_summary_prompt_version`` son trazabilidad: un
    resumen generado hace tres meses lo escribió otro modelo con otro prompt,
    y sin registrarlo no hay manera de saber cuál — el mismo problema que
    ``detector_version`` resuelve para las reglas.

    Todas son NULL para las filas existentes. Los resúmenes ya generados se
    reconocen igualmente por tener ``ai_summary`` no nulo, así que no hace
    falta rellenar nada: el manager trata "hay resumen, sin estado" como
    terminado.
    """
    op.add_column("IrisAnalysis", sa.Column("ai_summary_status", sa.String(length=16), nullable=True))
    op.add_column("IrisAnalysis", sa.Column("ai_summary_job_id", sa.String(length=64), nullable=True))
    op.add_column("IrisAnalysis", sa.Column("ai_summary_model", sa.String(length=64), nullable=True))
    op.add_column("IrisAnalysis", sa.Column("ai_summary_prompt_version", sa.String(length=32), nullable=True))


def downgrade() -> None:
    """Downgrade schema.

    Los resúmenes generados se conservan (``ai_summary`` no se toca); lo que
    se pierde es su estado y su procedencia, y con ello la idempotencia:
    volver aquí reabre la posibilidad de encolar dos generaciones del mismo
    análisis.
    """
    op.drop_column("IrisAnalysis", "ai_summary_prompt_version")
    op.drop_column("IrisAnalysis", "ai_summary_model")
    op.drop_column("IrisAnalysis", "ai_summary_job_id")
    op.drop_column("IrisAnalysis", "ai_summary_status")
