"""Calidad del análisis de Iris y catálogo de reglas que lo produjo (#209)

Revision ID: c93b8545601b
Revises: b46e50206411
Create Date: 2026-08-31 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = 'c93b8545601b'
down_revision: Union[str, Sequence[str], None] = 'b46e50206411'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema.

    Una regla que reventaba se convertía en una fila más de ``IrisRuleResult``
    con veredicto ``error`` y ahí se acababa: el análisis podía presentarse
    como limpio sin ninguna advertencia, aunque la regla que faltó fuera la
    que decide si el mensaje está autenticado.

    ``analysis_quality`` distingue un análisis completo de uno degradado,
    ``failed_rules`` guarda cuáles no llegaron a ejecutarse (nombre, familia y
    categoría), y ``detector_version`` marca con qué catálogo de reglas se
    produjo el resultado, para que un informe guardado siga siendo
    interpretable cuando el catálogo cambie.

    Las tres son NULL para los análisis ya existentes. No se rellenan: no hay
    forma de saber a posteriori si una regla falló en un análisis de hace tres
    meses, y un ``complete`` inventado sería peor que un NULL honesto — la
    lectura correcta de NULL es "de este análisis no se registró la calidad",
    no "fue completo".

    El esquema de campos es el que comparten `B05` y `M02` (confianza e
    incertidumbre en el veredicto): `M02` añadirá sus propias columnas de
    confianza, pero reutiliza este ``analysis_quality`` en vez de definir un
    segundo indicador paralelo.
    """
    op.add_column("IrisAnalysis", sa.Column("analysis_quality", sa.String(length=16), nullable=True))
    op.add_column("IrisAnalysis", sa.Column("failed_rules", postgresql.JSONB(astext_type=sa.Text()), nullable=True))
    op.add_column("IrisAnalysis", sa.Column("detector_version", sa.String(length=64), nullable=True))


def downgrade() -> None:
    """Downgrade schema.

    Se pierde el registro de qué análisis fueron degradados y con qué catálogo
    se produjeron; los veredictos ya calculados no cambian.
    """
    op.drop_column("IrisAnalysis", "detector_version")
    op.drop_column("IrisAnalysis", "failed_rules")
    op.drop_column("IrisAnalysis", "analysis_quality")
