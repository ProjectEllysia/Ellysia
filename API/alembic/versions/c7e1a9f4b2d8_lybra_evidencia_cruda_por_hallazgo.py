"""lybra: evidencia cruda por hallazgo (Fase E)

Revision ID: c7e1a9f4b2d8
Revises: fd07fce5f920
Create Date: 2026-09-03 10:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB


# revision identifiers, used by Alembic.
revision: str = 'c7e1a9f4b2d8'
down_revision: Union[str, Sequence[str], None] = 'fd07fce5f920'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Crea la tabla de evidencia de hallazgos.

    Un hallazgo dice qué encontró y con qué regla, pero no guardaba lo que el
    objetivo respondió. Esta tabla lo guarda: la respuesta cruda —redactada,
    con su hash y su fecha— que provocó el hallazgo, para poder defenderla ante
    un cliente y para diagnosticar un falso positivo sin repetir el escaneo a
    mano.

    ``ondelete=CASCADE`` a propósito: la evidencia no tiene sentido sin su
    hallazgo, así que borrar un escaneo (que ya cae en cascada sobre sus
    hallazgos) se lleva también su evidencia, sin dejar filas huérfanas.

    El índice sobre ``captured_at`` es para la retención: la purga de la
    evidencia caducada barre por fecha, y sin índice ese barrido escanearía la
    tabla entera cada vez.
    """
    op.create_table(
        "FindingEvidence",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("finding_id", sa.Integer(),
                  sa.ForeignKey("Finding.id", ondelete="CASCADE"), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("payload", JSONB(), nullable=False),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column("captured_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_FindingEvidence_finding_id", "FindingEvidence", ["finding_id"])
    op.create_index("ix_FindingEvidence_captured_at", "FindingEvidence", ["captured_at"])


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index("ix_FindingEvidence_captured_at", table_name="FindingEvidence")
    op.drop_index("ix_FindingEvidence_finding_id", table_name="FindingEvidence")
    op.drop_table("FindingEvidence")
