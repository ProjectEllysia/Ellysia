"""Finding.feed_version a 64 caracteres para la marca del estado de la KB (#270)

Revision ID: d7e8f9a0b1c2
Revises: c7d8e9f0a1b2
Create Date: 2026-08-30 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd7e8f9a0b1c2'
down_revision: Union[str, Sequence[str], None] = 'c7d8e9f0a1b2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema.

    La marca de reproducibilidad de la detección por versión era la constante
    ``"lybra-0"`` y no cambiaba nunca, así que un hallazgo guardado no podía
    decir contra qué estado de la base de conocimiento se había resuelto.
    Ahora describe ese estado —``lybra-kb:nvd=2026-08-29,kev=2026-08-27,
    epss=2026-08-30``—, que ocupa hasta 54 caracteres y no cabía en los 32 de
    la columna.

    Se escribe entera en vez de resumirla en un hash corto porque el objetivo
    es justamente que un hallazgo siga siendo legible por sí solo dentro de un
    año; un hash sólo dice "no es el mismo que aquel otro" y necesitaría una
    tabla de consulta que todavía no existe (#302).

    Ampliar un ``varchar`` no reescribe la tabla en PostgreSQL (es un cambio de
    metadatos) y no toca ni un dato existente: los hallazgos ya guardados
    conservan su ``lybra-0``, que sigue siendo cierto para ellos.
    """
    op.alter_column(
        'Finding', 'feed_version',
        existing_type=sa.String(length=32),
        type_=sa.String(length=64),
        existing_nullable=True,
    )


def downgrade() -> None:
    """Downgrade schema.

    Estrechar la columna sí puede perder datos: cualquier marca escrita después
    de la subida mide más de 32 caracteres. Se truncan explícitamente antes de
    alterar el tipo, en vez de dejar que la base de datos falle a mitad.
    """
    op.execute('UPDATE "Finding" SET feed_version = left(feed_version, 32)')
    op.alter_column(
        'Finding', 'feed_version',
        existing_type=sa.String(length=64),
        type_=sa.String(length=32),
        existing_nullable=True,
    )
