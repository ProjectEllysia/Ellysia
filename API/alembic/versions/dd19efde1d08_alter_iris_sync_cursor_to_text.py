"""sync_cursor de Iris a Text: el deltaLink de Graph no cabe en 255 (#211)

Revision ID: dd19efde1d08
Revises: c93b8545601b
Create Date: 2026-08-31 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'dd19efde1d08'
down_revision: Union[str, Sequence[str], None] = 'c93b8545601b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema.

    ``sync_cursor`` guarda el marcador de hasta dónde ha llegado la ingesta de
    un buzón conectado. Para Gmail es un ``historyId`` corto, pero para
    Microsoft Graph es un ``@odata.deltaLink``: una URL completa con un token
    de estado opaco dentro, que rebasa con holgura los 255 caracteres.

    El propio docstring del modelo ya decía que el valor es opaco —es decir,
    que no debe interpretarse ni recortarse—, pero la columna lo acotaba. Un
    truncado silencioso rompe la sincronización incremental: el cursor
    guardado deja de ser válido, Graph responde 410 y la conexión vuelve a
    hacer bootstrap, perdiendo el punto en el que iba.

    ``Text`` no tiene límite práctico en PostgreSQL y no cuesta nada frente a
    ``varchar``: internamente son el mismo tipo, solo cambia la comprobación
    de longitud. La conversión ensancha la columna, así que ningún valor
    existente se pierde.
    """
    op.alter_column(
        "IrisMailboxConnection", "sync_cursor",
        existing_type=sa.String(length=255),
        type_=sa.Text(),
        existing_nullable=True,
    )


def downgrade() -> None:
    """Downgrade schema.

    Estrecha la columna de vuelta a 255. **Cualquier cursor más largo que eso
    hace fallar la bajada**, que es el comportamiento correcto: truncarlo en
    silencio dejaría conexiones con un marcador inválido que solo se
    manifestaría en la siguiente sincronización. Si hiciera falta bajar de
    verdad, lo seguro es poner a NULL los cursores largos primero — la
    conexión rehará el bootstrap, que es lento pero no pierde correo.
    """
    op.alter_column(
        "IrisMailboxConnection", "sync_cursor",
        existing_type=sa.Text(),
        type_=sa.String(length=255),
        existing_nullable=True,
    )
