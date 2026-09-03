"""lybra: escaneo parcial cuando el descubrimiento no termina

Revision ID: fd07fce5f920
Revises: e8f9a0b1c2d3
Create Date: 2026-09-02 21:33:52.595178

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'fd07fce5f920'
down_revision: Union[str, Sequence[str], None] = 'e8f9a0b1c2d3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema.

    Un barrido de puertos que se queda sin presupuesto de reloj encuentra
    puertos ciertos y deja otros sin mirar. Hasta ahora eso hacía fallar el
    escaneo entero: se descartaba información verificada para no arriesgarse a
    que el ciclo de vida diera por corregido lo que no se llegó a comprobar.

    Con esta columna el escaneo puede terminar diciendo la verdad —«esto es lo
    que vi, y no lo vi todo»— en vez de no decir nada.

    ``server_default`` es obligatorio y no cosmético: la columna es NOT NULL y
    la tabla ya tiene filas, así que sin un valor por defecto en el servidor
    PostgreSQL rechaza el ALTER. Todos los escaneos anteriores quedan como
    completos, que es lo que eran bajo el comportamiento antiguo: o terminaban
    enteros, o no llegaban a escribirse.
    """
    op.add_column(
        "LybraScan",
        sa.Column("is_partial", sa.Boolean(), nullable=False,
                  server_default=sa.false()),
    )


def downgrade() -> None:
    """Downgrade schema.

    Reversible sin pérdida de hallazgos: al bajar se vuelve al comportamiento
    en el que un descubrimiento truncado hacía fallar el escaneo, así que la
    distinción que esta columna guarda deja de poder producirse. Los escaneos
    parciales ya almacenados quedan indistinguibles de los completos — es la
    única pérdida, y afecta a una marca informativa, no a los datos.
    """
    op.drop_column("LybraScan", "is_partial")
