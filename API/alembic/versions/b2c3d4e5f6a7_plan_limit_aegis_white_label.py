"""catalogo: tope de white-labeling por plan

La clave 'aegis.white_label' no existia cuando se sembro el catalogo, y una
fila ausente vale 0 — o sea, sin white-labeling para nadie. Esta migracion la
inserta en las bases que ya estaban desplegadas, con los mismos valores que el
literal congelado de la migracion de siembra.

Su 'value' no es una cantidad sino el escalon concedido (LimitPeriod.TIER):
0 ninguno, 1 color de enfasis propio, 2 ademas el logo, 3 sin rastro de la
marca del producto.

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-08-27

"""
from typing import Sequence, Union

from alembic import op


revision: str = 'b2c3d4e5f6a7'
down_revision: Union[str, Sequence[str], None] = 'a1b2c3d4e5f6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_LIMIT_KEY = "aegis.white_label"

#: Mismos valores que _HOLDER_LIMITS en la migracion de siembra.
_VALUES: dict[str, int] = {"freemium": 0, "bronze": 1, "silver": 2, "gold": 3}


def upgrade() -> None:
    # Idempotente: en una base recien creada la siembra ya puso la fila, y esta
    # migracion corre despues sin duplicarla.
    for code, value in _VALUES.items():
        op.execute(
            f"""
            INSERT INTO "PlanLimit" (plan_id, limit_key, scope, value, period)
            SELECT p.id, '{_LIMIT_KEY}', 'holder', {value}, 'tier'
              FROM "Plan" p
             WHERE p.code = '{code}'
               AND NOT EXISTS (
                   SELECT 1 FROM "PlanLimit" l
                    WHERE l.plan_id = p.id
                      AND l.limit_key = '{_LIMIT_KEY}'
                      AND l.scope = 'holder'
               )
            """
        )


def downgrade() -> None:
    op.execute(f"""DELETE FROM "PlanLimit" WHERE limit_key = '{_LIMIT_KEY}'""")
