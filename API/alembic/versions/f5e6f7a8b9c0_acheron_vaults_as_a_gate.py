"""accounts: acheron.vaults pasa a ser una puerta, y la organizacion no la raciona

La semilla original vendia 1/3/10/ilimitadas bovedas por plan. Ese numero no
describia nada: Vault.user_id es UNIQUE, asi que **cada persona tiene una
boveda como maximo** y siempre fue asi. Un Bronze en solitario no iba a tener
tres jamas.

Lo que el plan del duenyo limita no es cuantas bovedas tiene una persona, sino
a cuanta de su gente le toca una — el contador del ambito 'member' suma las
bovedas de todos los miembros, que es como funciona cualquier bolsa comun.

Dos correcciones:

1. Ambito 'holder' -> 1 en todos los planes. La clave solo puede significar
   0 ("tu plan no incluye Acheron") o 1 ("si lo incluye"). Se deja el 1 y la
   puerta queda abierta en los cuatro; el 0 sigue disponible para un plan futuro.

2. Ambito 'member' -> ilimitado. Todos los miembros de una organizacion tienen
   su boveda. Servir una no cuesta nada — el servidor solo guarda cifrado, no
   hay IA ni escaneos detras — asi que racionarla se parecia mas a un incordio
   que a un argumento comercial.

Ojo: esto pisa el valor de esas dos claves aunque alguien lo haya editado desde
el panel. Es intencionado — son numeros que no podian estar bien.

Revision ID: f5e6f7a8b9c0
Revises: f4d5e6f7a8b9
Create Date: 2026-08-07 09:00:00.000000

"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = "f5e6f7a8b9c0"
down_revision: Union[str, Sequence[str], None] = "f4d5e6f7a8b9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


#: Valores anteriores, para poder deshacer. (code, scope, value)
_PREVIOUS: tuple[tuple[str, str, int | None], ...] = (
    ("freemium", "holder", 1),
    ("bronze",   "holder", 3),
    ("silver",   "holder", 10),
    ("gold",     "holder", None),
    ("bronze",   "member", 3),
    ("silver",   "member", 5),
    ("gold",     "member", None),
)


def _set(code: str, scope: str, value: int | None) -> None:
    literal = "NULL" if value is None else str(value)
    op.execute(
        f"""
        UPDATE "PlanLimit"
           SET value = {literal}
         WHERE limit_key = 'acheron.vaults'
           AND scope = '{scope}'
           AND plan_id IN (SELECT id FROM "Plan" WHERE code = '{code}')
        """
    )


def upgrade() -> None:
    # Puerta: incluido (1) en los cuatro planes.
    for code in ("freemium", "bronze", "silver", "gold"):
        _set(code, "holder", 1)

    # Dentro de una organizacion, boveda para todos.
    for code in ("bronze", "silver", "gold"):
        _set(code, "member", None)


def downgrade() -> None:
    for code, scope, value in _PREVIOUS:
        _set(code, scope, value)
