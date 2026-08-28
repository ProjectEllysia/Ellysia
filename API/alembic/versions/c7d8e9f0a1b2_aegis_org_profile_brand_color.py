"""aegis org profile: la columna brand_color que falto en a1b2c3d4e5f7

El mixin ``shared.WhiteLabelColumns`` declara tres columnas, pero la migracion
que lo acompanyaba solo creo dos: ``brand_color`` se perdio al resolver un
merge. En un despliegue real el esquema lo construye Alembic, asi que la
columna no existia y cualquier lectura de AegisOrgProfile (perfil, envio de
campanya, pagina publica del test) reventaba con UndefinedColumn. La suite no
lo veia porque los tests crean el esquema con ``Base.metadata.create_all``.

Va en una migracion nueva y no editando a1b2c3d4e5f7, que ya esta fusionada y
puede haberse aplicado: reeditarla dejaria esas bases sin la columna para
siempre. El ``IF NOT EXISTS`` la hace inocua alli donde a1b2c3d4e5f7 se
aplicara con la version que si la creaba.

Revision ID: c7d8e9f0a1b2
Revises: 4fe4383a5085
Create Date: 2026-08-28

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'c7d8e9f0a1b2'
down_revision: Union[str, Sequence[str], None] = '4fe4383a5085'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_COLUMN = sa.Column("brand_color", sa.String(length=7), nullable=True)


def upgrade() -> None:
    if not _has_brand_color():
        op.add_column("AegisOrgProfile", _COLUMN)


def downgrade() -> None:
    if _has_brand_color():
        op.drop_column("AegisOrgProfile", "brand_color")


def _has_brand_color() -> bool:
    """Si la columna ya esta, no se toca.

    El inspector es portable (Postgres y SQLite); ``ADD COLUMN IF NOT EXISTS``
    no lo es.
    """
    inspector = sa.inspect(op.get_bind())
    return any(
        column["name"] == "brand_color"
        for column in inspector.get_columns("AegisOrgProfile")
    )
