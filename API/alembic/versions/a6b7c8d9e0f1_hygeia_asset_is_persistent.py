"""hygeia: activos que se apagan a proposito (is_persistent)

Hasta ahora todo silencio era una incidencia: el detector de presencia abria
``host_down`` critica y mandaba correo en cuanto un activo dejaba de reportar.
Correcto para un servidor 24/7, ruido puro para un portatil que se suspende de
noche — y una alerta que suena cada noche por algo esperado es una alerta que
su dueño aprende a ignorar.

``is_persistent`` marca esa expectativa por activo. ``False`` no cambia la
transicion de estado (el activo sigue pasando a ``offline``: el estado es un
hecho observado, no una opinion), solo suprime la anomalia y, con ella, el
correo.

NOT NULL con ``server_default=true``: a diferencia de ``inventory``, aqui no
hay un tercer significado que un NULL pudiera representar — un activo o se
espera encendido o no — y el default rellena las filas existentes con el
comportamiento que ya tenian.

Revision ID: a6b7c8d9e0f1
Revises: f5e6f7a8b9c0
Create Date: 2026-08-11 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "a6b7c8d9e0f1"
down_revision: Union[str, Sequence[str], None] = "f5e6f7a8b9c0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        "MonitoredAsset",
        sa.Column("is_persistent", sa.Boolean(), nullable=False, server_default=sa.true()),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("MonitoredAsset", "is_persistent")
