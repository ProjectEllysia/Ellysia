"""scan: por qué falló, no sólo que falló

Revision ID: c3a7d1e94b52
Revises: 6ec0a7bf3ba1
Create Date: 2026-09-04 14:10:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c3a7d1e94b52'
down_revision: Union[str, Sequence[str], None] = '6ec0a7bf3ba1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema.

    Un escaneo que acaba en FAILED puede haber acabado ahí por motivos muy
    distintos: el host no respondía, el barrido de puertos no llegó a
    completarse, el escáner externo no devolvió nada, el proceso murió a mitad y
    la reconciliación de arranque lo cerró, o el motor lanzó una excepción. Hasta
    ahora los cinco casos se guardaban igual —``status = 'failed'`` y nada más—,
    así que la interfaz sólo podía escribir la misma frase genérica para todos,
    y el usuario no tenía forma de saber si el problema era suyo (una IP mal
    escrita, una máquina apagada) o del producto.

    La columna guarda un **código** corto (``host_unreachable``,
    ``port_discovery_failed``, ``no_results``, ``orphaned``, ``internal_error``),
    no una frase: la prosa de cara al usuario vive en el SPA y en castellano.

    Va en ``Scan`` y no en ``LybraScan`` porque cuatro de los cinco puntos de
    fallo están en ``ScanManager``, que comparten los cuatro escáneres.

    Nullable y sin ``server_default``, al revés que ``LybraScan.is_partial``:
    aquí no hay ningún valor que sea cierto para las filas que ya existen. Un
    escaneo que falló antes de esta migración no dejó constancia del motivo, y
    rellenarlo con cualquiera de los cinco códigos sería inventárselo. ``NULL``
    dice justo lo que pasa: no se sabe.
    """
    op.add_column(
        "Scan",
        sa.Column("failure_reason", sa.String(length=40), nullable=True),
    )


def downgrade() -> None:
    """Downgrade schema.

    Se pierde el motivo de los escaneos ya fallados, y con él se vuelve al
    comportamiento anterior: la interfaz sólo puede decir que el escaneo falló.
    No se pierde ningún hallazgo ni ningún escaneo — el estado ``failed`` sigue
    en su columna de siempre.
    """
    op.drop_column("Scan", "failure_reason")
