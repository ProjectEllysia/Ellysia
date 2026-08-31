"""Retirar el acoplamiento de Lybra con escáneres de terceros (#341)

Revision ID: e8f9a0b1c2d3
Revises: f1e0d1ee8820
Create Date: 2026-08-30 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB


# revision identifiers, used by Alembic.
revision: str = 'e8f9a0b1c2d3'
# Reencadenada sobre la fase 0 de Iris (#200). Esta revisión se escribió
# cuando `d7e8f9a0b1c2` era la punta; mientras esta rama avanzaba, esa fase
# metió cuatro migraciones colgando del mismo padre, así que al juntar las dos
# líneas el árbol quedaba con dos cabezas y `alembic upgrade head` —que
# `run.py` ejecuta en cada arranque— se negaba a elegir. La API no arrancaba.
#
# Se recoloca esta y no las otras porque es la que aún no se había integrado.
# No hay dependencia real entre ambas: aquellas tocan `IrisAnalysis` y
# `IrisMailboxConnection`, esta solo `LybraScan`, así que el orden entre ellas
# da igual y lo único que importa es que haya uno.
down_revision: Union[str, Sequence[str], None] = 'f1e0d1ee8820'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema.

    Lybra dejaba de ser independiente en dos columnas de su propia tabla:

    - ``source_scan_id`` guardaba el escaneo Nmap previo cuyos servicios se
      analizaban, uno de los modos de arranque del motor. Es una clave foránea
      a ``Scan.id``, así que PostgreSQL exige soltar la restricción antes de
      borrar la columna; Alembic no lo hace solo cuando la restricción se creó
      sin nombre explícito, de ahí la consulta al catálogo.
    - ``deep_scan_ids`` guardaba los ids de los escaneos Nmap/Nikto/Nuclei que
      el "análisis profundo" lanzaba como corroboradores, para fundir sus
      hallazgos con los de Lybra al leer el informe.

    Los hallazgos ya almacenados no se tocan: los que produjo un corroborador
    siguen colgando de *su propio* escaneo, que siempre fue una fila ``Scan``
    ordinaria e independiente. Lo único que desaparece es el vínculo que hacía
    que se leyeran bajo la firma de Lybra.
    """
    bind = op.get_bind()
    # El nombre de la clave foránea depende de cómo se creara la tabla (Alembic
    # sin convención de nombres deja que PostgreSQL lo genere), así que se
    # busca en el catálogo en vez de darlo por supuesto.
    if bind.dialect.name == "postgresql":
        constraints = bind.execute(sa.text("""
            SELECT con.conname
            FROM pg_constraint con
            JOIN pg_class rel ON rel.oid = con.conrelid
            JOIN pg_attribute att ON att.attrelid = rel.oid AND att.attnum = ANY(con.conkey)
            WHERE rel.relname = 'LybraScan'
              AND con.contype = 'f'
              AND att.attname = 'source_scan_id'
        """)).scalars().all()
        for name in constraints:
            op.drop_constraint(name, "LybraScan", type_="foreignkey")

    op.drop_column("LybraScan", "source_scan_id")
    op.drop_column("LybraScan", "deep_scan_ids")


def downgrade() -> None:
    """Downgrade schema.

    Recrea las dos columnas vacías. No intenta reconstruir su contenido: el
    dato que guardaban —qué escaneo Nmap originó éste, qué corroboradores se
    lanzaron— no existe en ninguna otra parte del esquema, y rellenarlo a
    ojo sería inventárselo.
    """
    op.add_column("LybraScan", sa.Column("deep_scan_ids", JSONB, nullable=True))
    op.add_column("LybraScan", sa.Column("source_scan_id", sa.Integer(), nullable=True))
    op.create_foreign_key(
        "LybraScan_source_scan_id_fkey", "LybraScan", "Scan", ["source_scan_id"], ["id"],
    )
