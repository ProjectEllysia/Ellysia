"""lybra: avisos de distribucion para verificar backports

Revision ID: 6ec0a7bf3ba1
Revises: 0fd9d718b2a2
Create Date: 2026-09-03 20:41:05.333746

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = '6ec0a7bf3ba1'
down_revision: Union[str, Sequence[str], None] = '0fd9d718b2a2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema.

    Las dos tablas de la Fase O: el aviso del proveedor y lo que dice de cada
    paquete. Es la brecha G3 del roadmap —los backports— y ataca la causa
    número uno de falsos positivos de la detección por versión.

    El constraint que importa es el de `DistroPkgStatus`: un pronunciamiento por
    `(vendor, release, package, cve)`. Sin él, cada sincronización acumularía
    filas repetidas y la consulta tendría que elegir entre varias respuestas
    para la misma pregunta.

    `release` admite nulo a propósito: hay avisos que aplican a todas las
    versiones del proveedor, e inventarles una concreta sería peor que no
    tenerla.

    Ambas nacen vacías. Sin sincronizar el feed no hay verificación de
    backports, y la consecuencia es exactamente la de antes de esta migración:
    el hallazgo se queda con su `qod=70` y su `confirmed=false`.
    """
    op.create_table(
        "DistroAdvisory",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("advisory_id", sa.String(length=64), nullable=False),
        sa.Column("vendor", sa.String(length=32), nullable=False),
        sa.Column("title", sa.Text(), nullable=True),
        sa.Column("cve_ids", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("published", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_DistroAdvisory_advisory_id"), "DistroAdvisory",
                    ["advisory_id"], unique=True)
    op.create_index(op.f("ix_DistroAdvisory_vendor"), "DistroAdvisory", ["vendor"], unique=False)

    op.create_table(
        "DistroPkgStatus",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("vendor", sa.String(length=32), nullable=False),
        sa.Column("release", sa.String(length=32), nullable=True),
        sa.Column("package", sa.String(length=128), nullable=False),
        sa.Column("cve_id", sa.String(length=32), nullable=False),
        sa.Column("fixed_in", sa.String(length=64), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("vendor", "release", "package", "cve_id",
                            name="unique_distro_pkg_status"),
    )
    op.create_index(op.f("ix_DistroPkgStatus_vendor"), "DistroPkgStatus", ["vendor"], unique=False)
    op.create_index(op.f("ix_DistroPkgStatus_package"), "DistroPkgStatus", ["package"], unique=False)
    op.create_index(op.f("ix_DistroPkgStatus_cve_id"), "DistroPkgStatus", ["cve_id"], unique=False)


def downgrade() -> None:
    """Downgrade schema.

    Se pierde el espejo de avisos de distribución. Ningún hallazgo depende de
    él: sin estas tablas la verificación de backports simplemente no se aplica,
    y los hallazgos por versión vuelven a quedarse como hipótesis, que es lo que
    eran antes.
    """
    op.drop_index(op.f("ix_DistroPkgStatus_cve_id"), table_name="DistroPkgStatus")
    op.drop_index(op.f("ix_DistroPkgStatus_package"), table_name="DistroPkgStatus")
    op.drop_index(op.f("ix_DistroPkgStatus_vendor"), table_name="DistroPkgStatus")
    op.drop_table("DistroPkgStatus")
    op.drop_index(op.f("ix_DistroAdvisory_vendor"), table_name="DistroAdvisory")
    op.drop_index(op.f("ix_DistroAdvisory_advisory_id"), table_name="DistroAdvisory")
    op.drop_table("DistroAdvisory")
