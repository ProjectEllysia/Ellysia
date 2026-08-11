"""drop openvas tables

Roadmap Lybra §7/§6.3, Ronda 2 (E2+E3): OpenVAS se retira del producto y del
código; esta migración retira sus tres tablas nativas
(``OpenVASScanResult``, ``OpenVASScan``, ``OpenVASVulnerability``). Sin paso
de backfill previo: verificado por consulta antes de escribir esta migración
que las tres estaban vacías en la base de desarrollo (0 filas cada una), así
que no hay nada que archivar. Los `Finding` con `source="openvas"` viven en
la tabla `Finding`, ajena a esta migración, y no se ven afectados.

El autogenerate de esta revisión arrastraba la misma deriva preexistente que
``e343ef335a44`` ya documentaba (renombrados de índice case-sensitive,
recreación de FKs de Acheron) — se descarta y se deja solo el drop/create de
las tres tablas de OpenVAS. El orden de ``downgrade()`` también se corrigió a
mano: el autogenerate recreaba ``OpenVASScanResult`` (que referencia a las
otras dos por FK) antes que sus propias tablas destino, lo que habría fallado
en Postgres al no existir todavía ``OpenVASScan``/``OpenVASVulnerability``.

Revision ID: 6192692bd7d7
Revises: e343ef335a44
Create Date: 2026-07-31 21:54:24.400498

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '6192692bd7d7'
down_revision: Union[str, Sequence[str], None] = 'e343ef335a44'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # OpenVASScanResult primero: es la única de las tres con FKs salientes
    # hacia las otras dos.
    op.drop_index(op.f('ix_OpenVASScanResult_vulnerability_id'), table_name='OpenVASScanResult')
    op.drop_index(op.f('ix_OpenVASScanResult_openvas_scan_id'), table_name='OpenVASScanResult')
    op.drop_index(op.f('ix_OpenVASScanResult_host_id'), table_name='OpenVASScanResult')
    op.drop_table('OpenVASScanResult')

    op.drop_table('OpenVASScan')

    op.drop_index(op.f('ix_OpenVASVulnerability_nvt_oid'), table_name='OpenVASVulnerability')
    op.drop_index(op.f('ix_OpenVASVulnerability_severity_class'), table_name='OpenVASVulnerability')
    op.drop_table('OpenVASVulnerability')


def downgrade() -> None:
    """Downgrade schema."""
    op.create_table(
        'OpenVASVulnerability',
        sa.Column('id', sa.INTEGER(), autoincrement=True, nullable=False),
        sa.Column('nvt_oid', sa.VARCHAR(length=255), autoincrement=False, nullable=False),
        sa.Column('name', sa.TEXT(), autoincrement=False, nullable=False),
        sa.Column('severity_score', sa.REAL(), autoincrement=False, nullable=True),
        sa.Column('severity_class', sa.VARCHAR(length=20), autoincrement=False, nullable=True),
        sa.Column('cvss_base_score', sa.REAL(), autoincrement=False, nullable=True),
        sa.Column('cvss_vector', sa.VARCHAR(length=255), autoincrement=False, nullable=True),
        sa.Column('cve_ids', sa.TEXT(), autoincrement=False, nullable=True),
        sa.Column('cert_refs', sa.TEXT(), autoincrement=False, nullable=True),
        sa.Column('bugtraq_ids', sa.TEXT(), autoincrement=False, nullable=True),
        sa.Column('other_refs', sa.TEXT(), autoincrement=False, nullable=True),
        sa.Column('summary', sa.TEXT(), autoincrement=False, nullable=True),
        sa.Column('description', sa.TEXT(), autoincrement=False, nullable=True),
        sa.Column('impact', sa.TEXT(), autoincrement=False, nullable=True),
        sa.Column('insight', sa.TEXT(), autoincrement=False, nullable=True),
        sa.Column('affected_software', sa.TEXT(), autoincrement=False, nullable=True),
        sa.Column('solution_type', sa.VARCHAR(length=50), autoincrement=False, nullable=True),
        sa.Column('solution', sa.TEXT(), autoincrement=False, nullable=True),
        sa.Column('qod_value', sa.INTEGER(), autoincrement=False, nullable=True),
        sa.Column('qod_type', sa.VARCHAR(length=100), autoincrement=False, nullable=True),
        sa.Column('family', sa.VARCHAR(length=255), autoincrement=False, nullable=True),
        sa.Column('category', sa.VARCHAR(length=255), autoincrement=False, nullable=True),
        sa.Column('created_at', postgresql.TIMESTAMP(), autoincrement=False, nullable=False),
        sa.Column('updated_at', postgresql.TIMESTAMP(), autoincrement=False, nullable=True),
        sa.PrimaryKeyConstraint('id', name=op.f('OpenVASVulnerability_pkey')),
    )
    op.create_index(op.f('ix_OpenVASVulnerability_severity_class'), 'OpenVASVulnerability', ['severity_class'], unique=False)
    op.create_index(op.f('ix_OpenVASVulnerability_nvt_oid'), 'OpenVASVulnerability', ['nvt_oid'], unique=True)

    op.create_table(
        'OpenVASScan',
        sa.Column('id', sa.INTEGER(), autoincrement=False, nullable=False),
        sa.Column('task_id', sa.VARCHAR(length=255), autoincrement=False, nullable=False),
        sa.Column('report_id', sa.VARCHAR(length=255), autoincrement=False, nullable=False),
        sa.Column('scan_config_name', sa.VARCHAR(length=255), autoincrement=False, nullable=True),
        sa.Column('scanner_name', sa.VARCHAR(length=255), autoincrement=False, nullable=True),
        sa.ForeignKeyConstraint(['id'], ['Scan.id'], name=op.f('OpenVASScan_id_fkey')),
        sa.PrimaryKeyConstraint('id', name=op.f('OpenVASScan_pkey')),
        sa.UniqueConstraint('task_id', 'report_id', name=op.f('unique_task_report')),
    )

    op.create_table(
        'OpenVASScanResult',
        sa.Column('id', sa.INTEGER(), autoincrement=True, nullable=False),
        sa.Column('openvas_scan_id', sa.INTEGER(), autoincrement=False, nullable=False),
        sa.Column('vulnerability_id', sa.INTEGER(), autoincrement=False, nullable=False),
        sa.Column('host_id', sa.INTEGER(), autoincrement=False, nullable=False),
        sa.Column('detected_at', postgresql.TIMESTAMP(), autoincrement=False, nullable=False),
        sa.ForeignKeyConstraint(['host_id'], ['Host.id'], name=op.f('OpenVASScanResult_host_id_fkey')),
        sa.ForeignKeyConstraint(['openvas_scan_id'], ['OpenVASScan.id'], name=op.f('OpenVASScanResult_openvas_scan_id_fkey'), ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['vulnerability_id'], ['OpenVASVulnerability.id'], name=op.f('OpenVASScanResult_vulnerability_id_fkey')),
        sa.PrimaryKeyConstraint('id', name=op.f('OpenVASScanResult_pkey')),
    )
    op.create_index(op.f('ix_OpenVASScanResult_vulnerability_id'), 'OpenVASScanResult', ['vulnerability_id'], unique=False)
    op.create_index(op.f('ix_OpenVASScanResult_openvas_scan_id'), 'OpenVASScanResult', ['openvas_scan_id'], unique=False)
    op.create_index(op.f('ix_OpenVASScanResult_host_id'), 'OpenVASScanResult', ['host_id'], unique=False)
