"""iris: split raw message storage into IrisRawMessage, add indexes (M09/B17/B19)

El resultado analítico pequeño y consultable (score, veredicto, resultados
por regla) vivía en la misma fila que el raw MIME completo
(``IrisAnalysis.raw_headers``, texto plano sin cifrar). Eso impedía purgar
el raw por retención sin borrar también el resultado, y dejaba el contenido
del correo legible para quien tuviera acceso directo a la base de datos.

Esta migración crea ``IrisRawMessage`` (una fila 1:1 por análisis, con el
contenido cifrado vía Fernet -- ``purpose="iris_raw_message"``, mismo
mecanismo que ya protegía los refresh token de OAuth de Iris), traslada
cifrando el contenido de cada ``IrisAnalysis.raw_headers`` existente, y
retira esa columna. ``IrisAnalysis.raw_headers`` sigue existiendo como
property en el modelo (ver ``model.py``): el resto del código no cambia.

De paso (B17) añade los índices que faltaban en las columnas por las que de
verdad se filtra/ordena (``user_id``, ``created_at``, ``status``,
``verdict``, ``connection_id`` en ``IrisAnalysis``; ``analysis_id`` en
``IrisRuleResult``) -- ninguna de las dos tablas tenía más índice que las
UNIQUE constraints ya existentes.

Revision ID: 3a7f74c514d5
Revises: 32f0181bf6d7
Create Date: 2026-09-09 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '3a7f74c514d5'
down_revision: Union[str, Sequence[str], None] = '32f0181bf6d7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'IrisRawMessage',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('analysis_id', sa.Integer(), nullable=False),
        sa.Column('content', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['analysis_id'], ['IrisAnalysis.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('analysis_id'),
    )

    # Backfill: cifra el raw_headers de cada análisis existente hacia su
    # nueva fila IrisRawMessage. Import perezoso -- este módulo de cifrado
    # tira de config_reading, que a su vez engancha con el resto de la app;
    # cargarlo a nivel de módulo de la migración no hace falta salvo aquí.
    from src.modules.shared._crypto import encrypt_at_rest

    connection = op.get_bind()
    rows = connection.execute(
        sa.text('SELECT id, created_at, raw_headers FROM "IrisAnalysis"')
    ).fetchall()
    for analysis_id, created_at, raw_headers in rows:
        if raw_headers is None:
            continue
        connection.execute(
            sa.text(
                'INSERT INTO "IrisRawMessage" (analysis_id, content, created_at) '
                'VALUES (:analysis_id, :content, :created_at)'
            ),
            {
                "analysis_id": analysis_id,
                "content": encrypt_at_rest(raw_headers, purpose="iris_raw_message"),
                "created_at": created_at,
            },
        )

    op.drop_column('IrisAnalysis', 'raw_headers')

    op.create_index('ix_iris_analysis_user_id', 'IrisAnalysis', ['user_id'])
    op.create_index('ix_iris_analysis_created_at', 'IrisAnalysis', ['created_at'])
    op.create_index('ix_iris_analysis_status', 'IrisAnalysis', ['status'])
    op.create_index('ix_iris_analysis_verdict', 'IrisAnalysis', ['verdict'])
    op.create_index('ix_iris_analysis_connection_id', 'IrisAnalysis', ['connection_id'])
    op.create_index('ix_iris_rule_result_analysis_id', 'IrisRuleResult', ['analysis_id'])


def downgrade() -> None:
    """Downgrade schema.

    Limitación conocida: si la retención (M09/B17) ya purgó el raw de
    algún análisis antes de este downgrade, esa fila no tiene
    ``IrisRawMessage`` que restaurar y el ``ALTER COLUMN ... NOT NULL``
    final falla para ella -- un downgrade no puede recuperar un dato que
    la propia política de retención borró a propósito.
    """
    op.drop_index('ix_iris_rule_result_analysis_id', table_name='IrisRuleResult')
    op.drop_index('ix_iris_analysis_connection_id', table_name='IrisAnalysis')
    op.drop_index('ix_iris_analysis_verdict', table_name='IrisAnalysis')
    op.drop_index('ix_iris_analysis_status', table_name='IrisAnalysis')
    op.drop_index('ix_iris_analysis_created_at', table_name='IrisAnalysis')
    op.drop_index('ix_iris_analysis_user_id', table_name='IrisAnalysis')

    op.add_column('IrisAnalysis', sa.Column('raw_headers', sa.Text(), nullable=True))

    from src.modules.shared._crypto import decrypt_at_rest

    connection = op.get_bind()
    rows = connection.execute(
        sa.text('SELECT analysis_id, content FROM "IrisRawMessage"')
    ).fetchall()
    for analysis_id, content in rows:
        connection.execute(
            sa.text('UPDATE "IrisAnalysis" SET raw_headers = :raw_headers WHERE id = :analysis_id'),
            {
                "raw_headers": decrypt_at_rest(content, purpose="iris_raw_message"),
                "analysis_id": analysis_id,
            },
        )

    op.alter_column('IrisAnalysis', 'raw_headers', nullable=False)
    op.drop_table('IrisRawMessage')
