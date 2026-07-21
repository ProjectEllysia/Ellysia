"""add aegis org profile

Revision ID: 3e6128d45a70
Revises: 66b2381dcb8b
Create Date: 2026-07-12 10:31:01.617195

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '3e6128d45a70'
down_revision: Union[str, Sequence[str], None] = '66b2381dcb8b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Recortado a mano: el autogenerate también detectó deriva de esquema
    # preexistente y no relacionada (constraints de FK del vault de Acheron
    # perdiendo ondelete=CASCADE, renombres de índice en MFA, cambio de tipo
    # en OpenVASVulnerability) — fuera de alcance de este cambio, no se toca.
    op.create_table(
        'AegisOrgProfile',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('company', sa.String(length=128), nullable=True),
        sa.Column('contact_email', sa.String(length=128), nullable=True),
        sa.Column('tone', sa.String(length=32), nullable=True),
        sa.Column('company_size', sa.String(length=16), nullable=True),
        sa.Column('jurisdiction', sa.String(length=128), nullable=True),
        sa.Column('language', sa.String(length=8), nullable=True),
        sa.Column('sector', sa.String(length=128), nullable=True),
        sa.Column('work_model', sa.String(length=16), nullable=True),
        sa.Column('employee_count', sa.Integer(), nullable=True),
        sa.Column('associated_brands', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['User.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('user_id'),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table('AegisOrgProfile')
