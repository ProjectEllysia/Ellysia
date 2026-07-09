"""add MFA (TOTP) support: credentials, recovery codes, login challenges

Anade el soporte para autenticacion multifactor (MFA) via TOTP, como
funcionalidad global de la API (no especifica de Acheron):
  - MFATotpCredential : secreto TOTP cifrado en reposo, uno por usuario.
  - MFARecoveryCode   : codigos de recuperacion de un solo uso.
  - MFAChallenge      : desafio de corta duracion emitido tras el grant
                        'password' cuando el usuario tiene MFA activado;
                        se canjea en POST /oauth/mfa/verify.

Revision ID: a9b0c1d2e3f4
Revises: f6a7b8c9d0e1
Create Date: 2026-07-06 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a9b0c1d2e3f4'
down_revision: Union[str, Sequence[str], None] = 'c9d0e1f2a3b4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'MFATotpCredential',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('User.id'), nullable=False, unique=True),
        sa.Column('secret_encrypted', sa.String(length=512), nullable=False),
        sa.Column('confirmed_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
    )

    op.create_table(
        'MFARecoveryCode',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('User.id'), nullable=False),
        sa.Column('code_hash', sa.String(length=512), nullable=False),
        sa.Column('used_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
    )
    op.create_index('ix_mfarecoverycode_user_id', 'MFARecoveryCode', ['user_id'])

    op.create_table(
        'MFAChallenge',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('token', sa.String(length=512), nullable=False),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('User.id'), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.Column('attempts', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('created_at', sa.DateTime(), nullable=False),
    )
    op.create_index('ix_mfachallenge_token', 'MFAChallenge', ['token'], unique=True)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('ix_mfachallenge_token', table_name='MFAChallenge')
    op.drop_table('MFAChallenge')
    op.drop_index('ix_mfarecoverycode_user_id', table_name='MFARecoveryCode')
    op.drop_table('MFARecoveryCode')
    op.drop_table('MFATotpCredential')
