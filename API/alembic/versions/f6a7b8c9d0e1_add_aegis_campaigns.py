"""add Aegis quiz + awareness campaigns

Adds the data model for the Aegis "campaigns" feature: a multiple-choice
quiz attached to each pill (AegisQuizQuestion), reusable distribution lists
(DistributionList/Recipient), and campaigns that send a pill+quiz to a list
via email with a per-recipient, token-based, no-login, one-shot quiz link
(Campaign/CampaignRecipient/CampaignAnswer).

Revision ID: f6a7b8c9d0e1
Revises: e5f6a7b8c9d0
Create Date: 2026-07-03 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = 'f6a7b8c9d0e1'
down_revision: Union[str, Sequence[str], None] = 'e5f6a7b8c9d0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'AegisQuizQuestion',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('document_id', sa.Integer(), nullable=False),
        sa.Column('position', sa.SmallInteger(), nullable=False),
        sa.Column('prompt', sa.Text(), nullable=False),
        sa.Column('options', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('correct_index', sa.SmallInteger(), nullable=False),
        sa.ForeignKeyConstraint(['document_id'], ['AegisDocument.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('document_id', 'position', name='uq_question_document_position'),
    )

    op.create_table(
        'DistributionList',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=128), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['User.id'], ),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'Recipient',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('list_id', sa.Integer(), nullable=False),
        sa.Column('email', sa.String(length=256), nullable=False),
        sa.Column('name', sa.String(length=128), nullable=True),
        sa.ForeignKeyConstraint(['list_id'], ['DistributionList.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('list_id', 'email', name='uq_recipient_list_email'),
    )

    op.create_table(
        'Campaign',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('document_id', sa.Integer(), nullable=False),
        sa.Column('list_id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=128), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('questions_snapshot', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('launched_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['User.id'], ),
        sa.ForeignKeyConstraint(['document_id'], ['AegisDocument.id'], ),
        sa.ForeignKeyConstraint(['list_id'], ['DistributionList.id'], ),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'CampaignRecipient',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('campaign_id', sa.Integer(), nullable=False),
        sa.Column('recipient_email', sa.String(length=256), nullable=False),
        sa.Column('recipient_name', sa.String(length=128), nullable=True),
        sa.Column('token', sa.String(length=64), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('sent_at', sa.DateTime(), nullable=True),
        sa.Column('opened_at', sa.DateTime(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.Column('score', sa.SmallInteger(), nullable=True),
        sa.ForeignKeyConstraint(['campaign_id'], ['Campaign.id'], ),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        op.f('ix_CampaignRecipient_token'), 'CampaignRecipient', ['token'], unique=True,
    )

    op.create_table(
        'CampaignAnswer',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('campaign_recipient_id', sa.Integer(), nullable=False),
        sa.Column('question_position', sa.SmallInteger(), nullable=False),
        sa.Column('selected_index', sa.SmallInteger(), nullable=False),
        sa.Column('is_correct', sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(['campaign_recipient_id'], ['CampaignRecipient.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint(
            'campaign_recipient_id', 'question_position', name='uq_answer_recipient_question',
        ),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table('CampaignAnswer')
    op.drop_index(op.f('ix_CampaignRecipient_token'), table_name='CampaignRecipient')
    op.drop_table('CampaignRecipient')
    op.drop_table('Campaign')
    op.drop_table('Recipient')
    op.drop_table('DistributionList')
    op.drop_table('AegisQuizQuestion')
