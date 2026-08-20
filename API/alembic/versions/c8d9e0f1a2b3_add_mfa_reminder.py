"""Añade el control de periodicidad de los recordatorios MFA."""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "c8d9e0f1a2b3"
down_revision: Union[str, Sequence[str], None] = "b7c8d9e0f1a2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Añade la fecha del último recordatorio enviado por usuario."""
    op.add_column(
        "User",
        sa.Column("last_mfa_reminder_at", sa.DateTime(), nullable=True),
    )


def downgrade() -> None:
    """Revierte la fecha de control de recordatorios MFA."""
    op.drop_column("User", "last_mfa_reminder_at")
