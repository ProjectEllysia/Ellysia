"""fix Document.document_type sentinel to themis

970ef4458365 renamed the Scan.scan_type / Finding.source / UserAttribute
discriminators for the Sentinel->Themis and Ellysia->Lybra renames, but
missed one: Document is itself a polymorphic base table (shared by Aegis,
Iris and Themis documents), and its own discriminator column,
document_type, still had rows saying 'sentinel' -- the value
ThemisDocument's polymorphic_identity used to be, before the rename.

SQLAlchemy raises AssertionError: No such polymorphic_identity 'sentinel'
is defined the moment it tries to hydrate one of these rows, since no
mapper is registered under that identity anymore -- surfaced as a 500 on
GET /themis/results the first time a scan with a generated PDF report
got listed.

Revision ID: e9e894e2791e
Revises: 970ef4458365
Create Date: 2026-07-09 16:19:27.903210

"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = 'e9e894e2791e'
down_revision: Union[str, Sequence[str], None] = '970ef4458365'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.execute("UPDATE \"Document\" SET document_type = 'themis' WHERE document_type = 'sentinel'")


def downgrade() -> None:
    """Downgrade schema."""
    op.execute("UPDATE \"Document\" SET document_type = 'sentinel' WHERE document_type = 'themis'")
