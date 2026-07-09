"""rename sentinel/ellysia to themis/lybra

Non-destructive rename following the Sentinel->Themis module rename and the
Ellysia->Lybra engine rename (both already applied at the Python/ORM level).
Renames tables so the schema matches the new __tablename__ values, and
rewrites persisted string values so existing rows keep working under the new
names:

  - EllysiaScan -> LybraScan, SentinelDocument -> ThemisDocument (table rename;
    Postgres keeps FK constraints intact across a rename).
  - Scan.scan_type 'ellysia' -> 'lybra' (the polymorphic_identity value).
  - Finding.source 'ellysia' -> 'lybra', and the 'ellysia:' prefix in
    Finding.check_id / 'ellysia' substring in Finding.feed_version -> 'lybra'.
  - UserAttribute.attribute_name 'sentinel_*' -> 'themis_*' -- the ABAC
    permission strings already granted to real users. This is the one that
    matters most: skipping it would silently strip scan permissions from
    every user who already has them.

Verified against the live dev DB before writing this: EllysiaScan and
SentinelDocument exist under their old names; no scan_type/Finding.source
rows say 'ellysia' yet (those UPDATEs are defensive no-ops here, not dead
code -- another environment may have them); 11 UserAttribute rows do say
'sentinel_*' and are the real reason this migration exists.

Revision ID: 970ef4458365
Revises: a9b0c1d2e3f4
Create Date: 2026-07-08 22:17:48.983262

"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = '970ef4458365'
down_revision: Union[str, Sequence[str], None] = 'a9b0c1d2e3f4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.rename_table('EllysiaScan', 'LybraScan')
    op.rename_table('SentinelDocument', 'ThemisDocument')

    op.execute("UPDATE \"Scan\" SET scan_type = 'lybra' WHERE scan_type = 'ellysia'")
    op.execute("UPDATE \"Finding\" SET source = 'lybra' WHERE source = 'ellysia'")
    op.execute("UPDATE \"Finding\" SET check_id = REPLACE(check_id, 'ellysia:', 'lybra:') "
               "WHERE check_id LIKE 'ellysia:%'")
    op.execute("UPDATE \"Finding\" SET feed_version = REPLACE(feed_version, 'ellysia', 'lybra') "
               "WHERE feed_version LIKE '%ellysia%'")
    op.execute("UPDATE \"UserAttribute\" SET attribute_name = REPLACE(attribute_name, 'sentinel_', 'themis_') "
               "WHERE attribute_name LIKE 'sentinel_%'")


def downgrade() -> None:
    """Downgrade schema."""
    op.execute("UPDATE \"UserAttribute\" SET attribute_name = REPLACE(attribute_name, 'themis_', 'sentinel_') "
               "WHERE attribute_name LIKE 'themis_%'")
    op.execute("UPDATE \"Finding\" SET feed_version = REPLACE(feed_version, 'lybra', 'ellysia') "
               "WHERE feed_version LIKE '%lybra%'")
    op.execute("UPDATE \"Finding\" SET check_id = REPLACE(check_id, 'lybra:', 'ellysia:') "
               "WHERE check_id LIKE 'lybra:%'")
    op.execute("UPDATE \"Finding\" SET source = 'ellysia' WHERE source = 'lybra'")
    op.execute("UPDATE \"Scan\" SET scan_type = 'ellysia' WHERE scan_type = 'lybra'")

    op.rename_table('ThemisDocument', 'SentinelDocument')
    op.rename_table('LybraScan', 'EllysiaScan')
