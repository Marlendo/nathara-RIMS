"""SSO Nathara: link supabase_sub di ops_user + kolom sesi SSO app

PM RIMS 0001 — revisi aditif (JANGAN edit revisi applied):
- ops_user.supabase_sub TEXT UNIQUE NULL + index ix_ops_user_supabase_sub
  (link ke subjek SSO Supabase prod; nullable untuk backfill bertahap).
- user_session: sso_session_id / idp_sub / sso_expires_at (nullable) +
  index ix_user_session_sso_session_id. Kolom token lama dipertahankan
  (nullable bertahap, JANGAN drop di rilis ini).

Revision ID: 7f3a2c9d1e55
Revises: 9c2e7a4d1b38
Create Date: 2026-11-22 00:00:00.000000+00:00

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "7f3a2c9d1e55"
down_revision: Union[str, None] = "9c2e7a4d1b38"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("ops_user", sa.Column("supabase_sub", sa.Text(), nullable=True))
    op.create_index("ix_ops_user_supabase_sub", "ops_user", ["supabase_sub"], unique=True)
    # sqlalchemy-continuum: version-table copy (pola revisi display-name SC).
    op.add_column(
        "ops_user_version",
        sa.Column("supabase_sub", sa.Text(), autoincrement=False, nullable=True),
    )

    op.add_column("user_session", sa.Column("sso_session_id", sa.Text(), nullable=True))
    op.add_column("user_session", sa.Column("idp_sub", sa.Text(), nullable=True))
    op.add_column("user_session", sa.Column("sso_expires_at", sa.DateTime(), nullable=True))
    op.create_index("ix_user_session_sso_session_id", "user_session", ["sso_session_id"], unique=False)
    op.add_column(
        "user_session_version",
        sa.Column("sso_session_id", sa.Text(), autoincrement=False, nullable=True),
    )
    op.add_column(
        "user_session_version",
        sa.Column("idp_sub", sa.Text(), autoincrement=False, nullable=True),
    )
    op.add_column(
        "user_session_version",
        sa.Column("sso_expires_at", sa.DateTime(), autoincrement=False, nullable=True),
    )


def downgrade() -> None:
    op.drop_column("user_session_version", "sso_expires_at")
    op.drop_column("user_session_version", "idp_sub")
    op.drop_column("user_session_version", "sso_session_id")
    op.drop_index("ix_user_session_sso_session_id", table_name="user_session")
    op.drop_column("user_session", "sso_expires_at")
    op.drop_column("user_session", "idp_sub")
    op.drop_column("user_session", "sso_session_id")

    op.drop_column("ops_user_version", "supabase_sub")
    op.drop_index("ix_ops_user_supabase_sub", table_name="ops_user")
    op.drop_column("ops_user", "supabase_sub")
