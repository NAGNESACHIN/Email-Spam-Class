"""Add user ownership foreign keys and scan history index.

Revision ID: 0002_schema_hardening
Revises: 0001_baseline
"""

from alembic import op
from sqlalchemy import inspect

revision="0002_schema_hardening"
down_revision="0001_baseline"
branch_labels=None
depends_on=None


def _has_fk(insp,table,column,target_table):
    return any(
        fk.get("referred_table")==target_table and column in (fk.get("constrained_columns") or [])
        for fk in insp.get_foreign_keys(table)
    )


def upgrade():
    bind=op.get_bind()
    insp=inspect(bind)
    if "users" not in insp.get_table_names():
        # Fresh databases can be initialized from the current SQLAlchemy metadata.
        from backend.auth import Base
        Base.metadata.create_all(bind)
        return

    if "scans" in insp.get_table_names() and not _has_fk(insp,"scans","user_id","users"):
        if bind.dialect.name=="sqlite":
            with op.batch_alter_table("scans",recreate="always") as batch:
                batch.create_foreign_key("fk_scans_user_id","users",["user_id"],["id"],ondelete="CASCADE")
        else:
            op.create_foreign_key("fk_scans_user_id","scans","users",["user_id"],["id"],ondelete="CASCADE")

    if "oauth_identities" in insp.get_table_names() and not _has_fk(insp,"oauth_identities","user_id","users"):
        if bind.dialect.name=="sqlite":
            with op.batch_alter_table("oauth_identities",recreate="always") as batch:
                batch.create_foreign_key("fk_oauth_identities_user_id","users",["user_id"],["id"],ondelete="CASCADE")
        else:
            op.create_foreign_key("fk_oauth_identities_user_id","oauth_identities","users",["user_id"],["id"],ondelete="CASCADE")

    if "oauth_codes" in insp.get_table_names() and not _has_fk(insp,"oauth_codes","user_id","users"):
        if bind.dialect.name=="sqlite":
            with op.batch_alter_table("oauth_codes",recreate="always") as batch:
                batch.create_foreign_key("fk_oauth_codes_user_id","users",["user_id"],["id"],ondelete="CASCADE")
        else:
            op.create_foreign_key("fk_oauth_codes_user_id","oauth_codes","users",["user_id"],["id"],ondelete="CASCADE")

    insp=inspect(bind)
    indexes={idx.get("name") for idx in insp.get_indexes("scans")} if "scans" in insp.get_table_names() else set()
    if "ix_scans_user_timestamp" not in indexes and "scans" in insp.get_table_names():
        op.create_index("ix_scans_user_timestamp","scans",["user_id","timestamp"],unique=False)


def downgrade():
    # Keep downgrade conservative because production data may already depend on
    # these ownership constraints. Remove the index explicitly; foreign keys can
    # be dropped in a reviewed migration when a rollback is required.
    bind=op.get_bind()
    insp=inspect(bind)
    indexes={idx.get("name") for idx in insp.get_indexes("scans")} if "scans" in insp.get_table_names() else set()
    if "ix_scans_user_timestamp" in indexes:
        op.drop_index("ix_scans_user_timestamp",table_name="scans")
