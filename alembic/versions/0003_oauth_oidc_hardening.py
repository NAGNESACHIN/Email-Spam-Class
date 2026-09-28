"""Add OIDC transaction fields and provider issuer identity context.

Revision ID: 0003_oauth_oidc_hardening
Revises: 0002_schema_hardening
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

revision="0003_oauth_oidc_hardening"
down_revision="0002_schema_hardening"
branch_labels=None
depends_on=None


def _columns(bind, table):
    return {column.get("name") for column in inspect(bind).get_columns(table)}


def _indexes(bind, table):
    return {index.get("name") for index in inspect(bind).get_indexes(table)}


def upgrade():
    bind=op.get_bind()
    tables=set(inspect(bind).get_table_names())

    if "oauth_states" in tables:
        cols=_columns(bind,"oauth_states")
        if "browser_binding_hash" not in cols:
            op.add_column("oauth_states",sa.Column("browser_binding_hash",sa.String(length=64),nullable=True))
        if "code_challenge" not in cols:
            op.add_column("oauth_states",sa.Column("code_challenge",sa.String(length=128),nullable=True))
        if "nonce_hash" not in cols:
            op.add_column("oauth_states",sa.Column("nonce_hash",sa.String(length=64),nullable=True))
        if "redirect_uri" not in cols:
            op.add_column("oauth_states",sa.Column("redirect_uri",sa.String(length=1024),nullable=True))
        if "consumed_at" not in cols:
            op.add_column("oauth_states",sa.Column("consumed_at",sa.DateTime(),nullable=True))

    if "oauth_identities" in tables:
        cols=_columns(bind,"oauth_identities")
        if "issuer" not in cols:
            op.add_column("oauth_identities",sa.Column("issuer",sa.String(length=512),nullable=True))
        if "tenant_id" not in cols:
            op.add_column("oauth_identities",sa.Column("tenant_id",sa.String(length=128),nullable=True))

        indexes=_indexes(bind,"oauth_identities")
        if "ix_oauth_identity_issuer_subject" not in indexes:
            op.create_index(
                "ix_oauth_identity_issuer_subject",
                "oauth_identities",
                ["provider","issuer","subject"],
                unique=False,
            )


def downgrade():
    bind=op.get_bind()
    tables=set(inspect(bind).get_table_names())
    if "oauth_identities" in tables:
        indexes=_indexes(bind,"oauth_identities")
        if "ix_oauth_identity_issuer_subject" in indexes:
            op.drop_index("ix_oauth_identity_issuer_subject",table_name="oauth_identities")
        cols=_columns(bind,"oauth_identities")
        for name in ("tenant_id","issuer"):
            if name in cols:
                op.drop_column("oauth_identities",name)

    if "oauth_states" in tables:
        cols=_columns(bind,"oauth_states")
        for name in ("consumed_at","redirect_uri","nonce_hash","code_challenge","browser_binding_hash"):
            if name in cols:
                op.drop_column("oauth_states",name)
