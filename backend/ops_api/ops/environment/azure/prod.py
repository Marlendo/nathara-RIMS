import os

from ops_api.ops.environment.default_settings import *  # noqa: F403, F401

DEBUG = False

# Pull secrets from ACA Environment
db_username = os.getenv("PGUSER")
db_password = os.getenv("PGPASSWORD")
db_host = os.getenv("PGHOST")
db_port = os.getenv("PGPORT")
db_name = os.getenv("PGDATABASE")

OPS_FRONTEND_URL = os.getenv("OPS_FRONTEND_URL")

SQLALCHEMY_DATABASE_URI = (
    f"postgresql+psycopg2://{db_username}:{db_password}@{db_host}:{db_port}/{db_name}"  # noqa: B950
)

SQLALCHEMY_ECHO = False


# CSRF Protection
# This is the prefix for the Host header in the cloud environment.
HOST_HEADER_PREFIX = "opre-ops-prod-app-backend."

SUPER_USER = "SUPER_USER"

# Increase pool size for production environment
SQLALCHEMY_POOL_SIZE = 20
SQLALCHEMY_MAX_OVERFLOW = 20

# Skip Change Request for Draft->Planned status changes and in-Planned budget edits.
# Disabled in production (Change Request review remains required).
SKIP_CR_FOR_DRAFT_PLANNED = True

# Allow today/past Obligate By dates on non-Draft budget lines (issue 6443); see default_settings.py to turn it off.
ALLOW_PAST_OBLIGATE_BY_DATES = True

# MIGRATION (PM RIMS 0001): AUTHLIB provider lama DIMATIKAN (dict kosong).
AUTHLIB_OAUTH_CLIENTS = {}
