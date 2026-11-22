from ops_api.ops.environment.default_settings import *  # noqa: F403, F401

DEBUG = True  # make sure DEBUG is off unless enabled explicitly otherwise

# pragma: allowlist secret
SQLALCHEMY_DATABASE_URI = "postgresql+psycopg2://ops:ops@db:5432/postgres"  # pragma: allowlist secret
SQLALCHEMY_ECHO = False

# Increase pool size for local development and E2E testing
# Local E2E tests make many concurrent requests that can exhaust the default pool
SQLALCHEMY_POOL_SIZE = 20
SQLALCHEMY_MAX_OVERFLOW = 20

# MIGRATION (PM RIMS 0001): AUTHLIB provider lama DIMATIKAN (dict kosong).
AUTHLIB_OAUTH_CLIENTS = {}
