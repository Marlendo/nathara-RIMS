from ops_api.ops.environment.default_settings import *  # noqa: F403, F401

DEBUG = True  # make sure DEBUG is off unless enabled explicitly otherwise

# pragma: allowlist secret
SQLALCHEMY_DATABASE_URI = "postgresql+psycopg2://ops:ops@localhost:5432/postgres"  # pragma: allowlist secret
SQLALCHEMY_ECHO = False

# MIGRATION (PM RIMS 0001): AUTHLIB provider lama DIMATIKAN (dict kosong).
AUTHLIB_OAUTH_CLIENTS = {}
