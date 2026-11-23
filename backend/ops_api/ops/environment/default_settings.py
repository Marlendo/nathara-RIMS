import os
from datetime import timedelta

DEBUG = False  # make sure DEBUG is off unless enabled explicitly otherwise

SQLALCHEMY_TRACK_MODIFICATIONS = False
SQLALCHEMY_ECHO = False

# SQLAlchemy Connection Pool Settings
# Defaults are conservative for production; override in local/dev configs for E2E testing
SQLALCHEMY_POOL_SIZE = 10  # Number of connections to keep open (default 5)
SQLALCHEMY_MAX_OVERFLOW = 10  # Additional connections when pool exhausted (default 10)
SQLALCHEMY_POOL_TIMEOUT = 30  # Seconds to wait for connection (default 30)
SQLALCHEMY_POOL_RECYCLE = 3600  # Recycle connections after 1 hour
SQLALCHEMY_POOL_PRE_PING = True  # Test connections before use

FLASK_PORT = 8080

# MIGRATION (PM RIMS 0001): keypair JWT lama DIMATIKAN. JANGAN isi nilai.
# Verifikasi diganti JWKS Supabase prod (publik, read-only).
JWT_PRIVATE_KEY = None  # DIMATIKAN (PM RIMS 0001)
JWT_PUBLIC_KEY = None  # DIMATIKAN (PM RIMS 0001)
# Sesi aplikasi internal memakai HS256 simetris dengan secret server-side
# (BUKAN keypair lama, BUKAN service_role). WAJIB diisi via env di staging/prod;
# nilai di bawah HANYA fallback dev/test lokal.
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "dev-only-insecure-secret-ganti-di-staging")  # noqa: S105
JWT_ALGORITHM = "HS256"
JWT_DECODE_ALGORITHMS = "HS256"
JWT_TOKEN_LOCATION = "headers"  # noqa: S105 "Not a secret"
JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=30)  # FedRAMP AC-12 Control is 30 min
JWT_REFRESH_TOKEN_EXPIRES = timedelta(hours=12)

# OPS-API JWT
JWT_ENCODE_ISSUER = "https://opre-ops-backend-dev"
JWT_ENCODE_AUDIENCE = "https://opre-ops-frontend-dev"

# OPS-FRONTEND
OPS_FRONTEND_URL = os.getenv("OPS_FRONTEND_URL", "http://localhost:3000")

# MIGRATION (PM RIMS 0001): AUTHLIB provider lama DIMATIKAN (dict kosong).
# SSO Supabase prod via SUPABASE_* di bawah (hanya nilai publik).
AUTHLIB_OAUTH_CLIENTS = {}

# SSO Supabase PROD (hanya nilai publik; service_role + keypair lama HARAM).
# SSOT Prod FINAL (PM RIMS 0002, 2026-11-23): JWKS functions/v1/sso-jwks
# (kid=sso-prod-2026-11), iss=https://sso.nathara.ac.id, aud=lppm.
SUPABASE_JWKS_URL = os.getenv(
    "SUPABASE_JWKS_URL", "https://api.nathara.ac.id/functions/v1/sso-jwks"
)
SUPABASE_ISS = os.getenv("SUPABASE_ISS", "https://sso.nathara.ac.id")
SUPABASE_AUD = os.getenv("SUPABASE_AUD", "lppm")
SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY", "")  # publishable/anon key (public)

STORAGE_ACCOUNT_NAME = "timstoragetesting"
STORAGE_ACCOUNT_KEY = os.getenv("AZURE_STORAGE_ACCOUNT_KEY")

JSONIFY_PRETTYPRINT_REGULAR = True

# User Session Variables
USER_SESSION_EXPIRATION = timedelta(minutes=28)  # See ADR 29

# MIGRATION (PM RIMS 0001): FakeAuth DIMATIKAN — daftar kosong.
FAKE_USER_OIDC_IDS = []

DOCUMENT_PROVIDERS = {
    "fake",
    "azure",
}

# Azure log truncation (Container App / Log Analytics Log field limit 32766 bytes)
# Only applied when OPS_CONFIG contains "environment/azure" (e.g. Azure deployment).
AZURE_LOG_FIELD_MAX_BYTES = 32766
AZURE_BODY_LOG_MAX_BYTES = 20000

# True when OPS_CONFIG points at Azure environment config; enables log truncation.
RUNNING_IN_AZURE = "environment/azure" in (os.getenv("OPS_CONFIG") or "")

# When True, Draft→Planned status changes and in-Planned budget-detail edits apply
# immediately instead of creating a Change Request for Division Director review.
# Set per-environment via the SKIP_CR_FOR_DRAFT_PLANNED env var (no code change to flip).
# Default OFF everywhere so behavior is unchanged unless explicitly enabled.
SKIP_CR_FOR_DRAFT_PLANNED = os.getenv("SKIP_CR_FOR_DRAFT_PLANNED", "false").lower() == "true"

# When True, approved budget line change requests on an Awarded agreement are recorded as
# "Edits That Require a Contract Modification" and listed on the Award & Modifications tab
# (OPS-3072, Modified LOE contract mod, slice 1). Set per-environment via the
# ENABLE_MODIFIED_LOE_EDITS env var. Default OFF everywhere so behavior is unchanged unless
# explicitly enabled.
ENABLE_MODIFIED_LOE_EDITS = os.getenv("ENABLE_MODIFIED_LOE_EDITS", "false").lower() == "true"

# When True, a non-Draft budget line's Obligate By date (date_needed) may be today or in the
# past for every user (issue 6443). The missing-date and within-Period-of-Performance rules still
# apply. Default OFF. The ALLOW_PAST_OBLIGATE_BY_DATES env var sets it for local runs. Deployed
# environments hard-code True in environment/azure/*.py; to turn it off there without a code change,
# set FLASK_ALLOW_PAST_OBLIGATE_BY_DATES=false (lowercase false, or 0) on the backend container app
# and restart it. from_prefixed_env parses the value as JSON, so "False" or "no" stays a truthy
# string and leaves the feature on.
ALLOW_PAST_OBLIGATE_BY_DATES = os.getenv("ALLOW_PAST_OBLIGATE_BY_DATES", "false").lower() == "true"

# CSRF Protection
# This is the prefix for the Host header in the cloud environment.
HOST_HEADER_PREFIX = "localhost"

# Whether /api/v1/health/ checks the HHS AMS OAuth server.
HEALTH_CHECK_AUTH_SERVICES = True

SUPER_USER = "SUPER_USER"
