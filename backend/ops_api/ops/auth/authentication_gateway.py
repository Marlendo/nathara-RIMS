"""MIGRATION (PM RIMS 0001): AuthenticationGateway DIMATIKAN.

Legacy OAuth gateway (3 legacy providers via factory) diganti adapter SSO
Supabase prod: ops_api.ops.auth.supabase_sso_provider (validasi RS256 via
JWKS + cache). File ini dipertahankan sebagai stub agar import lama gagal
secara eksplisit (fail-closed), bukan diam-diam lolos.
"""

from ops_api.ops.auth.exceptions import AuthenticationError


class AuthenticationGateway:
    """Stub mati — JANGAN dipakai. Pakai supabase_sso_provider."""

    def __init__(self, config=None) -> None:
        raise AuthenticationError(
            "Login lama dimatikan (PM RIMS 0001). Gunakan SSO Nathara via /auth/sso/callback."
        )

    def authenticate(self, provider_name, auth_code):
        raise AuthenticationError("Login lama dimatikan (PM RIMS 0001).")

    def get_user_info(self, provider: str, token: str):
        raise AuthenticationError("Login lama dimatikan (PM RIMS 0001).")

    def validate_token(self, provider: str, token: str):
        raise AuthenticationError("Login lama dimatikan (PM RIMS 0001).")
