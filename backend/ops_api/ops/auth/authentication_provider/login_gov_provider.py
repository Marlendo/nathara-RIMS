"""MIGRATION (PM RIMS 0001): provider login.gov DIMATIKAN. Pakai SSO Supabase prod."""

from ops_api.ops.auth.authentication_provider.authentication_provider import (
    AuthenticationProvider,
)
from ops_api.ops.auth.exceptions import AuthenticationError


class LoginGovProvider(AuthenticationProvider):
    def __init__(self, provider_name: str, config=None) -> None:
        raise AuthenticationError("Login lama dimatikan (PM RIMS 0001). Gunakan SSO Nathara.")

    def authenticate(self, auth_code):
        raise AuthenticationError("Login lama dimatikan (PM RIMS 0001).")

    def get_user_info(self, token):
        raise AuthenticationError("Login lama dimatikan (PM RIMS 0001).")

    def validate_token(self, token):
        raise AuthenticationError("Login lama dimatikan (PM RIMS 0001).")
