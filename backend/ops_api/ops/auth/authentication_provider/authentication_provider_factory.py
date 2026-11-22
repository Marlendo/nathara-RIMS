"""MIGRATION (PM RIMS 0001): factory provider lama DIMATIKAN.

Hanya SSO Supabase prod yang didukung. Lihat supabase_sso_provider.
"""

from ops_api.ops.auth.exceptions import AuthenticationError


class AuthenticationProviderFactory:
    @staticmethod
    def create_provider(provider_name: str, config=None):
        raise AuthenticationError(
            "Provider login lama dimatikan (PM RIMS 0001). Gunakan SSO Nathara."
        )
