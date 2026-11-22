"""MIGRATION (PM RIMS 0001): provider login dev tanpa kredensial DIMATIKAN.

FakeAuth DILARANG tersisa/lolos ke staging. Stub fail-closed.
"""

from ops_api.ops.auth.authentication_provider.authentication_provider import (
    AuthenticationProvider,
)
from ops_api.ops.auth.exceptions import AuthenticationError


class FakeAuthProvider(AuthenticationProvider):
    def __init__(self, provider_name: str, config=None) -> None:
        raise AuthenticationError("FakeAuth dimatikan (PM RIMS 0001). Dilarang di staging.")

    def authenticate(self, auth_code):
        raise AuthenticationError("FakeAuth dimatikan (PM RIMS 0001).")

    def get_user_info(self, token):
        raise AuthenticationError("FakeAuth dimatikan (PM RIMS 0001).")

    def validate_token(self, token):
        raise AuthenticationError("FakeAuth dimatikan (PM RIMS 0001).")
