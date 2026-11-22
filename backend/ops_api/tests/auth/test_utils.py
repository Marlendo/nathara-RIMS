"""MIGRATION (PM RIMS 0001): create_oauth_jwt/keypair lama DIMATIKAN."""

import time
import uuid
from uuid import UUID

import pytest
from authlib.jose import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import current_app
from flask_jwt_extended import create_access_token
from sqlalchemy import select

from models.users import User
from ops_api.ops.auth.authorization_providers import AuthorizationGateway
from ops_api.ops.auth.exceptions import PrivateKeyError
from ops_api.ops.auth.utils import create_oauth_jwt, get_user, is_token_expired

key = rsa.generate_private_key(backend=default_backend(), public_exponent=65537, key_size=2048)


def test_get_jwt_no_key(app):
    # keypair lama DIMATIKAN: create_oauth_jwt selalu raise PrivateKeyError.
    with app.test_request_context("/auth/sso/callback", method="POST", data={"supabase_jwt": "x"}):
        with pytest.raises(PrivateKeyError):
            create_oauth_jwt(
                "nathara-sso",
                app.config,
                key=key,
                header={"alg": "RS256"},
                payload={
                    "sub": "1234567890",
                    "name": "John Doe",
                    "admin": "true",
                    "iat": 1516239022,
                },
            )


def test_is_token_expired_without_secret_key():
    # Expiry dibaca dari klaim tanpa secret (pemanggil wajib validasi
    # tanda tangan via verify_supabase_jwt terlebih dulu).
    import base64
    import json as _json

    def _unsigned(payload: dict) -> str:
        body = base64.urlsafe_b64encode(_json.dumps(payload).encode()).rstrip(b"=").decode()
        return f"header.{body}.sig"

    assert is_token_expired(_unsigned({"exp": int(time.time()) - 10})) is True
    assert is_token_expired(_unsigned({"exp": int(time.time()) + 600})) is False
    assert is_token_expired("not-a-jwt") is True


def test_authorization_gateway_authorize_successful(mocker, app_ctx):
    class MockAuthorizationProvider:
        def is_authorized(self, user_id: str, permission: list[str]):
            return True

    mock_basic_provider = MockAuthorizationProvider()
    mocker.patch.object(mock_basic_provider, "is_authorized")
    authorization_gateway = AuthorizationGateway(mock_basic_provider)
    result = authorization_gateway.authorize("1234-5432-1234", ["can_read", "portfolio_read"])
    assert result is True


@pytest.fixture()
def user_with_no_oidc_id(loaded_db):
    user = User(
        oidc_id=None,
        email="user@example.com",
        first_name="User",
        last_name="Example",
    )
    loaded_db.add(user)
    loaded_db.commit()
    yield user

    loaded_db.delete(user)
    loaded_db.commit()


@pytest.fixture()
def sso_user_info():
    yield {
        "sub": "6b3f72cb-0c04-4eff-94b3-fa012f63a9c6",
        "aud": "1aba44a4-4fd3-4d8b-a4bc-d8afecc6abb7",
        "email_verified": True,
        "hhsid": "9765836011",
        "IAL": 3,
        "name": "JOHN DOE",
        "iss": "https://sso-stage.acf.hhs.gov/auth/realms/ACF-SSO",
        "preferred_username": "john.doe@acf.hhs.gov",
        "AAL": 3,
        "given_name": "JOHN",
        "family_name": "DOE",
        "email": "john.doe@acf.hhs.gov",
    }


def test_get_user(user_with_no_oidc_id, loaded_db):
    # test happy path
    user = get_user(
        {
            "email": "admin.demo@email.com",
            "sub": "00000000-0000-1111-a111-000000000018",
            "given_name": "Admin",
        },
        loaded_db,
    )
    assert user is not None
    assert user.email == "admin.demo@email.com"

    # test user with no oidc_id
    stmt = select(User).where(User.email == "user@example.com")  # type: ignore
    user = loaded_db.scalars(stmt).one_or_none()
    assert user is not None
    assert user.oidc_id is None

    user = get_user(
        {
            "email": "user@example.com",
            "sub": "9b5b5b5e-5288-401d-8267-a80605cce16f",
            "given_name": "Admin",
        },
        loaded_db,
    )
    assert user is not None
    assert user.email == "user@example.com"
    stmt = select(User).where(User.email == "user@example.com")  # type: ignore
    user = loaded_db.scalars(stmt).one_or_none()
    assert user is not None
    assert user.oidc_id == UUID("9b5b5b5e-5288-401d-8267-a80605cce16f")


def test_get_user_info_set(loaded_db, sso_user_info):
    user = User(oidc_id=UUID(sso_user_info["sub"]), email="replace me")
    loaded_db.add(user)
    loaded_db.commit()

    user = get_user(sso_user_info, loaded_db)
    assert user is not None
    assert user.oidc_id == UUID(sso_user_info["sub"])
    assert user.email == sso_user_info["email"]
    assert user.first_name == sso_user_info["given_name"]
    assert user.last_name == sso_user_info["family_name"]
    assert user.hhs_id == sso_user_info["hhsid"]

    # cleanup
    loaded_db.delete(user)
    loaded_db.commit()
