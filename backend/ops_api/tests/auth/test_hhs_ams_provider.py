"""MIGRATION (PM RIMS 0001): test provider HHS AMS lama diganti test SSO Supabase prod.

Unit test murni (tanpa DB): verifikasi RS256 via JWKS mock + cache,
guard kanonis role == 'admin' AND scope == 'RIMS', dan penolakan
none/HS256, iss/aud salah, serta token kedaluwarsa.
"""

import time
import uuid

import pytest
from authlib.jose import jwt as jose_jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from ops_api.ops.auth import supabase_sso_provider as sso
from ops_api.ops.auth.exceptions import AuthenticationError


def _make_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_numbers = private_key.public_key().public_numbers()
    # bangun JWK RSA minimal untuk JWKS mock
    import base64

    def b64u(n: int) -> str:
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    jwk = {
        "kty": "RSA",
        "kid": "test-key",
        "use": "sig",
        "alg": "RS256",
        "n": b64u(public_numbers.n),
        "e": b64u(public_numbers.e),
    }
    return private_key, jwk


def _sign(private_key, payload, alg="RS256", kid="test-key"):
    return jose_jwt.encode(header={"alg": alg, "kid": kid}, payload=payload, key=private_key)


@pytest.fixture()
def sso_setup():
    """Flask app minimal lokal (tanpa DB/harness docker) untuk unit test SSO."""
    from flask import Flask

    app = Flask(__name__)
    app.config["SUPABASE_JWKS_URL"] = "https://test.invalid/jwks.json"
    app.config["SUPABASE_ISS"] = "https://test.invalid/auth/v1"
    app.config["SUPABASE_AUD"] = "authenticated"
    ctx = app.app_context()
    ctx.push()
    private_key, jwk = _make_keypair()
    sso._jwks_cache["keys"] = [jwk]
    sso._jwks_cache["fetched_at"] = time.time()
    yield private_key, jwk
    sso._jwks_cache["keys"] = None
    sso._jwks_cache["fetched_at"] = 0.0
    ctx.pop()


def _claims(**over):
    now = int(time.time())
    base = {
        "iss": "https://test.invalid/auth/v1",
        "aud": "authenticated",
        "sub": str(uuid.uuid4()),
        "email": "admin.rims@example.com",
        "exp": now + 600,
        "iat": now,
        "role": "admin",
        "scope": "RIMS",
    }
    base.update(over)
    return base


def test_verify_ok_and_guard_admin_rims(sso_setup):
    private_key, _ = sso_setup
    token = _sign(private_key, _claims())
    claims = sso.verify_supabase_jwt(token)
    assert claims["email"] == "admin.rims@example.com"
    identity = sso.extract_sso_identity(claims)
    assert sso.is_rims_admin(identity) is True


def test_guard_matrix_denies_non_admin_rims(sso_setup):
    private_key, _ = sso_setup
    cases = [
        ({"role": "user", "scope": "RIMS"}, False),
        ({"role": "admin", "scope": "OTHER"}, False),
        ({"role": "admin", "scope": None}, False),
        ({"role": None, "scope": "RIMS"}, False),
        ("__pop_role_scope__", False),
    ]
    for patch, expected in cases:
        claims = _claims()
        if patch == "__pop_role_scope__":
            claims.pop("role", None)
            claims.pop("scope", None)
        else:
            claims.update(patch)
        token = _sign(private_key, claims)
        verified = sso.verify_supabase_jwt(token)
        identity = sso.extract_sso_identity(verified)
        assert sso.is_rims_admin(identity) is expected, patch


def test_reject_wrong_iss(sso_setup):
    private_key, _ = sso_setup
    token = _sign(private_key, _claims(iss="https://evil.invalid/"))
    with pytest.raises(AuthenticationError):
        sso.verify_supabase_jwt(token)


def test_reject_wrong_aud(sso_setup):
    private_key, _ = sso_setup
    token = _sign(private_key, _claims(aud="someone-else"))
    with pytest.raises(AuthenticationError):
        sso.verify_supabase_jwt(token)


def test_reject_expired(sso_setup):
    private_key, _ = sso_setup
    token = _sign(private_key, _claims(exp=int(time.time()) - 3600))
    with pytest.raises(AuthenticationError):
        sso.verify_supabase_jwt(token)


def test_reject_hs256(sso_setup):
    _private_key, _ = sso_setup
    # HS256 dengan shared secret (bukan RSA): provider hanya terima RS256.
    token = _sign("shared-secret-bukan-rsa", _claims(), alg="HS256")
    with pytest.raises(AuthenticationError):
        sso.verify_supabase_jwt(token)


def test_reject_empty_token(sso_setup):
    with pytest.raises(AuthenticationError):
        sso.verify_supabase_jwt("")


def test_name_fallbacks():
    assert sso.extract_sso_identity({"sub": "abc123", "email": "Aa@x.id", "role": "admin", "scope": "RIMS"})["nama"] == "Aa"
    assert (
        sso.extract_sso_identity({"sub": "abcdef123456", "role": "admin", "scope": "RIMS"})["nama"]
        == "abcdef12"
    )
