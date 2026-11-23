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
    app.config["SUPABASE_JWKS_URL"] = "https://test.invalid/functions/v1/sso-jwks"
    app.config["SUPABASE_ISS"] = "https://sso.test.invalid"
    app.config["SUPABASE_AUD"] = "lppm"
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
    # SSOT Prod (PM RIMS 0002): iss=https://sso.nathara.ac.id, aud=lppm,
    # klaim otorisasi top-level role + scopes. Di sini pakai host test.
    now = int(time.time())
    base = {
        "iss": "https://sso.test.invalid",
        "aud": "lppm",
        "sub": str(uuid.uuid4()),
        "email": "admin.rims@example.com",
        "exp": now + 600,
        "iat": now,
        "role": "admin",
        "scopes": ["RIMS"],
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
    # Matriks 403 SSOT (PM RIMS 0002), 6 kasus: hanya admin+RIMS yang lolos.
    private_key, _ = sso_setup
    cases = [
        ({"role": "admin", "scopes": ["RIMS"]}, True),  # 1. admin + RIMS -> OK
        ({"role": "user", "scopes": ["RIMS"]}, False),  # 2. non-admin + RIMS -> 403
        ({"role": "admin", "scopes": ["OTHER"]}, False),  # 3. admin + scope lain -> 403
        ({"role": "admin", "scopes": []}, False),  # 4. admin tanpa scope -> 403
        ({"role": "authenticated", "scopes": ["RIMS"]}, False),  # 5. postgres-role lama -> 403
        ("__pop_role_scopes__", False),  # 6. tanpa klaim SSOT -> 403
    ]
    for patch, expected in cases:
        claims = _claims()
        if patch == "__pop_role_scopes__":
            claims.pop("role", None)
            claims.pop("scopes", None)
            claims.pop("scope", None)
        else:
            claims.pop("scope", None)
            claims.update(patch)
        token = _sign(private_key, claims)
        verified = sso.verify_supabase_jwt(token)
        identity = sso.extract_sso_identity(verified)
        assert sso.is_rims_admin(identity) is expected, patch


def test_user_metadata_role_admin_is_denied(sso_setup):
    # H-01 anti-privesc: user_metadata.role=admin TANPA klaim SSOT -> 403.
    private_key, _ = sso_setup
    claims = _claims()
    claims.pop("role", None)
    claims.pop("scopes", None)
    claims.pop("scope", None)
    claims["user_metadata"] = {"role": "admin", "scope": "RIMS"}
    token = _sign(private_key, claims)
    verified = sso.verify_supabase_jwt(token)
    identity = sso.extract_sso_identity(verified)
    assert sso.is_rims_admin(identity) is False


def test_app_metadata_role_admin_is_denied(sso_setup):
    # H-01: app_metadata BUKAN sumber otorisasi SSOT -> 403.
    private_key, _ = sso_setup
    claims = _claims()
    claims.pop("role", None)
    claims.pop("scopes", None)
    claims.pop("scope", None)
    claims["app_metadata"] = {"role": "admin", "scope": "RIMS"}
    token = _sign(private_key, claims)
    verified = sso.verify_supabase_jwt(token)
    identity = sso.extract_sso_identity(verified)
    assert sso.is_rims_admin(identity) is False


def test_singular_scope_tolerated(sso_setup):
    # Toleransi bentuk singular ekuivalen (TODO-SSOT-VERIFY): tetap hijau.
    private_key, _ = sso_setup
    claims = _claims()
    claims.pop("scopes", None)
    claims["scope"] = "RIMS"
    token = _sign(private_key, claims)
    identity = sso.extract_sso_identity(sso.verify_supabase_jwt(token))
    assert sso.is_rims_admin(identity) is True


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


def test_reject_iat_far_future(sso_setup):
    private_key, _ = sso_setup
    token = _sign(private_key, _claims(iat=int(time.time()) + 3600))
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
