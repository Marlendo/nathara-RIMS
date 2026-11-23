"""SSO Supabase Production provider (backend-only).

Menggantikan AuthenticationGateway + provider OAuth lama yang dimatikan
(PM RIMS 0001). Validasi JWT RS256 prod via JWKS + cache in-memory TTL
10 menit (hanya JWKS yang di-cache, BUKAN decision user). Menolak alg
``none``/HS256. ``iss``/``aud`` dicocokkan exact, toleransi clock skew
+/-60 detik.

TODO-SSOT-VERIFY: nilai default iss/aud/JWKS di bawah adalah SSOT Prod FINAL
(PM RIMS 0002, diterima 2026-11-23): JWKS=https://api.nathara.ac.id/functions/v1/sso-jwks
(kid=sso-prod-2026-11), iss=https://sso.nathara.ac.id, aud=lppm (exact).
Klaim otorisasi TOP-LEVEL ``role`` + ``scopes`` (bukan app_metadata /
user_metadata). user_metadata HANYA untuk nama tampilan, TIDAK PERNAH untuk
otorisasi (H-01). Klaim top-level ``role`` postgres lama (``"authenticated"``)
TIDAK DIBACA untuk otorisasi (H-02) — IdP SSOT menerbitkan peran aplikasi di
top-level ``role`` + ``scopes``.
JANGAN hardcode secret di sini; hanya JWKS URL publik + anon/publishable
key (public). service_role + keypair lama HARAM.
"""

import time

import requests
from authlib.jose import JsonWebToken
from authlib.jose.errors import JoseError
from flask import current_app
from loguru import logger

from ops_api.ops.auth.exceptions import AuthenticationError

# SSOT Prod FINAL (PM RIMS 0002). Boleh override via env
# (SUPABASE_JWKS_URL/SUPABASE_ISS/SUPABASE_AUD) untuk staging/test.
DEFAULT_JWKS_URL = "https://api.nathara.ac.id/functions/v1/sso-jwks"
DEFAULT_ISS = "https://sso.nathara.ac.id"
DEFAULT_AUD = "lppm"

_JWKS_CACHE_TTL_SECONDS = 600  # 10 menit (usul SA-RIMS 0001)
_CLOCK_SKEW_SECONDS = 60  # +/-60 detik untuk exp/nbf/iat

_jwks_cache: dict = {"keys": None, "fetched_at": 0.0}


def get_supabase_jwks() -> dict:
    """Ambil JWKS prod dengan cache in-memory TTL 10 menit."""
    now = time.time()
    if _jwks_cache["keys"] is not None and (now - _jwks_cache["fetched_at"]) < _JWKS_CACHE_TTL_SECONDS:
        return {"keys": _jwks_cache["keys"]}
    jwks_url = current_app.config.get("SUPABASE_JWKS_URL", DEFAULT_JWKS_URL)
    try:
        resp = requests.get(jwks_url, headers={"Accept": "application/json"}, timeout=10)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        logger.error(f"SSO: gagal fetch JWKS prod {jwks_url}: {e}")
        if _jwks_cache["keys"] is not None:
            logger.warning("SSO: pakai JWKS cache basi karena fetch gagal")
            return {"keys": _jwks_cache["keys"]}
        raise AuthenticationError("SSO IdP tidak tersedia, coba lagi.")
    keys = data.get("keys", [])
    _jwks_cache["keys"] = keys
    _jwks_cache["fetched_at"] = now
    logger.info("SSO: JWKS prod di-refresh (cache miss/expired)")
    return {"keys": keys}


def _get_expected_iss_aud() -> tuple[str, str]:
    iss = current_app.config.get("SUPABASE_ISS", DEFAULT_ISS)
    aud = current_app.config.get("SUPABASE_AUD", DEFAULT_AUD)
    return iss, aud


def verify_supabase_jwt(token: str) -> dict:
    """Validasi JWT Supabase prod. Return claims dict bila valid.

    Raises AuthenticationError bila tidak valid (401 di API layer).
    """
    if not token:
        raise AuthenticationError("Token SSO tidak ada.")
    header_claims = None
    try:
        jwt = JsonWebToken(["RS256"])  # tolak none/HS256 dari IdP
        jwks = get_supabase_jwks()
        claims = jwt.decode(token, jwks)
    except (JoseError, ValueError, Exception) as e:
        logger.warning(f"SSO: JWT tidak valid: {e}")
        raise AuthenticationError("Token SSO tidak valid.")
    header_claims = claims
    now = int(time.time())
    expected_iss, expected_aud = _get_expected_iss_aud()

    iss = claims.get("iss")
    if iss != expected_iss:
        logger.warning(f"SSO: iss mismatch got={iss}")
        raise AuthenticationError("Token SSO issuer tidak dikenal.")

    aud = claims.get("aud")
    aud_ok = aud == expected_aud or (
        isinstance(aud, list) and expected_aud in aud
    )
    if not aud_ok:
        logger.warning("SSO: aud mismatch")
        raise AuthenticationError("Token SSO audience tidak dikenal.")

    exp = claims.get("exp")
    if exp is None or int(exp) + _CLOCK_SKEW_SECONDS < now:
        raise AuthenticationError("Sesi SSO kedaluwarsa, silakan login ulang.")
    nbf = claims.get("nbf")
    if nbf is not None and int(nbf) - _CLOCK_SKEW_SECONDS > now:
        raise AuthenticationError("Token SSO belum berlaku.")
    # L-03: tolak token yang diterbitkan jauh di masa depan (pra-diterbitkan).
    iat = claims.get("iat")
    if iat is not None and int(iat) - _CLOCK_SKEW_SECONDS > now:
        logger.warning("SSO: iat di masa depan")
        raise AuthenticationError("Token SSO belum berlaku.")
    return dict(header_claims)


def _as_scope_list(raw) -> list:
    """Normalisasi klaim scopes SSOT ke list string.

    SSOT: ``scopes`` top-level (list, mis. ["RIMS"]). Toleransi bentuk
    ekuivalen: string tunggal di ``scopes``/``scope`` (TODO-SSOT-VERIFY —
    verifikasi bentuk final saat token prod asli tersedia).
    """
    if raw is None:
        return []
    if isinstance(raw, (list, tuple)):
        return [str(s) for s in raw]
    if isinstance(raw, str):
        return [raw]
    return []


def extract_sso_identity(claims: dict) -> dict:
    """Petakan klaim SSOT prod -> identitas internal + guard admin/RIMS.

    SSOT Prod (PM RIMS 0002): otorisasi dibaca HANYA dari klaim TOP-LEVEL
    ``role`` + ``scopes`` (exact). ``app_metadata``/``user_metadata``/klaim
    top-level generik lain TIDAK dibaca untuk role/scope (H-01/H-02) —
    ``user_metadata`` hanya dipakai untuk nama tampilan (display name),
    TIDAK PERNAH untuk keputusan otorisasi. Guard kanonis tetap
    ``role == 'admin' AND 'RIMS' in scopes`` (exact, default deny 403).
    """

    role = claims.get("role")
    raw_scopes = claims.get("scopes")
    if raw_scopes is None:
        # Toleransi bentuk singular ekuivalen (TODO-SSOT-VERIFY).
        raw_scopes = claims.get("scope")
    scopes = _as_scope_list(raw_scopes)
    scope = scopes[0] if scopes else None
    sub = claims.get("sub")
    email = claims.get("email")
    # Nama tampilan: klaim top-level dulu, lalu user_metadata (display-only).
    user_meta = claims.get("user_metadata") or {}
    given = claims.get("given_name") or user_meta.get("given_name") or user_meta.get("full_name")
    family = claims.get("family_name") or user_meta.get("family_name")
    if given and family:
        nama = f"{given} {family}".strip()
    elif given:
        nama = str(given)
    elif email:
        nama = str(email).split("@")[0]
    elif sub:
        nama = str(sub)[:8]
    else:
        nama = "Pengguna SSO"
    return {
        "sub": sub,
        "email": email,
        "nama": nama,
        "given_name": given,
        "family_name": family,
        "role": role,
        "scope": scope,
        "scopes": scopes,
    }


def is_rims_admin(identity: dict) -> bool:
    """Guard kanonis SSOT: role == 'admin' AND 'RIMS' in scopes (exact)."""
    if identity.get("role") != "admin":
        return False
    scopes = identity.get("scopes")
    if scopes is None:
        single = identity.get("scope")
        scopes = [single] if single else []
    return "RIMS" in [str(s) for s in scopes]
