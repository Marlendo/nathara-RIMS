"""H-03 (PM RIMS 0002): material token TIDAK BOLEH masuk DB event/log."""

from ops_api.ops.utils.events import (
    REDACTED_VALUE,
    redact_event_metadata,
    token_fingerprint,
)


def test_redact_event_metadata_headers_and_body():
    meta = redact_event_metadata(
        {
            "Authorization": "Bearer abc.def.ghi",
            "Cookie": "session=xyz",
            "Content-Type": "application/json",
            "nested": {"supabase_jwt": "JWT-MENTAH", "access_token": "T", "refresh_token": "R"},
            "code": "auth-code-123",
            "password": "rahasia",
            "scopes": ["RIMS"],
            "role": "admin",
        }
    )
    assert meta["Authorization"] == REDACTED_VALUE
    assert meta["Cookie"] == REDACTED_VALUE
    assert meta["Content-Type"] == "application/json"
    assert meta["nested"]["supabase_jwt"] == REDACTED_VALUE
    assert meta["nested"]["access_token"] == REDACTED_VALUE
    assert meta["nested"]["refresh_token"] == REDACTED_VALUE
    assert meta["code"] == REDACTED_VALUE
    assert meta["password"] == REDACTED_VALUE
    # klaim otorisasi non-token tetap terbaca audit
    assert meta["scopes"] == ["RIMS"]
    assert meta["role"] == "admin"


def test_redact_header_case_insensitive():
    meta = redact_event_metadata({"authorization": "Bearer x", "AUTHORIZATION": "Bearer y"})
    assert meta["authorization"] == REDACTED_VALUE
    assert meta["AUTHORIZATION"] == REDACTED_VALUE


def test_token_fingerprint_is_stable_and_non_reversible():
    fp = token_fingerprint("access-token-mentah-contoh")
    assert fp is not None and len(fp) == 8
    assert fp == token_fingerprint("access-token-mentah-contoh")
    assert "access-token-mentah-contoh" not in fp
    assert token_fingerprint(None) is None
    assert token_fingerprint("") is None
