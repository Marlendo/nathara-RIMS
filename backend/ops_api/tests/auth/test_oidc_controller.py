"""MIGRATION (PM RIMS 0001): test controller login lama diganti test SSO.

- POST /auth/login/ (provider/code) DIMATIKAN -> 410.
- Login baru: POST /auth/sso/callback {supabase_jwt} -> sesi app;
  GET /auth/sso/session -> info sesi.
"""

import pytest
from sqlalchemy import text

from models.events import OpsEventStatus, OpsEventType
from ops_api.ops.auth.exceptions import PrivateKeyError, UserInactiveError, UserLockedError


def test_auth_login_deprecated_returns_410(client):
    res = client.post("/auth/login/", json={"provider": "whatever", "code": "x"})
    assert res.status_code == 410
    assert "sso/callback" in res.json["message"]


def test_create_oauth_jwt_disabled_raises(app, app_ctx):
    from ops_api.ops.auth.utils import create_oauth_jwt

    with pytest.raises(PrivateKeyError):
        create_oauth_jwt("whatever", app.config)


def test_sso_callback_rejects_empty_payload(client):
    res = client.post("/auth/sso/callback", json={})
    assert res.status_code == 400


def test_sso_callback_rejects_invalid_token(client, mocker):
    mocker.patch(
        "ops_api.ops.auth.service.verify_supabase_jwt",
        side_effect=PrivateKeyError("nope"),
    )
    res = client.post("/auth/sso/callback", json={"supabase_jwt": "bad"})
    assert res.status_code in (400, 401, 500)


def test_sso_callback_denies_non_admin_rims(client, loaded_db, mocker):
    mocker.patch(
        "ops_api.ops.auth.service.verify_supabase_jwt",
        return_value={
            "iss": "https://sso.nathara.ac.id",
            "aud": "lppm",
            "sub": "11111111-1111-1111-1111-111111111111",
            "email": "user.demo@email.com",
            "exp": 4102444800,
            "role": "user",
            "scope": "RIMS",
        },
    )
    res = client.post("/auth/sso/callback", json={"supabase_jwt": "dummy"})
    assert res.status_code == 403


def test_sso_callback_succeeds_creates_event(client, loaded_db, mocker, test_non_admin_user):
    mock_cm = mocker.patch("ops_api.ops.utils.events.Session")
    mock_session = mocker.MagicMock()
    mock_cm.return_value.__enter__.return_value = mock_session

    mocker.patch(
        "ops_api.ops.auth.service.verify_supabase_jwt",
        return_value={
            "iss": "https://sso.nathara.ac.id",
            "aud": "lppm",
            "sub": "22222222-2222-2222-2222-222222222222",
            "email": test_non_admin_user.email,
            "given_name": "Test",
            "family_name": "User",
            "exp": 4102444800,
            "role": "admin",
            "scopes": ["RIMS"],
            "scope": "RIMS",
        },
    )

    res = client.post("/auth/sso/callback", json={"supabase_jwt": "dummy"})
    assert res.status_code == 200
    assert res.json["access_token"]
    assert res.json["refresh_token"]

    event = mock_session.add.call_args[0][0]
    assert event.event_type == OpsEventType.LOGIN_ATTEMPT
    assert event.event_status == OpsEventStatus.SUCCESS

    # cleanup
    loaded_db.execute(text("DELETE FROM user_session"))
    loaded_db.commit()


def test_sso_callback_fails_with_inactive_user(client, loaded_db, mocker):
    m1 = mocker.patch("ops_api.ops.auth.service.login_sso")
    m1.side_effect = UserInactiveError("inactive")

    res = client.post("/auth/sso/callback", json={"supabase_jwt": "dummy"})
    assert res.status_code == 401
    assert res.json["error_type"] == "USER_INACTIVE"


def test_sso_callback_fails_with_locked_user(client, loaded_db, mocker):
    m1 = mocker.patch("ops_api.ops.auth.service.login_sso")
    m1.side_effect = UserLockedError("locked")

    res = client.post("/auth/sso/callback", json={"supabase_jwt": "dummy"})
    assert res.status_code == 401
    assert res.json["error_type"] == "USER_LOCKED"
