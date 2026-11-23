import asyncio
from unittest.mock import patch

import pytest
from flask import Flask

from ops_api.ops.utils.health_check import check_auth_services


@pytest.fixture()
def auth_check_app():
    app = Flask(__name__)
    app.config["SUPABASE_JWKS_URL"] = "https://sso.example.com/functions/v1/sso-jwks"
    with app.app_context():
        yield app


def test_check_auth_services_skipped_when_disabled(auth_check_app):
    """With the check off they report healthy without calling out."""
    auth_check_app.config["HEALTH_CHECK_AUTH_SERVICES"] = False

    with patch(
        "ops_api.ops.utils.health_check.get_supabase_jwks"
    ) as mock_jwks, patch("requests.get") as mock_get:
        resp = asyncio.run(check_auth_services())

    assert resp == {"status_code": None, "alarm_level": 0}
    mock_jwks.assert_not_called()
    mock_get.assert_not_called()


@pytest.mark.parametrize(
    "keys, status_code, alarm_level",
    [([{"kid": "sso-prod-2026-11"}], 200, 0), ([], 503, 1)],
)
def test_check_auth_services_uses_cached_jwks(auth_check_app, keys, status_code, alarm_level):
    """M-01: health-check lewat get_supabase_jwks() (cache TTL), bukan fetch langsung."""
    auth_check_app.config["HEALTH_CHECK_AUTH_SERVICES"] = True

    with patch(
        "ops_api.ops.utils.health_check.get_supabase_jwks",
        return_value={"keys": keys},
    ) as mock_jwks, patch("requests.get") as mock_get:
        resp = asyncio.run(check_auth_services())

    mock_jwks.assert_called_once_with()
    mock_get.assert_not_called()
    assert resp == {"status_code": status_code, "alarm_level": alarm_level}


def test_check_auth_services_alarm_on_jwks_error(auth_check_app):
    auth_check_app.config["HEALTH_CHECK_AUTH_SERVICES"] = True

    with patch(
        "ops_api.ops.utils.health_check.get_supabase_jwks",
        side_effect=Exception("IdP down"),
    ):
        resp = asyncio.run(check_auth_services())

    assert resp == {"status_code": None, "alarm_level": 2}
