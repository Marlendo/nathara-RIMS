from datetime import datetime, timedelta
from functools import wraps
from typing import Callable, Optional

from flask import Response, current_app, request
from flask_jwt_extended import current_user, get_jwt_identity, jwt_required
from loguru import logger

from models import User
from ops_api.ops.auth.auth_types import Permission, PermissionType
from ops_api.ops.auth.authorization_providers import _check_role
from ops_api.ops.auth.exceptions import (
    AuthenticationError,
    ExtraCheckError,
    InvalidUserSessionError,
)
from ops_api.ops.auth.utils import (
    deactivate_all_user_sessions,
    get_all_active_user_sessions,
    get_bearer_token,
    get_latest_user_session,
    idle_logout,
)
from ops_api.ops.utils.errors import error_simulator
from ops_api.ops.utils.response import make_response_with_headers


def is_user_active(f):
    """
    Decorator SSO (PM RIMS 0001): request WAJIB membawa sesi aplikasi
    internal yang aktif (dibuat via /auth/sso/callback). Keamanan di
    backend; guard FE hanya UX.
    """

    @wraps(f)
    def decorated(*args, **kwargs):
        from ops_api.ops.auth.exceptions import (
            AuthenticationError,
            InvalidUserSessionError,
        )
        from ops_api.ops.auth.utils import get_latest_user_session

        identity = get_jwt_identity()
        if not identity:
            raise AuthenticationError("Sesi SSO tidak ada. Silakan login ulang.")
        user = current_user
        if not user:
            raise AuthenticationError("User sesi SSO tidak ditemukan.")
        latest = get_latest_user_session(user.id, current_app.db_session)
        if not latest or not latest.is_active:
            raise InvalidUserSessionError("Sesi tidak aktif. Silakan login ulang.")
        return f(*args, **kwargs)

    return decorated


def require_rims_access(f):
    """Guard kanonis SSO: role == 'admin' AND 'RIMS' in scopes (exact).

    Dibaca dari klaim JWT internal sesi app (diset saat login_sso dari
    klaim Supabase SSOT prod terverifikasi). Default deny 403 jelas.

    Model otorisasi resource (PM RIMS 0002, keputusan eksplisit): jalur
    resource umum tetap memakai model role-permission lama
    (``is_authorized`` -> ``_check_role``) agar diff kecil dan tidak mengubah
    logika bisnis di luar kill-list. Pencabutan akses mengandalkan
    ``UserSession.is_active=false`` (logout menonaktifkan semua sesi) +
    expiry sesi app max 30 menit + idle-timeout 28 menit. Guard ini tersedia
    untuk endpoint sensitif SSO-gated bila PM memutuskan pemasangan per
    resource di rilis berikut — JANGAN pasang global tanpa APPROVE PM.
    """

    @wraps(f)
    def decorated(*args, **kwargs):
        from flask_jwt_extended import get_jwt

        claims = get_jwt()
        if not (claims.get("sso_role") == "admin" and claims.get("sso_scope") == "RIMS"):
            return make_response_with_headers(
                {"message": "Akses ditolak: butuh role admin + scope RIMS. Hubungi admin."}, 403
            )
        return f(*args, **kwargs)

    return decorated


class is_authorized:
    def __init__(
        self,
        permission_type: PermissionType,
        permission: Permission,
        extra_check: Optional[Callable[..., bool]] = None,
    ) -> None:
        """Checks for if the user is authorized to use this endpoint. The order of authorizations is as follows:
        Role -> Extra.

        If the user has the correct role permission, then the user is authorized.
        Else if the user passes the extra validation check that is defined, the user is authorized.
        Else the user is not authorized.

        Args:
            permission_type: The permission "verb" (GET, PUT, PATCH, etc)
            permission: The permission "noun" (USER, AGREEMENT, BUDGET_LINE_ITEM, etc)
            extra_check: If given, a function that accepts the same parameters as the decorated function/method, and
                returns a boolean value, which does additional custom checking to see if the user is authorized.
        """
        self.permission_type = permission_type
        self.permission = permission
        self.extra_check = extra_check

    def __call__(self, func: Callable) -> Callable:
        @wraps(func)
        @jwt_required()
        @error_simulator
        def wrapper(*args, **kwargs) -> Response:
            try:
                if _check_role(self.permission_type, self.permission):
                    response = func(*args, **kwargs)
                else:
                    response = make_response_with_headers({}, 403)

            except ExtraCheckError as e:
                response = make_response_with_headers(e.response_data, 400)

            return response

        return wrapper


def check_user_session(f):
    """
    Decorator to check if the user has a valid user session.
    """

    @wraps(f)
    def decorated(*args, **kwargs):
        check_user_session_function(current_user)

        return f(*args, **kwargs)

    return decorated


def check_user_session_function(user: User):
    """
    Function to check if the user has a valid user session.

    A user session is considered valid if:
    1. The user has an active user session.
    2. The access token in the request is the same as the latest user session access token.
    3. The last_accessed_at field of the latest user session is not more than a configurable threshold ago.
    """
    user_sessions = get_all_active_user_sessions(user.id, current_app.db_session)
    latest_user_session = get_latest_user_session(user.id, current_app.db_session)

    # Check if the latest user session is active
    if not latest_user_session or not latest_user_session.is_active:
        deactivate_all_user_sessions(user_sessions)
        raise InvalidUserSessionError(f"User with id={user.id} does not have an active user session")
    # Check if the access token in the request is the same as the latest user session access token
    bearer_token = get_bearer_token()
    if bearer_token:
        access_token = bearer_token.replace("Bearer", "").strip()

        if access_token != latest_user_session.access_token:
            deactivate_all_user_sessions(user_sessions)
            raise InvalidUserSessionError(f"User with id={user.id} is using an invalid access token")
    # Check if the last_accessed_at field of the latest user session is not more than a configurable threshold ago
    if check_last_active_at(latest_user_session):
        idle_logout(user, user_sessions)
        raise InvalidUserSessionError(f"User with id={user.id} has not accessed the system for more than the threshold")
    # Update the last_accessed_at field of the latest user session (if this isn't only touching /notification)
    if "notification" not in request.endpoint:
        # If last_accessed_at is more than 30 minutes ago, then throw an exception
        latest_user_session.last_active_at = datetime.now()
        current_app.db_session.add(latest_user_session)
        current_app.db_session.commit()


def check_last_active_at(latest_user_session, threshold_in_seconds=None):
    """
    Return True if the last_active_at field of the latest user session is more than threshold_in_seconds ago.
    """
    final_threshold_in_seconds = (
        threshold_in_seconds or current_app.config.get("USER_SESSION_EXPIRATION", timedelta(minutes=30)).total_seconds()
    )
    logger.info(
        f"Checking if latest_user_session.last_active_at={latest_user_session.last_active_at} is more than "
        f"{final_threshold_in_seconds} seconds ago"
    )
    return (datetime.now() - latest_user_session.last_active_at).total_seconds() > final_threshold_in_seconds
