from flask import Response, current_app, request
from flask_jwt_extended import jwt_required

import ops_api.ops.auth.service as auth_service
from ops_api.ops.auth import bp
from ops_api.ops.auth.exceptions import AuthenticationError
from ops_api.ops.auth.schema import (
    LoginResponseSchema,
    LogoutResponseSchema,
    RefreshResponseSchema,
    RoleRequestSchema,
    RoleResponseSchema,
    SsoCallbackRequestSchema,
    SsoSessionResponseSchema,
    UserResponseSchema,
)
from ops_api.ops.utils.errors import error_simulator
from ops_api.ops.utils.response import make_response_with_headers


@bp.route("/login/", methods=["POST"])
@error_simulator
def login_post() -> Response:
    """MIGRATION (PM RIMS 0001): login lama DIMATIKAN -> 410 + arahkan ke SSO."""
    return make_response_with_headers(
        {
            "message": "Login lama dimatikan (PM RIMS 0001). Gunakan POST /auth/sso/callback.",
            "error_type": "AUTHN_ERROR",
        },
        410,
    )


@bp.route("/sso/callback", methods=["POST"])
@error_simulator
def sso_callback_post() -> Response:
    """Tukar JWT Supabase prod -> sesi aplikasi internal."""
    try:
        data = SsoCallbackRequestSchema().load(request.json or {})
    except Exception as e:
        return make_response_with_headers({"message": f"Payload SSO tidak valid: {e}"}, 400)
    try:
        result = auth_service.login_sso(data["supabase_jwt"])
    except AuthenticationError as e:
        msg = str(e)
        denied = "ditolak" in msg or "Akses" in msg or "diaktifkan" in msg
        status = 403 if denied else 401
        error_type = "AUTHZ_ERROR" if denied else "AUTHN_ERROR"
        return make_response_with_headers({"error_type": error_type, "message": msg}, status)
    response_schema = LoginResponseSchema()
    out = response_schema.dump(result)
    user_schema = UserResponseSchema()
    out["user"] = user_schema.dump(result["user"])
    return make_response_with_headers(out)


@bp.route("/sso/session", methods=["GET"])
@jwt_required()
@error_simulator
def sso_session_get() -> Response:
    result = auth_service.sso_session_info()
    data = SsoSessionResponseSchema().dump(result)
    return make_response_with_headers(data)


@bp.route("/logout/", methods=["POST"])
@jwt_required()
@error_simulator
def logout_post() -> Response:
    result = auth_service.logout()
    response_schema = LogoutResponseSchema()
    data = response_schema.dump(result)
    return make_response_with_headers(data)


@bp.route("/refresh/", methods=["POST"])
@jwt_required(refresh=True, verify_type=True)
@error_simulator
def refresh_post() -> Response:
    result = auth_service.refresh()
    response_schema = RefreshResponseSchema()
    data = response_schema.dump(result)
    return make_response_with_headers(data)


@bp.route("/roles/", methods=["GET"])
@error_simulator
def roles_get() -> Response:
    request_schema = RoleRequestSchema()
    data = request_schema.dump(request_schema.load(request.args))
    result = auth_service.get_roles(current_app.db_session, **data)
    response_schema = RoleResponseSchema(many=True)
    data = response_schema.dump(result)
    return make_response_with_headers(data)
